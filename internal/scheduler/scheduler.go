package scheduler

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	ErrDuplicateTask = errors.New("scheduler task already registered")
	ErrTaskNotFound  = errors.New("scheduler task not found")
)

type Handler func(context.Context) error

type Schedule struct {
	Every      time.Duration `json:"every_ns"`
	Jitter     time.Duration `json:"jitter_ns,omitempty"`
	Timeout    time.Duration `json:"timeout_ns,omitempty"`
	RunOnStart bool          `json:"run_on_start"`
}

func (schedule Schedule) Validate() error {
	switch {
	case schedule.Every <= 0:
		return errors.New("schedule interval must be positive")
	case schedule.Jitter < 0:
		return errors.New("schedule jitter cannot be negative")
	case schedule.Jitter >= schedule.Every:
		return errors.New("schedule jitter must be less than interval")
	case schedule.Timeout < 0:
		return errors.New("schedule timeout cannot be negative")
	default:
		return nil
	}
}

func (schedule Schedule) Next(after time.Time, stableKey string) time.Time {
	next := after.Add(schedule.Every)
	if schedule.Jitter == 0 {
		return next
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(stableKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.FormatInt(after.UnixNano(), 10)))
	offset := time.Duration(hasher.Sum64() % uint64(schedule.Jitter+1))
	return next.Add(offset)
}

type TaskSpec struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Schedule Schedule          `json:"schedule"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func (spec TaskSpec) Validate() error {
	switch {
	case spec.ID == "":
		return errors.New("task id is required")
	case spec.Kind == "":
		return errors.New("task kind is required")
	default:
		return spec.Schedule.Validate()
	}
}

type Task struct {
	Spec    TaskSpec
	Handler Handler
}

func (task Task) Validate() error {
	if err := task.Spec.Validate(); err != nil {
		return err
	}
	if task.Handler == nil {
		return errors.New("task handler is required")
	}
	return nil
}

type Registry struct {
	mu    sync.RWMutex
	tasks map[string]Task
}

func NewRegistry() *Registry {
	return &Registry{tasks: make(map[string]Task)}
}

func (registry *Registry) Register(task Task) error {
	if err := task.Validate(); err != nil {
		return err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.tasks == nil {
		registry.tasks = make(map[string]Task)
	}
	if _, exists := registry.tasks[task.Spec.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateTask, task.Spec.ID)
	}
	registry.tasks[task.Spec.ID] = task
	return nil
}

func (registry *Registry) Get(id string) (Task, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	task, ok := registry.tasks[id]
	if !ok {
		return Task{}, fmt.Errorf("%w: %s", ErrTaskNotFound, id)
	}
	return task, nil
}

func (registry *Registry) Specs() []TaskSpec {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	specs := make([]TaskSpec, 0, len(registry.tasks))
	for _, task := range registry.tasks {
		specs = append(specs, task.Spec)
	}
	sort.Slice(specs, func(i, j int) bool {
		return specs[i].ID < specs[j].ID
	})
	return specs
}

type Execution struct {
	TaskID     string        `json:"task_id"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration_ns"`
	TimedOut   bool          `json:"timed_out"`
	Error      string        `json:"error,omitempty"`
}

type Executor struct {
	Now func() time.Time
}

func (executor Executor) Execute(ctx context.Context, task Task) Execution {
	now := executor.Now
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	execution := Execution{
		TaskID:    task.Spec.ID,
		StartedAt: started,
	}
	if err := task.Validate(); err != nil {
		execution.FinishedAt = now().UTC()
		execution.Duration = execution.FinishedAt.Sub(started)
		execution.Error = err.Error()
		return execution
	}

	runContext := ctx
	cancel := func() {}
	if task.Spec.Schedule.Timeout > 0 {
		runContext, cancel = context.WithTimeout(ctx, task.Spec.Schedule.Timeout)
	}
	defer cancel()

	err := task.Handler(runContext)
	execution.FinishedAt = now().UTC()
	execution.Duration = execution.FinishedAt.Sub(started)
	execution.TimedOut = errors.Is(runContext.Err(), context.DeadlineExceeded)
	if err != nil {
		execution.Error = err.Error()
	} else if execution.TimedOut {
		execution.Error = context.DeadlineExceeded.Error()
	}
	return execution
}

type Planner struct {
	mu   sync.Mutex
	next map[string]time.Time
}

func NewPlanner() *Planner {
	return &Planner{next: make(map[string]time.Time)}
}

func (planner *Planner) Add(spec TaskSpec, registeredAt time.Time) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	planner.mu.Lock()
	defer planner.mu.Unlock()
	if planner.next == nil {
		planner.next = make(map[string]time.Time)
	}
	if _, exists := planner.next[spec.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateTask, spec.ID)
	}
	if spec.Schedule.RunOnStart {
		planner.next[spec.ID] = registeredAt.UTC()
	} else {
		planner.next[spec.ID] = spec.Schedule.Next(registeredAt.UTC(), spec.ID)
	}
	return nil
}

func (planner *Planner) Due(specs []TaskSpec, now time.Time) []TaskSpec {
	planner.mu.Lock()
	defer planner.mu.Unlock()

	due := make([]TaskSpec, 0)
	for _, spec := range specs {
		next, exists := planner.next[spec.ID]
		if !exists || next.After(now) {
			continue
		}
		due = append(due, spec)
		planner.next[spec.ID] = spec.Schedule.Next(now.UTC(), spec.ID)
	}
	sort.Slice(due, func(i, j int) bool {
		return due[i].ID < due[j].ID
	})
	return due
}

func (planner *Planner) Next(id string) (time.Time, bool) {
	planner.mu.Lock()
	defer planner.mu.Unlock()
	next, ok := planner.next[id]
	return next, ok
}
