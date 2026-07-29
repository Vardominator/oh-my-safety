package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTaskSpecJSONContract(t *testing.T) {
	spec := TaskSpec{
		ID:   "scan.security.fast",
		Kind: "scan",
		Schedule: Schedule{
			Every:      5 * time.Minute,
			Jitter:     30 * time.Second,
			Timeout:    time.Minute,
			RunOnStart: true,
		},
		Labels: map[string]string{"profile": "personal"},
	}
	got, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"scan.security.fast","kind":"scan","schedule":{"every_ns":300000000000,"jitter_ns":30000000000,"timeout_ns":60000000000,"run_on_start":true},"labels":{"profile":"personal"}}`
	if string(got) != want {
		t.Fatalf("task contract changed\nwant: %s\n got: %s", want, got)
	}
}

func TestScheduleNextUsesStableBoundedJitter(t *testing.T) {
	start := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	schedule := Schedule{Every: time.Minute, Jitter: 10 * time.Second}
	first := schedule.Next(start, "task-a")
	second := schedule.Next(start, "task-a")
	if !first.Equal(second) {
		t.Fatalf("jitter is not stable: %v != %v", first, second)
	}
	minimum := start.Add(time.Minute)
	maximum := minimum.Add(10 * time.Second)
	if first.Before(minimum) || first.After(maximum) {
		t.Fatalf("jittered time %v outside [%v, %v]", first, minimum, maximum)
	}
}

func TestRegistryRejectsDuplicatesAndSortsSpecs(t *testing.T) {
	registry := NewRegistry()
	handler := func(context.Context) error { return nil }
	for _, id := range []string{"z-task", "a-task"} {
		err := registry.Register(Task{
			Spec: TaskSpec{
				ID: id, Kind: "test",
				Schedule: Schedule{Every: time.Minute},
			},
			Handler: handler,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := registry.Register(Task{
		Spec: TaskSpec{
			ID: "a-task", Kind: "test",
			Schedule: Schedule{Every: time.Minute},
		},
		Handler: handler,
	})
	if !errors.Is(err, ErrDuplicateTask) {
		t.Fatalf("duplicate registration error = %v", err)
	}
	specs := registry.Specs()
	if len(specs) != 2 || specs[0].ID != "a-task" || specs[1].ID != "z-task" {
		t.Fatalf("registry specs not stable: %#v", specs)
	}
}

func TestRegistryAndPlannerZeroValuesAreUsable(t *testing.T) {
	var registry Registry
	task := Task{
		Spec: TaskSpec{
			ID: "zero-value", Kind: "test",
			Schedule: Schedule{Every: time.Minute},
		},
		Handler: func(context.Context) error { return nil },
	}
	if err := registry.Register(task); err != nil {
		t.Fatalf("zero-value registry: %v", err)
	}

	var planner Planner
	if err := planner.Add(task.Spec, time.Time{}); err != nil {
		t.Fatalf("zero-value planner: %v", err)
	}
}

func TestPlannerClaimsDueTasksAndAdvancesThem(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	immediate := TaskSpec{
		ID: "immediate", Kind: "test",
		Schedule: Schedule{Every: time.Minute, RunOnStart: true},
	}
	delayed := TaskSpec{
		ID: "delayed", Kind: "test",
		Schedule: Schedule{Every: time.Minute},
	}
	planner := NewPlanner()
	if err := planner.Add(immediate, now); err != nil {
		t.Fatal(err)
	}
	if err := planner.Add(delayed, now); err != nil {
		t.Fatal(err)
	}

	due := planner.Due([]TaskSpec{delayed, immediate}, now)
	if len(due) != 1 || due[0].ID != "immediate" {
		t.Fatalf("initial due tasks = %#v", due)
	}
	if repeated := planner.Due([]TaskSpec{immediate}, now); len(repeated) != 0 {
		t.Fatalf("claimed task returned twice: %#v", repeated)
	}
	due = planner.Due([]TaskSpec{delayed, immediate}, now.Add(time.Minute))
	if len(due) != 2 || due[0].ID != "delayed" || due[1].ID != "immediate" {
		t.Fatalf("minute due tasks = %#v", due)
	}
}

func TestExecutorPropagatesTimeoutContext(t *testing.T) {
	start := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	calls := 0
	now := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		calls++
		return start.Add(time.Duration(calls-1) * time.Second)
	}
	task := Task{
		Spec: TaskSpec{
			ID: "timeout", Kind: "test",
			Schedule: Schedule{Every: time.Minute, Timeout: 5 * time.Millisecond},
		},
		Handler: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	execution := (Executor{Now: now}).Execute(context.Background(), task)
	if !execution.TimedOut || execution.Error != context.DeadlineExceeded.Error() {
		t.Fatalf("unexpected timeout execution: %#v", execution)
	}
	if execution.Duration != time.Second {
		t.Fatalf("duration = %v, want 1s", execution.Duration)
	}
}

func TestInvalidSchedulesAreRejected(t *testing.T) {
	cases := []Schedule{
		{},
		{Every: time.Minute, Jitter: -1},
		{Every: time.Minute, Jitter: time.Minute},
		{Every: time.Minute, Timeout: -1},
	}
	for _, schedule := range cases {
		if err := schedule.Validate(); err == nil {
			t.Fatalf("invalid schedule accepted: %#v", schedule)
		}
	}
}
