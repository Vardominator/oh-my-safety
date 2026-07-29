package notifier

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

const (
	Schema        = "io.oh-my-safety/notification"
	SchemaVersion = 1
)

var (
	ErrDuplicateChannel = errors.New("notification channel already registered")
	ErrUnknownChannel   = errors.New("notification channel not registered")
)

type Notification struct {
	Schema        string            `json:"schema"`
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	FindingID     string            `json:"finding_id,omitempty"`
	Severity      model.Severity    `json:"severity"`
	Title         string            `json:"title"`
	Body          string            `json:"body"`
	CreatedAt     time.Time         `json:"created_at"`
	Labels        map[string]string `json:"labels,omitempty"`
}

func (notification Notification) Validate() error {
	switch {
	case notification.Schema != Schema:
		return fmt.Errorf("unsupported notification schema %q", notification.Schema)
	case notification.SchemaVersion != SchemaVersion:
		return fmt.Errorf("unsupported notification schema version %d", notification.SchemaVersion)
	case strings.TrimSpace(notification.ID) == "":
		return errors.New("notification id is required")
	case !notification.Severity.Valid():
		return fmt.Errorf("invalid notification severity %q", notification.Severity)
	case strings.TrimSpace(notification.Title) == "":
		return errors.New("notification title is required")
	case strings.TrimSpace(notification.Body) == "":
		return errors.New("notification body is required")
	case notification.CreatedAt.IsZero():
		return errors.New("notification created_at is required")
	default:
		return nil
	}
}

type Channel interface {
	Name() string
	Notify(context.Context, Notification) error
}

type Registry struct {
	mu       sync.RWMutex
	channels map[string]Channel
}

func NewRegistry() *Registry {
	return &Registry{channels: make(map[string]Channel)}
}

func (registry *Registry) Register(channel Channel) error {
	if channel == nil {
		return errors.New("notification channel is required")
	}
	name := strings.TrimSpace(channel.Name())
	if name == "" {
		return errors.New("notification channel name is required")
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.channels == nil {
		registry.channels = make(map[string]Channel)
	}
	if _, exists := registry.channels[name]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateChannel, name)
	}
	registry.channels[name] = channel
	return nil
}

func (registry *Registry) Get(name string) (Channel, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	channel, ok := registry.channels[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownChannel, name)
	}
	return channel, nil
}

func (registry *Registry) Names() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	names := make([]string, 0, len(registry.channels))
	for name := range registry.channels {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type Delivery struct {
	Channel   string `json:"channel"`
	Delivered bool   `json:"delivered"`
	Error     string `json:"error,omitempty"`
}

func (registry *Registry) Deliver(
	ctx context.Context,
	names []string,
	notification Notification,
) ([]Delivery, error) {
	if err := notification.Validate(); err != nil {
		return nil, err
	}

	deliveries := make([]Delivery, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, requestedName := range names {
		name := strings.TrimSpace(requestedName)
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}

		channel, err := registry.Get(name)
		if err != nil {
			deliveries = append(deliveries, Delivery{
				Channel: name,
				Error:   err.Error(),
			})
			continue
		}
		delivery := Delivery{Channel: name}
		if err := channel.Notify(ctx, notification); err != nil {
			delivery.Error = err.Error()
		} else {
			delivery.Delivered = true
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}
