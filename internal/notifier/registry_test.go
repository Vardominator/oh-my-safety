package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

func TestNotificationJSONContract(t *testing.T) {
	notification := testNotification()
	got, err := json.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"io.oh-my-safety/notification","schema_version":1,"id":"notice-1","finding_id":"finding-1","severity":"critical","title":"Credential exposed","body":"A redacted credential finding needs attention.","created_at":"2026-07-29T12:00:00Z","labels":{"scope":"local"}}`
	if string(got) != want {
		t.Fatalf("notification contract changed\nwant: %s\n got: %s", want, got)
	}
}

func TestRegistryDeliversOncePerRequestedChannel(t *testing.T) {
	registry := NewRegistry()
	local := &stubChannel{name: "local"}
	failing := &stubChannel{name: "failing", err: errors.New("delivery failed")}
	if err := registry.Register(local); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(failing); err != nil {
		t.Fatal(err)
	}

	deliveries, err := registry.Deliver(
		context.Background(),
		[]string{"local", "local", "missing", "failing"},
		testNotification(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("delivery count = %d, want 3: %#v", len(deliveries), deliveries)
	}
	if !deliveries[0].Delivered {
		t.Fatalf("local delivery failed: %#v", deliveries[0])
	}
	if deliveries[1].Delivered || deliveries[1].Error == "" {
		t.Fatalf("unknown delivery not reported: %#v", deliveries[1])
	}
	if deliveries[2].Delivered || deliveries[2].Error != "delivery failed" {
		t.Fatalf("channel error not reported: %#v", deliveries[2])
	}
	if local.callCount() != 1 || failing.callCount() != 1 {
		t.Fatalf("unexpected notifier calls: local=%d failing=%d", local.callCount(), failing.callCount())
	}
}

func TestRegistryRejectsDuplicateChannelsAndSortsNames(t *testing.T) {
	registry := NewRegistry()
	for _, name := range []string{"telegram", "local"} {
		if err := registry.Register(&stubChannel{name: name}); err != nil {
			t.Fatal(err)
		}
	}
	err := registry.Register(&stubChannel{name: "local"})
	if !errors.Is(err, ErrDuplicateChannel) {
		t.Fatalf("duplicate error = %v", err)
	}
	names := registry.Names()
	if len(names) != 2 || names[0] != "local" || names[1] != "telegram" {
		t.Fatalf("unstable registry names: %#v", names)
	}
}

func TestRegistryZeroValueCanRegister(t *testing.T) {
	var registry Registry
	if err := registry.Register(&stubChannel{name: "local"}); err != nil {
		t.Fatalf("zero-value registry: %v", err)
	}
	if len(registry.Names()) != 1 {
		t.Fatalf("zero-value registry names: %#v", registry.Names())
	}
}

func TestRegistryIsRaceSafe(t *testing.T) {
	registry := NewRegistry()
	const count = 32
	var wait sync.WaitGroup
	errs := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errs <- registry.Register(&stubChannel{name: fmt.Sprintf("channel-%02d", index)})
		}(index)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(registry.Names()) != count {
		t.Fatalf("channel count = %d, want %d", len(registry.Names()), count)
	}
}

func TestDeliverRejectsInvalidNotificationBeforeCallingChannels(t *testing.T) {
	registry := NewRegistry()
	channel := &stubChannel{name: "local"}
	if err := registry.Register(channel); err != nil {
		t.Fatal(err)
	}
	notification := testNotification()
	notification.Severity = "emergency"
	if _, err := registry.Deliver(context.Background(), []string{"local"}, notification); err == nil {
		t.Fatal("invalid notification accepted")
	}
	if channel.callCount() != 0 {
		t.Fatal("channel called for invalid notification")
	}
}

type stubChannel struct {
	name  string
	err   error
	mu    sync.Mutex
	calls int
}

func (channel *stubChannel) Name() string {
	return channel.name
}

func (channel *stubChannel) Notify(context.Context, Notification) error {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	channel.calls++
	return channel.err
}

func (channel *stubChannel) callCount() int {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	return channel.calls
}

func testNotification() Notification {
	return Notification{
		Schema:        Schema,
		SchemaVersion: SchemaVersion,
		ID:            "notice-1",
		FindingID:     "finding-1",
		Severity:      model.SeverityCritical,
		Title:         "Credential exposed",
		Body:          "A redacted credential finding needs attention.",
		CreatedAt:     time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Labels:        map[string]string{"scope": "local"},
	}
}
