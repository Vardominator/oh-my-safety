package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

var journalTestTime = time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

func TestJournalAppendReadIdempotencyAndConflict(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	first := testEvent(t, "evt-1", "scan.started", "", map[string]any{"deep": true}, 0)
	firstRecord, err := store.Append(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstRecord.Sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", firstRecord.Sequence)
	}

	duplicate, err := store.Append(ctx, first)
	if err != nil {
		t.Fatalf("idempotent append failed: %v", err)
	}
	if duplicate.Sequence != firstRecord.Sequence {
		t.Fatalf("duplicate sequence = %d, want %d", duplicate.Sequence, firstRecord.Sequence)
	}

	conflict := first
	conflict.Source = "different-source"
	if _, err := store.Append(ctx, conflict); !errors.Is(err, ErrEventIDConflict) {
		t.Fatalf("conflicting event error = %v, want ErrEventIDConflict", err)
	}

	second := testEvent(t, "evt-2", "scan.completed", "", map[string]any{"exit": 0}, time.Second)
	if _, err := store.Append(ctx, second); err != nil {
		t.Fatal(err)
	}

	records, err := store.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Event.ID != "evt-1" || records[1].Event.ID != "evt-2" {
		t.Fatalf("unexpected journal records: %#v", records)
	}
	afterFirst, err := store.Read(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFirst) != 1 || afterFirst[0].Sequence != 2 {
		t.Fatalf("unexpected paged records: %#v", afterFirst)
	}
}

func TestJournalEventsAreDatabaseEnforcedAppendOnly(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	event := testEvent(t, "evt-immutable", "test.event", "", nil, 0)
	if _, err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, "UPDATE events SET source = 'changed' WHERE event_id = 'evt-immutable'"); err == nil {
		t.Fatal("event update unexpectedly succeeded")
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM events WHERE event_id = 'evt-immutable'"); err == nil {
		t.Fatal("event delete unexpectedly succeeded")
	}
	records, err := store.Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Event.Source != "test" {
		t.Fatalf("append-only event changed: %#v", records)
	}
}

func TestFindingLifecycleMaterializationAndReopen(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	findingID := "sec:/redacted:credential"
	observation := model.FindingObservation{
		DetectorID: "secrets-content",
		Category:   "security",
		Title:      "Credential-like content found",
		Summary:    "A masked credential pattern was detected.",
		Severity:   model.SeverityCritical,
		Evidence: []model.Evidence{{
			Type: "file", Ref: "hmac:abc", Summary: "masked match",
		}},
		Remediation: &model.Remediation{
			Summary: "Rotate the credential before removing it.",
		},
	}

	observed := testEvent(t, "evt-observed-1", model.EventFindingObserved, findingID, observation, 0)
	if _, err := store.Append(ctx, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, observed); err != nil {
		t.Fatalf("idempotent finding event failed: %v", err)
	}
	assertFinding(t, store, findingID, model.FindingOpen, 1)

	secondObservation := observation
	secondObservation.Summary = "The credential remains exposed."
	if _, err := store.Append(ctx, testEvent(
		t, "evt-observed-2", model.EventFindingObserved, findingID, secondObservation, time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, store, findingID, model.FindingOpen, 2)

	if _, err := store.Append(ctx, transitionEvent(
		t, "evt-ack", model.EventFindingAcknowledged, findingID,
		model.FindingTransition{Actor: "user:local", Note: "Investigating"}, 2*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, store, findingID, model.FindingAcknowledged, 2)

	until := journalTestTime.Add(time.Hour)
	if _, err := store.Append(ctx, transitionEvent(
		t, "evt-suppress", model.EventFindingSuppressed, findingID,
		model.FindingTransition{Actor: "user:local", Note: "Maintenance", Until: &until}, 3*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	suppressed := assertFinding(t, store, findingID, model.FindingSuppressed, 2)
	if suppressed.SuppressedUntil == nil || !suppressed.SuppressedUntil.Equal(until) {
		t.Fatalf("suppressed_until = %v, want %v", suppressed.SuppressedUntil, until)
	}

	if _, err := store.Append(ctx, testEvent(
		t, "evt-observed-3", model.EventFindingObserved, findingID, observation, 4*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, store, findingID, model.FindingSuppressed, 3)

	if _, err := store.Append(ctx, transitionEvent(
		t, "evt-unsuppress", model.EventFindingUnsuppressed, findingID,
		model.FindingTransition{Actor: "user:local"}, 5*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, store, findingID, model.FindingOpen, 3)

	if _, err := store.Append(ctx, transitionEvent(
		t, "evt-resolve", model.EventFindingResolved, findingID,
		model.FindingTransition{Actor: "detector:secrets-content", Note: "No longer observed"}, 6*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	resolved := assertFinding(t, store, findingID, model.FindingResolved, 3)
	if resolved.Resolution == nil || resolved.Resolution.Actor != "detector:secrets-content" {
		t.Fatalf("resolution not materialized: %#v", resolved.Resolution)
	}

	if _, err := store.Append(ctx, testEvent(
		t, "evt-observed-4", model.EventFindingObserved, findingID, observation, 7*time.Minute,
	)); err != nil {
		t.Fatal(err)
	}
	reopened := assertFinding(t, store, findingID, model.FindingOpen, 4)
	if reopened.Resolution != nil || reopened.Acknowledgement != nil {
		t.Fatalf("reopened finding retained closed state: %#v", reopened)
	}
}

func TestInvalidFindingTransitionRollsBackJournalEvent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	findingID := "finding-rollback"
	observation := model.FindingObservation{
		DetectorID: "test",
		Title:      "Test",
		Summary:    "Test observation",
		Severity:   model.SeverityWarn,
	}
	if _, err := store.Append(ctx, testEvent(
		t, "evt-open", model.EventFindingObserved, findingID, observation, 0,
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, transitionEvent(
		t, "evt-resolved", model.EventFindingResolved, findingID,
		model.FindingTransition{Actor: "test"}, time.Minute,
	)); err != nil {
		t.Fatal(err)
	}

	_, err := store.Append(ctx, transitionEvent(
		t, "evt-invalid-ack", model.EventFindingAcknowledged, findingID,
		model.FindingTransition{Actor: "test"}, 2*time.Minute,
	))
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v, want ErrInvalidTransition", err)
	}

	records, err := store.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("failed lifecycle event was journaled: %#v", records)
	}
	assertFinding(t, store, findingID, model.FindingResolved, 1)
}

func TestRebuildFindingsReplaysJournal(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	observation := model.FindingObservation{
		DetectorID: "persistence-scan",
		Category:   "security",
		Title:      "New persistence",
		Summary:    "A new startup item appeared.",
		Severity:   model.SeverityWarn,
	}
	for index := 0; index < 2; index++ {
		id := fmt.Sprintf("finding-%d", index)
		if _, err := store.Append(ctx, testEvent(
			t, fmt.Sprintf("evt-%d", index), model.EventFindingObserved, id, observation, time.Duration(index)*time.Minute,
		)); err != nil {
			t.Fatal(err)
		}
	}
	before, err := store.ListFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RebuildFindings(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.ListFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Fatalf("rebuild changed projection\nbefore: %s\nafter:  %s", beforeJSON, afterJSON)
	}
}

func TestConcurrentAppendIsRaceSafe(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	const count = 32
	var wait sync.WaitGroup
	errs := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			event := testEvent(
				t,
				fmt.Sprintf("evt-concurrent-%02d", index),
				"telemetry.sample",
				"",
				map[string]int{"index": index},
				time.Duration(index)*time.Millisecond,
			)
			_, err := store.Append(ctx, event)
			errs <- err
		}(index)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.Read(ctx, 0, count)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != count {
		t.Fatalf("record count = %d, want %d", len(records), count)
	}
}

func TestOpenRestrictsOnDiskState(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "journal.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %o, want 600", got)
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := parentInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory permissions = %o, want 700", got)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close journal: %v", err)
		}
	})
	return store
}

func testEvent(
	t *testing.T,
	id string,
	eventType string,
	findingID string,
	payload any,
	offset time.Duration,
) model.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		Schema:        model.EventSchema,
		SchemaVersion: model.EventSchemaVersion,
		ID:            id,
		Type:          eventType,
		OccurredAt:    journalTestTime.Add(offset),
		RecordedAt:    journalTestTime.Add(offset),
		Source:        "test",
		FindingID:     findingID,
		Payload:       raw,
	}
	if payload == nil {
		event.Payload = nil
	}
	return event
}

func transitionEvent(
	t *testing.T,
	id string,
	eventType string,
	findingID string,
	transition model.FindingTransition,
	offset time.Duration,
) model.Event {
	t.Helper()
	return testEvent(t, id, eventType, findingID, transition, offset)
}

func assertFinding(
	t *testing.T,
	store *Store,
	id string,
	state model.FindingState,
	occurrences uint64,
) model.Finding {
	t.Helper()
	finding, err := store.CurrentFinding(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if finding.State != state || finding.Occurrences != occurrences {
		t.Fatalf(
			"finding state/count = %s/%d, want %s/%d: %#v",
			finding.State,
			finding.Occurrences,
			state,
			occurrences,
			finding,
		)
	}
	return finding
}
