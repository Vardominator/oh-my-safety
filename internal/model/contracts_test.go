package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventJSONContractV1(t *testing.T) {
	at := time.Date(2026, 7, 29, 12, 34, 56, 123000000, time.UTC)
	event := Event{
		Schema:        EventSchema,
		SchemaVersion: EventSchemaVersion,
		ID:            "evt-1",
		Type:          EventFindingObserved,
		OccurredAt:    at,
		RecordedAt:    at.Add(time.Second),
		Source:        "security/secrets-content",
		Platform:      "linux",
		Subject:       &Subject{Type: "file", ID: "sha256:redacted", Name: "credentials"},
		FindingID:     "sec:/redacted:content",
		CorrelationID: "scan-1",
		Labels:        map[string]string{"scope": "local"},
		Payload:       json.RawMessage(`{"redacted":true}`),
	}

	got, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"io.oh-my-safety/event","schema_version":1,"id":"evt-1","type":"finding.observed","occurred_at":"2026-07-29T12:34:56.123Z","recorded_at":"2026-07-29T12:34:57.123Z","source":"security/secrets-content","platform":"linux","subject":{"type":"file","id":"sha256:redacted","name":"credentials"},"finding_id":"sec:/redacted:content","correlation_id":"scan-1","labels":{"scope":"local"},"payload":{"redacted":true}}`
	if string(got) != want {
		t.Fatalf("event contract changed\nwant: %s\n got: %s", want, got)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
}

func TestFindingJSONContractV1(t *testing.T) {
	at := time.Date(2026, 7, 29, 12, 34, 56, 0, time.UTC)
	finding := Finding{
		Schema:            FindingSchema,
		SchemaVersion:     FindingSchemaVersion,
		ID:                "finding-1",
		DetectorID:        "secrets-content",
		Category:          "security",
		Title:             "Credential-like content found",
		Summary:           "A redacted credential pattern was detected.",
		Severity:          SeverityCritical,
		State:             FindingOpen,
		FirstSeen:         at,
		LastSeen:          at,
		UpdatedAt:         at,
		Occurrences:       1,
		Evidence:          []Evidence{{Type: "file", Ref: "hmac:abc", Summary: "masked match"}},
		Remediation:       &Remediation{Summary: "Rotate then remove the credential.", Reversible: false},
		Labels:            map[string]string{"check": "secrets-content"},
		LastEventID:       "evt-1",
		LastEventSequence: 1,
	}

	got, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"io.oh-my-safety/finding","schema_version":1,"id":"finding-1","detector_id":"secrets-content","category":"security","title":"Credential-like content found","summary":"A redacted credential pattern was detected.","severity":"critical","state":"open","first_seen":"2026-07-29T12:34:56Z","last_seen":"2026-07-29T12:34:56Z","updated_at":"2026-07-29T12:34:56Z","occurrences":1,"evidence":[{"type":"file","ref":"hmac:abc","summary":"masked match"}],"remediation":{"summary":"Rotate then remove the credential.","reversible":false},"labels":{"check":"secrets-content"},"last_event_id":"evt-1","last_event_sequence":1}`
	if string(got) != want {
		t.Fatalf("finding contract changed\nwant: %s\n got: %s", want, got)
	}
	if err := finding.Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
}

func TestValidationRejectsUnsupportedVersionsAndRawPayload(t *testing.T) {
	at := time.Now().UTC()
	event := Event{
		Schema:        EventSchema,
		SchemaVersion: 99,
		ID:            "evt",
		Type:          "test",
		OccurredAt:    at,
		RecordedAt:    at,
		Source:        "test",
	}
	if err := event.Validate(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error, got %v", err)
	}

	event.SchemaVersion = EventSchemaVersion
	event.Payload = json.RawMessage(`{`)
	if err := event.Validate(); err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("expected payload error, got %v", err)
	}
}

func TestNewIDIsUUIDV4ShapedAndUnique(t *testing.T) {
	first, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("generated duplicate ids")
	}
	if len(first) != 36 || first[14] != '4' || first[19] != '8' && first[19] != '9' && first[19] != 'a' && first[19] != 'b' {
		t.Fatalf("id is not UUIDv4-shaped: %q", first)
	}
}
