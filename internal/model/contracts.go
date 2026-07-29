package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	EventSchema          = "io.oh-my-safety/event"
	EventSchemaVersion   = 1
	FindingSchema        = "io.oh-my-safety/finding"
	FindingSchemaVersion = 1
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarn, SeverityCritical:
		return true
	default:
		return false
	}
}

type FindingState string

const (
	FindingOpen         FindingState = "open"
	FindingAcknowledged FindingState = "acknowledged"
	FindingSuppressed   FindingState = "suppressed"
	FindingResolved     FindingState = "resolved"
)

func (s FindingState) Valid() bool {
	switch s {
	case FindingOpen, FindingAcknowledged, FindingSuppressed, FindingResolved:
		return true
	default:
		return false
	}
}

const (
	EventFindingObserved     = "finding.observed"
	EventFindingAcknowledged = "finding.acknowledged"
	EventFindingSuppressed   = "finding.suppressed"
	EventFindingUnsuppressed = "finding.unsuppressed"
	EventFindingResolved     = "finding.resolved"
)

type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Event struct {
	Schema        string            `json:"schema"`
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	OccurredAt    time.Time         `json:"occurred_at"`
	RecordedAt    time.Time         `json:"recorded_at"`
	Source        string            `json:"source"`
	Platform      string            `json:"platform,omitempty"`
	Subject       *Subject          `json:"subject,omitempty"`
	FindingID     string            `json:"finding_id,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Payload       json.RawMessage   `json:"payload,omitempty"`
}

func NewEvent(eventType, source string, occurredAt, recordedAt time.Time, payload any) (Event, error) {
	id, err := NewID()
	if err != nil {
		return Event{}, err
	}

	var raw json.RawMessage
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return Event{}, fmt.Errorf("marshal event payload: %w", err)
		}
	}

	event := Event{
		Schema:        EventSchema,
		SchemaVersion: EventSchemaVersion,
		ID:            id,
		Type:          eventType,
		OccurredAt:    occurredAt.UTC(),
		RecordedAt:    recordedAt.UTC(),
		Source:        source,
		Payload:       raw,
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (e Event) Validate() error {
	switch {
	case e.Schema != EventSchema:
		return fmt.Errorf("unsupported event schema %q", e.Schema)
	case e.SchemaVersion != EventSchemaVersion:
		return fmt.Errorf("unsupported event schema version %d", e.SchemaVersion)
	case strings.TrimSpace(e.ID) == "":
		return errors.New("event id is required")
	case strings.TrimSpace(e.Type) == "":
		return errors.New("event type is required")
	case e.OccurredAt.IsZero():
		return errors.New("event occurred_at is required")
	case e.RecordedAt.IsZero():
		return errors.New("event recorded_at is required")
	case strings.TrimSpace(e.Source) == "":
		return errors.New("event source is required")
	case len(e.Payload) > 0 && !json.Valid(e.Payload):
		return errors.New("event payload is not valid JSON")
	default:
		return nil
	}
}

func (e Event) IsFindingLifecycle() bool {
	switch e.Type {
	case EventFindingObserved,
		EventFindingAcknowledged,
		EventFindingSuppressed,
		EventFindingUnsuppressed,
		EventFindingResolved:
		return true
	default:
		return false
	}
}

type Evidence struct {
	Type    string `json:"type"`
	Ref     string `json:"ref,omitempty"`
	Summary string `json:"summary"`
}

type Remediation struct {
	Summary    string `json:"summary"`
	Guide      string `json:"guide,omitempty"`
	Reversible bool   `json:"reversible"`
}

type FindingAction struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Note  string    `json:"note,omitempty"`
}

type Finding struct {
	Schema            string            `json:"schema"`
	SchemaVersion     int               `json:"schema_version"`
	ID                string            `json:"id"`
	DetectorID        string            `json:"detector_id"`
	Category          string            `json:"category"`
	Title             string            `json:"title"`
	Summary           string            `json:"summary"`
	Severity          Severity          `json:"severity"`
	State             FindingState      `json:"state"`
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Occurrences       uint64            `json:"occurrences"`
	Evidence          []Evidence        `json:"evidence,omitempty"`
	Remediation       *Remediation      `json:"remediation,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	SuppressedUntil   *time.Time        `json:"suppressed_until,omitempty"`
	Acknowledgement   *FindingAction    `json:"acknowledgement,omitempty"`
	Resolution        *FindingAction    `json:"resolution,omitempty"`
	LastEventID       string            `json:"last_event_id"`
	LastEventSequence int64             `json:"last_event_sequence"`
}

func (f Finding) Validate() error {
	switch {
	case f.Schema != FindingSchema:
		return fmt.Errorf("unsupported finding schema %q", f.Schema)
	case f.SchemaVersion != FindingSchemaVersion:
		return fmt.Errorf("unsupported finding schema version %d", f.SchemaVersion)
	case strings.TrimSpace(f.ID) == "":
		return errors.New("finding id is required")
	case strings.TrimSpace(f.DetectorID) == "":
		return errors.New("finding detector_id is required")
	case strings.TrimSpace(f.Title) == "":
		return errors.New("finding title is required")
	case !f.Severity.Valid():
		return fmt.Errorf("invalid finding severity %q", f.Severity)
	case !f.State.Valid():
		return fmt.Errorf("invalid finding state %q", f.State)
	case f.FirstSeen.IsZero() || f.LastSeen.IsZero() || f.UpdatedAt.IsZero():
		return errors.New("finding timestamps are required")
	case f.Occurrences == 0:
		return errors.New("finding occurrences must be positive")
	case strings.TrimSpace(f.LastEventID) == "":
		return errors.New("finding last_event_id is required")
	case f.LastEventSequence <= 0:
		return errors.New("finding last_event_sequence must be positive")
	default:
		return nil
	}
}

type FindingObservation struct {
	DetectorID  string            `json:"detector_id"`
	Category    string            `json:"category"`
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Severity    Severity          `json:"severity"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	Remediation *Remediation      `json:"remediation,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func (o FindingObservation) Validate() error {
	switch {
	case strings.TrimSpace(o.DetectorID) == "":
		return errors.New("observation detector_id is required")
	case strings.TrimSpace(o.Title) == "":
		return errors.New("observation title is required")
	case strings.TrimSpace(o.Summary) == "":
		return errors.New("observation summary is required")
	case !o.Severity.Valid():
		return fmt.Errorf("invalid observation severity %q", o.Severity)
	default:
		return nil
	}
}

type FindingTransition struct {
	Actor string     `json:"actor"`
	Note  string     `json:"note,omitempty"`
	Until *time.Time `json:"until,omitempty"`
}

func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	var encoded [32]byte
	hex.Encode(encoded[:], value[:])
	return string(encoded[0:8]) + "-" +
		string(encoded[8:12]) + "-" +
		string(encoded[12:16]) + "-" +
		string(encoded[16:20]) + "-" +
		string(encoded[20:32]), nil
}
