package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
	_ "modernc.org/sqlite"
)

const databaseSchemaVersion = 1

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("journal path is required")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("create journal directory: %w", err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			return nil, fmt.Errorf("restrict journal directory permissions: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite journal: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("restrict journal permissions: %w", err)
		}
	}
	return store, nil
}

func (s *Store) configure() error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = FULL",
		"PRAGMA journal_mode = WAL",
	}
	for _, statement := range pragmas {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("configure sqlite journal (%s): %w", statement, err)
		}
	}
	return nil
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL UNIQUE,
	schema_name TEXT NOT NULL,
	schema_version INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	recorded_at TEXT NOT NULL,
	source TEXT NOT NULL,
	platform TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	correlation_id TEXT NOT NULL,
	envelope BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS events_type_sequence_idx
	ON events(event_type, sequence);
CREATE INDEX IF NOT EXISTS events_finding_sequence_idx
	ON events(finding_id, sequence);

CREATE TABLE IF NOT EXISTS current_findings (
	finding_id TEXT PRIMARY KEY,
	state TEXT NOT NULL,
	severity TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	last_event_sequence INTEGER NOT NULL,
	document BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS current_findings_state_severity_idx
	ON current_findings(state, severity, updated_at);

CREATE TRIGGER IF NOT EXISTS events_reject_update
BEFORE UPDATE ON events
BEGIN
	SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_reject_delete
BEFORE DELETE ON events
BEGIN
	SELECT RAISE(ABORT, 'events are append-only');
END;
`
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin journal migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(schema); err != nil {
		return fmt.Errorf("create journal schema: %w", err)
	}
	var current int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read journal schema version: %w", err)
	}
	if current > databaseSchemaVersion {
		return fmt.Errorf("journal schema version %d is newer than supported version %d", current, databaseSchemaVersion)
	}
	if _, err := tx.Exec(
		"INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
		databaseSchemaVersion,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record journal migration: %w", err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", databaseSchemaVersion)); err != nil {
		return fmt.Errorf("set journal schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit journal migration: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Append(ctx context.Context, event model.Event) (Record, error) {
	if err := event.Validate(); err != nil {
		return Record{}, fmt.Errorf("validate event: %w", err)
	}
	if event.IsFindingLifecycle() && strings.TrimSpace(event.FindingID) == "" {
		return Record{}, errors.New("finding lifecycle event requires finding_id")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("begin append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	record, inserted, err := appendEvent(ctx, tx, event)
	if err != nil {
		return Record{}, err
	}
	if inserted && event.IsFindingLifecycle() {
		if _, err := projectFinding(ctx, tx, record); err != nil {
			return Record{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit append: %w", err)
	}
	return record, nil
}

func appendEvent(ctx context.Context, tx *sql.Tx, event model.Event) (Record, bool, error) {
	envelope, err := json.Marshal(event)
	if err != nil {
		return Record{}, false, fmt.Errorf("marshal event: %w", err)
	}

	var existingSequence int64
	var existingEnvelope []byte
	err = tx.QueryRowContext(
		ctx,
		"SELECT sequence, envelope FROM events WHERE event_id = ?",
		event.ID,
	).Scan(&existingSequence, &existingEnvelope)
	switch {
	case err == nil:
		if !bytes.Equal(existingEnvelope, envelope) {
			return Record{}, false, fmt.Errorf("%w: %s", ErrEventIDConflict, event.ID)
		}
		return Record{Sequence: existingSequence, Event: event}, false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return Record{}, false, fmt.Errorf("check event id: %w", err)
	}

	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO events (
			event_id, schema_name, schema_version, event_type, occurred_at,
			recorded_at, source, platform, finding_id, correlation_id, envelope
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID,
		event.Schema,
		event.SchemaVersion,
		event.Type,
		event.OccurredAt.UTC().Format(time.RFC3339Nano),
		event.RecordedAt.UTC().Format(time.RFC3339Nano),
		event.Source,
		event.Platform,
		event.FindingID,
		event.CorrelationID,
		envelope,
	)
	if err != nil {
		return Record{}, false, fmt.Errorf("append event: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return Record{}, false, fmt.Errorf("read event sequence: %w", err)
	}
	return Record{Sequence: sequence, Event: event}, true, nil
}

func (s *Store) Read(ctx context.Context, afterSequence int64, limit int) ([]Record, error) {
	if afterSequence < 0 {
		return nil, errors.New("after sequence cannot be negative")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, err := s.db.QueryContext(
		ctx,
		"SELECT sequence, envelope FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
		afterSequence,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("read events: %w", err)
	}
	defer rows.Close()

	records := make([]Record, 0)
	for rows.Next() {
		var record Record
		var envelope []byte
		if err := rows.Scan(&record.Sequence, &envelope); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if err := json.Unmarshal(envelope, &record.Event); err != nil {
			return nil, fmt.Errorf("decode event at sequence %d: %w", record.Sequence, err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return records, nil
}

func projectFinding(ctx context.Context, tx *sql.Tx, record Record) (model.Finding, error) {
	current, found, err := currentFindingTx(ctx, tx, record.Event.FindingID)
	if err != nil {
		return model.Finding{}, err
	}

	switch record.Event.Type {
	case model.EventFindingObserved:
		var observation model.FindingObservation
		if err := decodePayload(record.Event, &observation); err != nil {
			return model.Finding{}, err
		}
		if err := observation.Validate(); err != nil {
			return model.Finding{}, fmt.Errorf("validate finding observation: %w", err)
		}
		current = applyObservation(current, found, record, observation)

	case model.EventFindingAcknowledged:
		if !found {
			return model.Finding{}, ErrFindingNotFound
		}
		if current.State != model.FindingOpen {
			return model.Finding{}, transitionError(current.State, model.FindingAcknowledged)
		}
		transition, err := readTransition(record.Event)
		if err != nil {
			return model.Finding{}, err
		}
		current.State = model.FindingAcknowledged
		current.Acknowledgement = actionFrom(record.Event, transition)
		current.Resolution = nil
		current.SuppressedUntil = nil
		advanceFinding(&current, record)

	case model.EventFindingSuppressed:
		if !found {
			return model.Finding{}, ErrFindingNotFound
		}
		if current.State == model.FindingResolved {
			return model.Finding{}, transitionError(current.State, model.FindingSuppressed)
		}
		transition, err := readTransition(record.Event)
		if err != nil {
			return model.Finding{}, err
		}
		if transition.Until != nil && !transition.Until.After(record.Event.RecordedAt) {
			return model.Finding{}, errors.New("suppression until must be after recorded_at")
		}
		current.State = model.FindingSuppressed
		current.SuppressedUntil = utcTimePointer(transition.Until)
		current.Resolution = nil
		advanceFinding(&current, record)

	case model.EventFindingUnsuppressed:
		if !found {
			return model.Finding{}, ErrFindingNotFound
		}
		if current.State != model.FindingSuppressed {
			return model.Finding{}, transitionError(current.State, model.FindingOpen)
		}
		if _, err := readTransition(record.Event); err != nil {
			return model.Finding{}, err
		}
		current.State = model.FindingOpen
		current.SuppressedUntil = nil
		advanceFinding(&current, record)

	case model.EventFindingResolved:
		if !found {
			return model.Finding{}, ErrFindingNotFound
		}
		if current.State == model.FindingResolved {
			return model.Finding{}, transitionError(current.State, model.FindingResolved)
		}
		transition, err := readTransition(record.Event)
		if err != nil {
			return model.Finding{}, err
		}
		current.State = model.FindingResolved
		current.Resolution = actionFrom(record.Event, transition)
		current.SuppressedUntil = nil
		advanceFinding(&current, record)

	default:
		return model.Finding{}, fmt.Errorf("unsupported finding lifecycle event %q", record.Event.Type)
	}

	if err := current.Validate(); err != nil {
		return model.Finding{}, fmt.Errorf("validate materialized finding: %w", err)
	}
	document, err := json.Marshal(current)
	if err != nil {
		return model.Finding{}, fmt.Errorf("marshal materialized finding: %w", err)
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO current_findings (
			finding_id, state, severity, updated_at, last_event_sequence, document
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(finding_id) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			updated_at = excluded.updated_at,
			last_event_sequence = excluded.last_event_sequence,
			document = excluded.document`,
		current.ID,
		current.State,
		current.Severity,
		current.UpdatedAt.UTC().Format(time.RFC3339Nano),
		current.LastEventSequence,
		document,
	)
	if err != nil {
		return model.Finding{}, fmt.Errorf("materialize finding: %w", err)
	}
	return current, nil
}

func applyObservation(
	current model.Finding,
	found bool,
	record Record,
	observation model.FindingObservation,
) model.Finding {
	if !found {
		return model.Finding{
			Schema:            model.FindingSchema,
			SchemaVersion:     model.FindingSchemaVersion,
			ID:                record.Event.FindingID,
			DetectorID:        observation.DetectorID,
			Category:          observation.Category,
			Title:             observation.Title,
			Summary:           observation.Summary,
			Severity:          observation.Severity,
			State:             model.FindingOpen,
			FirstSeen:         record.Event.OccurredAt.UTC(),
			LastSeen:          record.Event.OccurredAt.UTC(),
			UpdatedAt:         record.Event.RecordedAt.UTC(),
			Occurrences:       1,
			Evidence:          observation.Evidence,
			Remediation:       observation.Remediation,
			Labels:            observation.Labels,
			LastEventID:       record.Event.ID,
			LastEventSequence: record.Sequence,
		}
	}

	current.DetectorID = observation.DetectorID
	current.Category = observation.Category
	current.Title = observation.Title
	current.Summary = observation.Summary
	current.Severity = observation.Severity
	current.Evidence = observation.Evidence
	current.Remediation = observation.Remediation
	current.Labels = observation.Labels
	current.Occurrences++
	if record.Event.OccurredAt.Before(current.FirstSeen) {
		current.FirstSeen = record.Event.OccurredAt.UTC()
	}
	if record.Event.OccurredAt.After(current.LastSeen) {
		current.LastSeen = record.Event.OccurredAt.UTC()
	}
	if current.State == model.FindingResolved {
		current.State = model.FindingOpen
		current.Acknowledgement = nil
		current.Resolution = nil
	}
	if current.State == model.FindingSuppressed &&
		current.SuppressedUntil != nil &&
		!current.SuppressedUntil.After(record.Event.RecordedAt) {
		current.State = model.FindingOpen
		current.SuppressedUntil = nil
	}
	advanceFinding(&current, record)
	return current
}

func advanceFinding(finding *model.Finding, record Record) {
	if record.Event.RecordedAt.After(finding.UpdatedAt) {
		finding.UpdatedAt = record.Event.RecordedAt.UTC()
	}
	finding.LastEventID = record.Event.ID
	finding.LastEventSequence = record.Sequence
}

func readTransition(event model.Event) (model.FindingTransition, error) {
	var transition model.FindingTransition
	if err := decodePayload(event, &transition); err != nil {
		return model.FindingTransition{}, err
	}
	if strings.TrimSpace(transition.Actor) == "" {
		return model.FindingTransition{}, errors.New("finding transition actor is required")
	}
	return transition, nil
}

func actionFrom(event model.Event, transition model.FindingTransition) *model.FindingAction {
	return &model.FindingAction{
		At:    event.RecordedAt.UTC(),
		Actor: transition.Actor,
		Note:  transition.Note,
	}
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func decodePayload(event model.Event, value any) error {
	if len(event.Payload) == 0 {
		return fmt.Errorf("%s event payload is required", event.Type)
	}
	if err := json.Unmarshal(event.Payload, value); err != nil {
		return fmt.Errorf("decode %s payload: %w", event.Type, err)
	}
	return nil
}

func transitionError(from, to model.FindingState) error {
	return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, from, to)
}

func currentFindingTx(ctx context.Context, tx *sql.Tx, id string) (model.Finding, bool, error) {
	var document []byte
	err := tx.QueryRowContext(
		ctx,
		"SELECT document FROM current_findings WHERE finding_id = ?",
		id,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, false, nil
	}
	if err != nil {
		return model.Finding{}, false, fmt.Errorf("read current finding: %w", err)
	}
	var finding model.Finding
	if err := json.Unmarshal(document, &finding); err != nil {
		return model.Finding{}, false, fmt.Errorf("decode current finding: %w", err)
	}
	return finding, true, nil
}

func (s *Store) CurrentFinding(ctx context.Context, id string) (model.Finding, error) {
	var document []byte
	err := s.db.QueryRowContext(
		ctx,
		"SELECT document FROM current_findings WHERE finding_id = ?",
		id,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return model.Finding{}, fmt.Errorf("read current finding: %w", err)
	}
	var finding model.Finding
	if err := json.Unmarshal(document, &finding); err != nil {
		return model.Finding{}, fmt.Errorf("decode current finding: %w", err)
	}
	return finding, nil
}

func (s *Store) ListFindings(ctx context.Context, states ...model.FindingState) ([]model.Finding, error) {
	allowed := make(map[model.FindingState]struct{}, len(states))
	for _, state := range states {
		if !state.Valid() {
			return nil, fmt.Errorf("invalid finding state filter %q", state)
		}
		allowed[state] = struct{}{}
	}

	rows, err := s.db.QueryContext(
		ctx,
		"SELECT document FROM current_findings ORDER BY updated_at DESC, finding_id",
	)
	if err != nil {
		return nil, fmt.Errorf("list current findings: %w", err)
	}
	defer rows.Close()

	findings := make([]model.Finding, 0)
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan current finding: %w", err)
		}
		var finding model.Finding
		if err := json.Unmarshal(document, &finding); err != nil {
			return nil, fmt.Errorf("decode current finding: %w", err)
		}
		if len(allowed) > 0 {
			if _, ok := allowed[finding.State]; !ok {
				continue
			}
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate current findings: %w", err)
	}
	return findings, nil
}

func (s *Store) RebuildFindings(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin finding rebuild: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "DELETE FROM current_findings"); err != nil {
		return fmt.Errorf("clear finding projection: %w", err)
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT sequence, envelope
		FROM events
		WHERE event_type LIKE 'finding.%'
		ORDER BY sequence`,
	)
	if err != nil {
		return fmt.Errorf("read finding events: %w", err)
	}

	records := make([]Record, 0)
	for rows.Next() {
		var record Record
		var envelope []byte
		if err := rows.Scan(&record.Sequence, &envelope); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan finding event: %w", err)
		}
		if err := json.Unmarshal(envelope, &record.Event); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode finding event at sequence %d: %w", record.Sequence, err)
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close finding event rows: %w", err)
	}
	for _, record := range records {
		if _, err := projectFinding(ctx, tx, record); err != nil {
			return fmt.Errorf("replay finding event at sequence %d: %w", record.Sequence, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit finding rebuild: %w", err)
	}
	return nil
}

func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if !findings[i].UpdatedAt.Equal(findings[j].UpdatedAt) {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].ID < findings[j].ID
	})
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 2
	case model.SeverityWarn:
		return 1
	default:
		return 0
	}
}
