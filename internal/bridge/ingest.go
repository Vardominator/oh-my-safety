package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/model"
)

const (
	IngestSchema         = "io.oh-my-safety/scan-ingest"
	IngestSchemaVersion  = 1
	CheckResultSchema    = "io.oh-my-safety/check-result"
	ScanCompletedSchema  = "io.oh-my-safety/scan-completed"
	PayloadSchemaVersion = 1
)

type IngestStore interface {
	journal.Journal
	journal.FindingReader
}

type IngestEnvelope struct {
	Schema          string `json:"schema"`
	SchemaVersion   int    `json:"schema_version"`
	SnapshotID      string `json:"snapshot_id"`
	CorrelationID   string `json:"correlation_id"`
	Results         int    `json:"results"`
	AlreadyIngested bool   `json:"already_ingested"`
}

type CheckResultPayload struct {
	Schema        string         `json:"schema"`
	SchemaVersion int            `json:"schema_version"`
	Category      string         `json:"category"`
	Name          string         `json:"name"`
	Status        CheckStatus    `json:"status"`
	Severity      model.Severity `json:"severity"`
	Summary       string         `json:"summary"`
	Remediation   string         `json:"remediation,omitempty"`
	Guide         string         `json:"guide,omitempty"`
	Scope         ScanScope      `json:"scope"`
}

type ScanCounts struct {
	OK       int `json:"ok"`
	Warn     int `json:"warn"`
	Critical int `json:"critical"`
	Skipped  int `json:"skipped"`
	Error    int `json:"error"`
}

type ScanCompletedPayload struct {
	Schema        string       `json:"schema"`
	SchemaVersion int          `json:"schema_version"`
	Metadata      ScanMetadata `json:"metadata"`
	Counts        ScanCounts   `json:"counts"`
}

func IngestScan(
	ctx context.Context,
	store IngestStore,
	snapshot ScanSnapshot,
) (IngestEnvelope, error) {
	if store == nil {
		return IngestEnvelope{}, errors.New("ingest store is required")
	}
	if err := snapshot.Validate(); err != nil {
		return IngestEnvelope{}, err
	}
	digest, err := SnapshotDigest(snapshot)
	if err != nil {
		return IngestEnvelope{}, err
	}
	snapshotID := "sha256:" + digest
	correlationID := "scan:" + digest
	envelope := IngestEnvelope{
		Schema:        IngestSchema,
		SchemaVersion: IngestSchemaVersion,
		SnapshotID:    snapshotID,
		CorrelationID: correlationID,
		Results:       len(snapshot.Results),
	}

	completed, err := scanCompletedEvent(snapshot, digest, correlationID)
	if err != nil {
		return IngestEnvelope{}, err
	}
	existing, exists, err := eventByID(ctx, store, completed.ID)
	if err != nil {
		return IngestEnvelope{}, err
	}
	if exists {
		storedEnvelope, storedErr := json.Marshal(existing.Event)
		expectedEnvelope, expectedErr := json.Marshal(completed)
		if storedErr != nil ||
			expectedErr != nil ||
			!bytes.Equal(storedEnvelope, expectedEnvelope) {
			return IngestEnvelope{}, fmt.Errorf(
				"%w: %s",
				journal.ErrEventIDConflict,
				completed.ID,
			)
		}
		envelope.AlreadyIngested = true
		return envelope, nil
	}

	results := append([]CheckResult(nil), snapshot.Results...)
	sortResults(results)
	for _, result := range results {
		checkEvent, err := checkResultEvent(snapshot, result, digest, correlationID)
		if err != nil {
			return IngestEnvelope{}, err
		}
		if _, err := store.Append(ctx, checkEvent); err != nil {
			return IngestEnvelope{}, fmt.Errorf("append check result: %w", err)
		}

		switch result.Status {
		case CheckStatusWarn, CheckStatusCritical, CheckStatusError:
			findingEvent, err := findingObservedEvent(
				snapshot,
				result,
				digest,
				correlationID,
			)
			if err != nil {
				return IngestEnvelope{}, err
			}
			if _, err := store.Append(ctx, findingEvent); err != nil {
				return IngestEnvelope{}, fmt.Errorf("append observed finding: %w", err)
			}

		case CheckStatusOK:
			findingID := checkFindingID(result)
			current, err := store.CurrentFinding(ctx, findingID)
			if errors.Is(err, journal.ErrFindingNotFound) {
				continue
			}
			if err != nil {
				return IngestEnvelope{}, fmt.Errorf("read finding before resolution: %w", err)
			}
			if current.State == model.FindingResolved {
				continue
			}
			resolvedEvent, err := findingResolvedEvent(
				snapshot,
				result,
				digest,
				correlationID,
			)
			if err != nil {
				return IngestEnvelope{}, err
			}
			if _, err := store.Append(ctx, resolvedEvent); err != nil {
				return IngestEnvelope{}, fmt.Errorf("append resolved finding: %w", err)
			}

		case CheckStatusSkip:
			// A skipped check is a coverage gap, never evidence of resolution.
		}
	}

	if _, err := store.Append(ctx, completed); err != nil {
		return IngestEnvelope{}, fmt.Errorf("append completed scan: %w", err)
	}
	return envelope, nil
}

func checkResultEvent(
	snapshot ScanSnapshot,
	result CheckResult,
	digest string,
	correlationID string,
) (model.Event, error) {
	payload := CheckResultPayload{
		Schema:        CheckResultSchema,
		SchemaVersion: PayloadSchemaVersion,
		Category:      result.Category,
		Name:          result.Name,
		Status:        result.Status,
		Severity:      result.Severity,
		Summary:       result.Summary,
		Remediation:   result.Remediation,
		Guide:         result.Guide,
		Scope:         snapshot.Metadata.Scope,
	}
	return bridgeEvent(
		snapshot,
		deterministicEventID(digest, "check.result", result.Category, result.Name),
		"check.result",
		correlationID,
		"",
		&model.Subject{
			Type: "check",
			ID:   result.Category + "/" + result.Name,
			Name: result.Name,
		},
		map[string]string{
			"category": result.Category,
			"scope":    string(snapshot.Metadata.Scope),
			"status":   string(result.Status),
		},
		payload,
	)
}

func findingObservedEvent(
	snapshot ScanSnapshot,
	result CheckResult,
	digest string,
	correlationID string,
) (model.Event, error) {
	var remediation *model.Remediation
	if result.Remediation != "" || result.Guide != "" {
		summary := result.Remediation
		if summary == "" {
			summary = "Review the check guide."
		}
		remediation = &model.Remediation{
			Summary: summary,
			Guide:   result.Guide,
		}
	}
	observation := model.FindingObservation{
		DetectorID:  result.Name,
		Category:    result.Category,
		Title:       result.Name + " check reported " + string(result.Status),
		Summary:     result.Summary,
		Severity:    result.Severity,
		Remediation: remediation,
		Labels: map[string]string{
			"scope":  string(snapshot.Metadata.Scope),
			"source": snapshot.Metadata.Source,
			"status": string(result.Status),
		},
	}
	findingID := checkFindingID(result)
	return bridgeEvent(
		snapshot,
		deterministicEventID(
			digest,
			model.EventFindingObserved,
			result.Category,
			result.Name,
		),
		model.EventFindingObserved,
		correlationID,
		findingID,
		&model.Subject{
			Type: "check",
			ID:   result.Category + "/" + result.Name,
			Name: result.Name,
		},
		map[string]string{
			"category": result.Category,
			"scope":    string(snapshot.Metadata.Scope),
		},
		observation,
	)
}

func findingResolvedEvent(
	snapshot ScanSnapshot,
	result CheckResult,
	digest string,
	correlationID string,
) (model.Event, error) {
	return bridgeEvent(
		snapshot,
		deterministicEventID(
			digest,
			model.EventFindingResolved,
			result.Category,
			result.Name,
		),
		model.EventFindingResolved,
		correlationID,
		checkFindingID(result),
		&model.Subject{
			Type: "check",
			ID:   result.Category + "/" + result.Name,
			Name: result.Name,
		},
		map[string]string{
			"category": result.Category,
			"scope":    string(snapshot.Metadata.Scope),
		},
		model.FindingTransition{
			Actor: "bridge:last-scan-v1",
			Note:  "check returned ok",
		},
	)
}

func scanCompletedEvent(
	snapshot ScanSnapshot,
	digest string,
	correlationID string,
) (model.Event, error) {
	return bridgeEvent(
		snapshot,
		deterministicEventID(digest, "scan.completed"),
		"scan.completed",
		correlationID,
		"",
		&model.Subject{
			Type: "host",
			ID:   "local",
			Name: snapshot.Metadata.Platform,
		},
		map[string]string{"scope": string(snapshot.Metadata.Scope)},
		ScanCompletedPayload{
			Schema:        ScanCompletedSchema,
			SchemaVersion: PayloadSchemaVersion,
			Metadata:      snapshot.Metadata,
			Counts:        scanCounts(snapshot.Results),
		},
	)
}

func bridgeEvent(
	snapshot ScanSnapshot,
	id string,
	eventType string,
	correlationID string,
	findingID string,
	subject *model.Subject,
	labels map[string]string,
	payload any,
) (model.Event, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return model.Event{}, errors.New("encode bridge event payload")
	}
	timestamp := snapshot.Metadata.UpdatedAt.UTC()
	event := model.Event{
		Schema:        model.EventSchema,
		SchemaVersion: model.EventSchemaVersion,
		ID:            id,
		Type:          eventType,
		OccurredAt:    timestamp,
		RecordedAt:    timestamp,
		Source:        snapshot.Metadata.Source,
		Platform:      snapshot.Metadata.Platform,
		Subject:       subject,
		FindingID:     findingID,
		CorrelationID: correlationID,
		Labels:        labels,
		Payload:       encoded,
	}
	if err := event.Validate(); err != nil {
		return model.Event{}, fmt.Errorf("validate bridge event: %w", err)
	}
	return event, nil
}

func eventByID(
	ctx context.Context,
	store journal.Journal,
	id string,
) (journal.Record, bool, error) {
	var after int64
	for {
		records, err := store.Read(ctx, after, 1000)
		if err != nil {
			return journal.Record{}, false, fmt.Errorf("search journal: %w", err)
		}
		if len(records) == 0 {
			return journal.Record{}, false, nil
		}
		for _, record := range records {
			if record.Event.ID == id {
				return record, true, nil
			}
			after = record.Sequence
		}
	}
}

func deterministicEventID(digest string, parts ...string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("oh-my-safety:bridge:v1"))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(digest))
	for _, part := range parts {
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(part))
	}
	return "bridge:v1:" + hex.EncodeToString(hasher.Sum(nil))
}

func checkFindingID(result CheckResult) string {
	return "check:" + result.Category + "/" + result.Name
}

func scanCounts(results []CheckResult) ScanCounts {
	var counts ScanCounts
	for _, result := range results {
		switch result.Status {
		case CheckStatusOK:
			counts.OK++
		case CheckStatusWarn:
			counts.Warn++
		case CheckStatusCritical:
			counts.Critical++
		case CheckStatusSkip:
			counts.Skipped++
		case CheckStatusError:
			counts.Error++
		}
	}
	return counts
}
