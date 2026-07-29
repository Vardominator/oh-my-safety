package bridge

import (
	"context"
	"errors"
	"fmt"

	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/model"
)

const (
	HistorySchema         = "io.oh-my-safety/history"
	HistorySchemaVersion  = 1
	FindingsSchema        = "io.oh-my-safety/findings"
	FindingsSchemaVersion = 1
	DefaultQueryLimit     = 100
	MaxQueryLimit         = 1000
)

type HistoryEnvelope struct {
	Schema        string           `json:"schema"`
	SchemaVersion int              `json:"schema_version"`
	Limit         int              `json:"limit"`
	Count         int              `json:"count"`
	Events        []journal.Record `json:"events"`
}

type FindingsEnvelope struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Limit         int             `json:"limit"`
	Count         int             `json:"count"`
	Findings      []model.Finding `json:"findings"`
}

func History(
	ctx context.Context,
	reader journal.Journal,
	limit int,
) (HistoryEnvelope, error) {
	if reader == nil {
		return HistoryEnvelope{}, errors.New("history reader is required")
	}
	if err := ValidateQueryLimit(limit); err != nil {
		return HistoryEnvelope{}, err
	}
	records, err := reader.Read(ctx, 0, limit)
	if err != nil {
		return HistoryEnvelope{}, fmt.Errorf("read history: %w", err)
	}
	if records == nil {
		records = make([]journal.Record, 0)
	}
	return HistoryEnvelope{
		Schema:        HistorySchema,
		SchemaVersion: HistorySchemaVersion,
		Limit:         limit,
		Count:         len(records),
		Events:        records,
	}, nil
}

func Findings(
	ctx context.Context,
	reader journal.FindingReader,
	limit int,
) (FindingsEnvelope, error) {
	if reader == nil {
		return FindingsEnvelope{}, errors.New("finding reader is required")
	}
	if err := ValidateQueryLimit(limit); err != nil {
		return FindingsEnvelope{}, err
	}
	findings, err := reader.ListFindings(ctx)
	if err != nil {
		return FindingsEnvelope{}, fmt.Errorf("read findings: %w", err)
	}
	journal.SortFindings(findings)
	if len(findings) > limit {
		findings = findings[:limit]
	}
	if findings == nil {
		findings = make([]model.Finding, 0)
	}
	return FindingsEnvelope{
		Schema:        FindingsSchema,
		SchemaVersion: FindingsSchemaVersion,
		Limit:         limit,
		Count:         len(findings),
		Findings:      findings,
	}, nil
}

func ValidateQueryLimit(limit int) error {
	if limit < 1 || limit > MaxQueryLimit {
		return fmt.Errorf("limit must be between 1 and %d", MaxQueryLimit)
	}
	return nil
}
