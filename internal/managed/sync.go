package managed

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/controller"
	"github.com/Vardominator/oh-my-safety/internal/model"
)

type FindingSource interface {
	ListFindings(context.Context, ...model.FindingState) ([]model.Finding, error)
}

type SyncResult struct {
	PolicyID         string `json:"policy_id"`
	PolicyRevision   uint64 `json:"policy_revision"`
	PolicyPath       string `json:"policy_path"`
	ReportingEnabled bool   `json:"reporting_enabled"`
	FindingsSent     int    `json:"findings_sent"`
}

func (client *Client) Sync(
	ctx context.Context,
	source FindingSource,
	metadata controller.DeviceMetadata,
	now time.Time,
) (SyncResult, error) {
	if ctx == nil {
		return SyncResult{}, errors.New("managed sync context is required")
	}
	if source == nil {
		return SyncResult{}, errors.New("local finding source is required")
	}
	if now.IsZero() {
		return SyncResult{}, errors.New("managed sync timestamp is required")
	}
	if err := client.Heartbeat(ctx, metadata); err != nil {
		return SyncResult{}, err
	}
	policy, err := client.FetchPolicy(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{
		PolicyID:         policy.ID,
		PolicyRevision:   policy.Revision,
		PolicyPath:       client.policyPath,
		ReportingEnabled: policy.Reporting.Enabled,
	}
	if !policy.Reporting.Enabled {
		return result, nil
	}
	localFindings, err := source.ListFindings(ctx)
	if err != nil {
		return SyncResult{}, errors.New("read local findings for managed sync")
	}
	redacted, err := RedactFindings(localFindings)
	if err != nil {
		return SyncResult{}, err
	}
	report := controller.ReportSync{
		Schema:        controller.ReportSchema,
		SchemaVersion: controller.ReportSchemaVersion,
		ReportedAt:    now.UTC(),
		Findings:      redacted,
	}
	if err := client.SubmitReport(ctx, report, now); err != nil {
		return SyncResult{}, err
	}
	result.FindingsSent = len(redacted)
	return result, nil
}

// RedactFindings is an allowlist transformation. It never reads or copies a
// finding's title, summary, evidence, remediation, labels, subject, action
// notes, paths, commands, or raw event data.
func RedactFindings(findings []model.Finding) ([]controller.RedactedFinding, error) {
	aggregated := make(map[string]controller.RedactedFinding, len(findings))
	for _, finding := range findings {
		category := finding.Category
		if category == "" {
			category = "uncategorized"
		}
		candidate := controller.RedactedFinding{
			DetectorID:  finding.DetectorID,
			Category:    category,
			Severity:    finding.Severity,
			State:       finding.State,
			FirstSeen:   finding.FirstSeen.UTC(),
			LastSeen:    finding.LastSeen.UTC(),
			Occurrences: finding.Occurrences,
		}
		key := candidate.DetectorID + "\x00" + candidate.Category
		existing, found := aggregated[key]
		if !found {
			aggregated[key] = candidate
			continue
		}
		if math.MaxUint64-existing.Occurrences < candidate.Occurrences {
			return nil, errors.New("redacted finding occurrence count overflow")
		}
		existing.Occurrences += candidate.Occurrences
		if candidate.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = candidate.FirstSeen
		}
		if candidate.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = candidate.LastSeen
		}
		if severityRank(candidate.Severity) > severityRank(existing.Severity) {
			existing.Severity = candidate.Severity
		}
		if stateRank(candidate.State) > stateRank(existing.State) {
			existing.State = candidate.State
		}
		aggregated[key] = existing
	}
	redacted := make([]controller.RedactedFinding, 0, len(aggregated))
	for _, finding := range aggregated {
		redacted = append(redacted, finding)
	}
	sort.Slice(redacted, func(left, right int) bool {
		if redacted[left].DetectorID == redacted[right].DetectorID {
			return redacted[left].Category < redacted[right].Category
		}
		return redacted[left].DetectorID < redacted[right].DetectorID
	})
	return redacted, nil
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 3
	case model.SeverityWarn:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func stateRank(state model.FindingState) int {
	switch state {
	case model.FindingOpen:
		return 4
	case model.FindingAcknowledged:
		return 3
	case model.FindingSuppressed:
		return 2
	case model.FindingResolved:
		return 1
	default:
		return 0
	}
}
