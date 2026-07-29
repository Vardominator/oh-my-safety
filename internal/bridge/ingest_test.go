package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/model"
)

func TestIngestIsDeterministicIdempotentAndUsesStableContracts(t *testing.T) {
	store := openBridgeStore(t)
	snapshot := mustParseScan(t, warnScanTSV())
	ctx := context.Background()

	first, err := IngestScan(ctx, store, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(
		`{"schema":"io.oh-my-safety/scan-ingest","schema_version":1,"snapshot_id":"sha256:%s","correlation_id":"scan:%s","results":2,"already_ingested":false}`,
		digest,
		digest,
	)
	if string(encoded) != want {
		t.Fatalf("ingest contract changed\nwant: %s\n got: %s", want, encoded)
	}

	records, err := store.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{
		"check.result",
		"check.result",
		model.EventFindingObserved,
		"scan.completed",
	}
	if len(records) != len(wantTypes) {
		t.Fatalf("event count = %d, want %d: %#v", len(records), len(wantTypes), records)
	}
	for index, record := range records {
		if record.Event.Type != wantTypes[index] {
			t.Fatalf("event %d type = %q, want %q", index, record.Event.Type, wantTypes[index])
		}
		if record.Event.CorrelationID != "scan:"+digest {
			t.Fatalf("event %d correlation = %q", index, record.Event.CorrelationID)
		}
		if !record.Event.OccurredAt.Equal(snapshot.Metadata.UpdatedAt) ||
			!record.Event.RecordedAt.Equal(snapshot.Metadata.UpdatedAt) {
			t.Fatalf("event %d has nondeterministic timestamps: %#v", index, record.Event)
		}
	}

	var resultPayload CheckResultPayload
	if err := json.Unmarshal(records[1].Event.Payload, &resultPayload); err != nil {
		t.Fatal(err)
	}
	if resultPayload.Schema != CheckResultSchema ||
		resultPayload.SchemaVersion != PayloadSchemaVersion ||
		resultPayload.Summary != "Credential-like content found" ||
		resultPayload.Remediation != "Rotate then remove the credential." {
		t.Fatalf("unexpected check-result payload: %#v", resultPayload)
	}

	var completedPayload ScanCompletedPayload
	if err := json.Unmarshal(records[len(records)-1].Event.Payload, &completedPayload); err != nil {
		t.Fatal(err)
	}
	if completedPayload.Schema != ScanCompletedSchema ||
		completedPayload.Counts.OK != 1 ||
		completedPayload.Counts.Warn != 1 {
		t.Fatalf("unexpected scan-completed payload: %#v", completedPayload)
	}

	second, err := IngestScan(ctx, store, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !second.AlreadyIngested ||
		second.SnapshotID != first.SnapshotID ||
		second.CorrelationID != first.CorrelationID {
		t.Fatalf("unexpected idempotent result: %#v", second)
	}
	after, err := store.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(records) {
		t.Fatalf("re-ingest appended events: before=%d after=%d", len(records), len(after))
	}

	finding, err := store.CurrentFinding(ctx, "check:security/secrets-content")
	if err != nil {
		t.Fatal(err)
	}
	if finding.State != model.FindingOpen ||
		finding.Occurrences != 1 ||
		finding.Summary != "Credential-like content found" {
		t.Fatalf("unexpected finding projection: %#v", finding)
	}
}

func TestWarnThenSkipStaysOpenThenOKResolves(t *testing.T) {
	store := openBridgeStore(t)
	ctx := context.Background()

	warn := singleResultScan(
		"2026-07-29T12:00:00Z",
		ScanScopeFull,
		"security",
		"process-audit",
		CheckStatusWarn,
		model.SeverityWarn,
		"Suspicious process observed",
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, warn)); err != nil {
		t.Fatal(err)
	}
	assertBridgeFindingState(t, store, "check:security/process-audit", model.FindingOpen)

	skip := singleResultScan(
		"2026-07-29T12:10:00Z",
		ScanScopePartial,
		"security",
		"process-audit",
		CheckStatusSkip,
		model.SeverityInfo,
		"Full Disk Access unavailable",
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, skip)); err != nil {
		t.Fatal(err)
	}
	assertBridgeFindingState(t, store, "check:security/process-audit", model.FindingOpen)

	ok := singleResultScan(
		"2026-07-29T12:20:00Z",
		ScanScopePartial,
		"security",
		"process-audit",
		CheckStatusOK,
		model.SeverityInfo,
		"No suspicious processes",
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, ok)); err != nil {
		t.Fatal(err)
	}
	finding := assertBridgeFindingState(
		t,
		store,
		"check:security/process-audit",
		model.FindingResolved,
	)
	if finding.Resolution == nil ||
		finding.Resolution.Actor != "bridge:last-scan-v1" {
		t.Fatalf("resolution action missing: %#v", finding.Resolution)
	}
}

func TestPartialScopeOnlyResolvesChecksPresentInSnapshot(t *testing.T) {
	store := openBridgeStore(t)
	ctx := context.Background()
	full := scanWithRows(
		"2026-07-29T12:00:00Z",
		ScanScopeFull,
		1,
		[]string{
			"result\tsecurity\tprocess-audit\twarn\twarn\tProcess finding\t\t",
			"result\tsecurity\tpersistence-scan\twarn\twarn\tPersistence finding\t\t",
		},
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, full)); err != nil {
		t.Fatal(err)
	}

	partial := singleResultScan(
		"2026-07-29T12:05:00Z",
		ScanScopePartial,
		"security",
		"process-audit",
		CheckStatusOK,
		model.SeverityInfo,
		"Process check clear",
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, partial)); err != nil {
		t.Fatal(err)
	}
	assertBridgeFindingState(
		t,
		store,
		"check:security/process-audit",
		model.FindingResolved,
	)
	assertBridgeFindingState(
		t,
		store,
		"check:security/persistence-scan",
		model.FindingOpen,
	)
}

func TestErrorResultCreatesCriticalCoverageFinding(t *testing.T) {
	store := openBridgeStore(t)
	input := singleResultScan(
		"2026-07-29T12:00:00Z",
		ScanScopePartial,
		"runner",
		"self-check",
		CheckStatusError,
		model.SeverityCritical,
		"No checks ran",
	)
	if _, err := IngestScan(context.Background(), store, mustParseScan(t, input)); err != nil {
		t.Fatal(err)
	}
	finding := assertBridgeFindingState(
		t,
		store,
		"check:runner/self-check",
		model.FindingOpen,
	)
	if finding.Severity != model.SeverityCritical {
		t.Fatalf("error finding severity = %q", finding.Severity)
	}
}

func TestIngestRejectsInvalidDirectSnapshotBeforeWriting(t *testing.T) {
	store := openBridgeStore(t)
	snapshot := mustParseScan(t, warnScanTSV())
	snapshot.Results[0].Guide = "../../outside"
	if _, err := IngestScan(context.Background(), store, snapshot); err == nil {
		t.Fatal("invalid direct snapshot accepted")
	}
	records, err := store.Read(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("invalid snapshot wrote events: %#v", records)
	}
}

func TestIngestRejectsConflictingCompletionMarker(t *testing.T) {
	store := openBridgeStore(t)
	ctx := context.Background()
	snapshot := mustParseScan(t, warnScanTSV())
	digest, err := SnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := scanCompletedEvent(snapshot, digest, "scan:"+digest)
	if err != nil {
		t.Fatal(err)
	}
	completed.Type = "scan.conflicting"
	if _, err := store.Append(ctx, completed); err != nil {
		t.Fatal(err)
	}

	if _, err := IngestScan(ctx, store, snapshot); !errors.Is(err, journal.ErrEventIDConflict) {
		t.Fatalf("conflicting marker error = %v, want ErrEventIDConflict", err)
	}
	records, err := store.Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("conflicting marker caused writes: %#v", records)
	}
}

func TestHistoryAndFindingsHaveExactEmptyJSONContracts(t *testing.T) {
	store := openBridgeStore(t)
	history, err := History(context.Background(), store, 2)
	if err != nil {
		t.Fatal(err)
	}
	historyJSON, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	wantHistory := `{"schema":"io.oh-my-safety/history","schema_version":1,"limit":2,"count":0,"events":[]}`
	if string(historyJSON) != wantHistory {
		t.Fatalf("history contract changed\nwant: %s\n got: %s", wantHistory, historyJSON)
	}

	findings, err := Findings(context.Background(), store, 3)
	if err != nil {
		t.Fatal(err)
	}
	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	wantFindings := `{"schema":"io.oh-my-safety/findings","schema_version":1,"limit":3,"count":0,"findings":[]}`
	if string(findingsJSON) != wantFindings {
		t.Fatalf("findings contract changed\nwant: %s\n got: %s", wantFindings, findingsJSON)
	}
}

func TestHistoryAndFindingsRespectBoundedLimit(t *testing.T) {
	store := openBridgeStore(t)
	ctx := context.Background()
	input := scanWithRows(
		"2026-07-29T12:00:00Z",
		ScanScopeFull,
		2,
		[]string{
			"result\tsecurity\twarning-check\twarn\twarn\tWarning\t\t",
			"result\tsecurity\tcritical-check\tcritical\tcritical\tCritical\t\t",
		},
	)
	if _, err := IngestScan(ctx, store, mustParseScan(t, input)); err != nil {
		t.Fatal(err)
	}
	history, err := History(ctx, store, 2)
	if err != nil {
		t.Fatal(err)
	}
	if history.Count != 2 || len(history.Events) != 2 {
		t.Fatalf("history limit not applied: %#v", history)
	}
	findings, err := Findings(ctx, store, 1)
	if err != nil {
		t.Fatal(err)
	}
	if findings.Count != 1 ||
		len(findings.Findings) != 1 ||
		findings.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("findings limit/sort not applied: %#v", findings)
	}
	for _, invalid := range []int{0, -1, MaxQueryLimit + 1} {
		if err := ValidateQueryLimit(invalid); err == nil {
			t.Fatalf("invalid limit %d accepted", invalid)
		}
	}
}

func openBridgeStore(t *testing.T) *journal.Store {
	t.Helper()
	store, err := journal.Open(filepath.Join(t.TempDir(), "journal.db"))
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

func mustParseScan(t *testing.T, input string) ScanSnapshot {
	t.Helper()
	snapshot, err := ParseScan(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertBridgeFindingState(
	t *testing.T,
	store *journal.Store,
	id string,
	state model.FindingState,
) model.Finding {
	t.Helper()
	finding, err := store.CurrentFinding(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if finding.State != state {
		t.Fatalf("finding %s state = %q, want %q: %#v", id, finding.State, state, finding)
	}
	return finding
}

func singleResultScan(
	timestamp string,
	scope ScanScope,
	category string,
	name string,
	status CheckStatus,
	severity model.Severity,
	summary string,
) string {
	exitCode := 0
	switch status {
	case CheckStatusWarn:
		exitCode = 1
	case CheckStatusCritical:
		exitCode = 2
	case CheckStatusError:
		exitCode = 3
	}
	row := fmt.Sprintf(
		"result\t%s\t%s\t%s\t%s\t%s\t\t",
		category,
		name,
		status,
		severity,
		summary,
	)
	return scanWithRows(timestamp, scope, exitCode, []string{row})
}

func scanWithRows(timestamp string, scope ScanScope, exitCode int, rows []string) string {
	lines := []string{
		"schema\t1",
		"meta\ttimestamp\t" + timestamp,
		"meta\tupdated_at\t" + timestamp,
		"meta\tversion\t0.2.3",
		"meta\tplatform\tlinux",
		"meta\tsource\tagent",
		"meta\tscope\t" + string(scope),
		fmt.Sprintf("meta\texit\t%d", exitCode),
		"meta\tfda\tfalse",
	}
	lines = append(lines, rows...)
	return strings.Join(lines, "\n")
}
