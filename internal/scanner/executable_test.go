package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExecutableTriageRecordsMetadataHashAndConservativeSignals(t *testing.T) {
	root := t.TempDir()
	downloads := filepath.Join(root, "Downloads")
	mustMkdirAll(t, downloads)
	path := filepath.Join(downloads, ".payload")
	content := []byte("#!/bin/sh\necho local-test\n")
	writeBytes(t, path, content, 0o700)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewExecutableScanner(ExecutableOptions{
		PackageOwnership: func(context.Context, string) (PackageOwnership, error) {
			return PackageOwnership{Status: PackageOwnershipUnowned}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(context.Background(), []ExecutableCandidate{{Path: path, New: true}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != ExecutableResultSchema ||
		result.SchemaVersion != ExecutableResultSchemaVersion ||
		result.ScannerID != ExecutableScannerID ||
		len(result.Executables) != 1 {
		t.Fatalf("unexpected triage contract: %#v", result)
	}

	record := result.Executables[0]
	sum := sha256.Sum256(content)
	if record.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) ||
		record.Path != path ||
		record.Size != int64(len(content)) ||
		!record.Ownership.Known ||
		record.PackageOwnership.Status != PackageOwnershipUnowned {
		t.Fatalf("incomplete executable metadata: %#v", record)
	}
	if record.Mode != "0755" {
		t.Fatalf("mode = %q, want 0755", record.Mode)
	}
	wantSignals := []TriageSignal{
		{ID: "hidden-executable", Assessment: AssessmentSuspicious},
		{ID: "new-executable-in-temp-or-downloads", Assessment: AssessmentSuspicious},
		{ID: "package-ownership-unowned", Assessment: AssessmentUnknown},
	}
	if !reflect.DeepEqual(record.Signals, wantSignals) {
		t.Fatalf("signals\n got: %#v\nwant: %#v", record.Signals, wantSignals)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "malware") {
		t.Fatalf("triage result made a malware verdict: %s", encoded)
	}
}

func TestExecutableSpecialModeSignalsAreConservativeObservations(t *testing.T) {
	mode := os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid
	signals := executableSignals(
		ExecutableCandidate{Path: "/usr/local/bin/tool"},
		mode,
		TriageSignal{},
	)
	want := []TriageSignal{
		{ID: "setgid-executable", Assessment: AssessmentSuspicious},
		{ID: "setuid-executable", Assessment: AssessmentSuspicious},
	}
	if !reflect.DeepEqual(signals, want) {
		t.Fatalf("special mode signals\n got: %#v\nwant: %#v", signals, want)
	}
	if got := normalizedMode(mode); got != "06755" {
		t.Fatalf("normalized special mode = %q, want 06755", got)
	}
}

func TestExecutableTriageIsDeterministicAndDeduplicatesCandidates(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	writeExecutable(t, first, "first")
	writeExecutable(t, second, "second")

	lookup := func(_ context.Context, path string) (PackageOwnership, error) {
		return PackageOwnership{Status: PackageOwnershipOwned, Package: "pkg-" + filepath.Base(path)}, nil
	}
	scanner, err := NewExecutableScanner(ExecutableOptions{PackageOwnership: lookup})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := scanner.Triage(context.Background(), []ExecutableCandidate{
		{Path: second},
		{Path: first},
		{Path: second, New: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := scanner.Triage(context.Background(), []ExecutableCandidate{
		{Path: first},
		{Path: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("candidate order changed deterministic result\nforward: %#v\nreverse: %#v", forward, reversed)
	}
	if len(forward.Executables) != 2 {
		t.Fatalf("deduplicated executables = %d, want 2", len(forward.Executables))
	}
	firstJSON, _ := json.Marshal(forward)
	secondJSON, _ := json.Marshal(reversed)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("JSON contract is nondeterministic\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestExecutableTriageSkipsUnsafeInputsAndReportsBounds(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeExecutable(t, target, "target")
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "plain")
	writeFile(t, plain, "plain", 0o600)
	oversize := filepath.Join(root, "oversize")
	writeExecutable(t, oversize, strings.Repeat("x", 80))
	missing := filepath.Join(root, "missing")

	scanner, err := NewExecutableScanner(ExecutableOptions{
		Limits: ExecutableLimits{MaxFileBytes: 64, MaxTotalBytes: 1_024, MaxFiles: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(context.Background(), []ExecutableCandidate{
		{Path: link},
		{Path: plain},
		{Path: oversize},
		{Path: missing},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executables) != 0 {
		t.Fatalf("unsafe inputs were triaged: %#v", result.Executables)
	}
	if result.Stats.SymlinksSkipped != 1 ||
		result.Stats.NonExecutableSkipped != 1 ||
		result.Stats.OversizeSkipped != 1 ||
		result.Stats.MissingSkipped != 1 {
		t.Fatalf("unexpected skip stats: %#v", result.Stats)
	}
	assertCoverage(t, result.Coverage, CoverageMaxFileBytes)
}

func TestExecutableTriageSkipsDeviceAndEmptyCandidates(t *testing.T) {
	if _, err := os.Lstat("/dev/null"); err != nil {
		t.Skipf("no portable device fixture: %v", err)
	}
	scanner, err := NewExecutableScanner(ExecutableOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(context.Background(), []ExecutableCandidate{
		{},
		{Path: "   "},
		{Path: "/dev/null", New: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executables) != 0 ||
		result.Stats.FilesConsidered != 1 ||
		result.Stats.NonRegularSkipped != 1 {
		t.Fatalf("device or empty candidate was not skipped: %#v", result)
	}
}

func TestExecutableTriageReportsFileAndTotalBounds(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "a")
		second := filepath.Join(root, "b")
		writeExecutable(t, first, "a")
		writeExecutable(t, second, "b")
		scanner, err := NewExecutableScanner(ExecutableOptions{
			Limits: ExecutableLimits{MaxFileBytes: 64, MaxTotalBytes: 128, MaxFiles: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := scanner.Triage(context.Background(), []ExecutableCandidate{{Path: second}, {Path: first}})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Executables) != 1 {
			t.Fatalf("executables = %d, want 1", len(result.Executables))
		}
		assertCoverage(t, result.Coverage, CoverageMaxFiles)
	})

	t.Run("total bytes", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "a")
		second := filepath.Join(root, "b")
		writeExecutable(t, first, strings.Repeat("a", 20))
		writeExecutable(t, second, strings.Repeat("b", 20))
		scanner, err := NewExecutableScanner(ExecutableOptions{
			Limits: ExecutableLimits{MaxFileBytes: 64, MaxTotalBytes: 30, MaxFiles: 10},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := scanner.Triage(context.Background(), []ExecutableCandidate{{Path: second}, {Path: first}})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Executables) != 1 {
			t.Fatalf("executables = %d, want 1", len(result.Executables))
		}
		assertCoverage(t, result.Coverage, CoverageMaxTotalBytes)
	})
}

func TestExecutablePackageLookupFailureIsUnknownAndRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "tool")
	const lookupDetail = "sensitive-package-lookup-detail"
	scanner, err := NewExecutableScanner(ExecutableOptions{
		PackageOwnership: func(context.Context, string) (PackageOwnership, error) {
			return PackageOwnership{}, errors.New(lookupDetail)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(context.Background(), []ExecutableCandidate{{Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	record := result.Executables[0]
	if record.PackageOwnership.Status != PackageOwnershipUnknown {
		t.Fatalf("lookup error status = %q, want unknown", record.PackageOwnership.Status)
	}
	if !containsSignal(record.Signals, "package-ownership-lookup-failed", AssessmentUnknown) {
		t.Fatalf("lookup failure not represented as unknown: %#v", record.Signals)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), lookupDetail) {
		t.Fatalf("package lookup error detail leaked: %s", encoded)
	}
}

func TestExecutablePackageOwnershipStatesRemainNonVerdicts(t *testing.T) {
	cases := []struct {
		name       string
		lookup     PackageOwnershipLookup
		wantStatus PackageOwnershipStatus
		wantSignal string
	}{
		{
			name: "not configured", lookup: nil,
			wantStatus: PackageOwnershipUnknown, wantSignal: "package-ownership-not-checked",
		},
		{
			name: "unknown",
			lookup: func(context.Context, string) (PackageOwnership, error) {
				return PackageOwnership{Status: PackageOwnershipUnknown}, nil
			},
			wantStatus: PackageOwnershipUnknown, wantSignal: "package-ownership-unknown",
		},
		{
			name: "owned",
			lookup: func(context.Context, string) (PackageOwnership, error) {
				return PackageOwnership{Status: PackageOwnershipOwned, Package: "trusted-package"}, nil
			},
			wantStatus: PackageOwnershipOwned,
		},
		{
			name: "owned without package",
			lookup: func(context.Context, string) (PackageOwnership, error) {
				return PackageOwnership{Status: PackageOwnershipOwned}, nil
			},
			wantStatus: PackageOwnershipUnknown, wantSignal: "package-ownership-invalid-result",
		},
		{
			name: "invalid status",
			lookup: func(context.Context, string) (PackageOwnership, error) {
				return PackageOwnership{Status: "malicious"}, nil
			},
			wantStatus: PackageOwnershipUnknown, wantSignal: "package-ownership-invalid-result",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			scanner, err := NewExecutableScanner(ExecutableOptions{PackageOwnership: testCase.lookup})
			if err != nil {
				t.Fatal(err)
			}
			ownership, signal := scanner.lookupPackageOwnership(context.Background(), "/local/tool")
			if ownership.Status != testCase.wantStatus || signal.ID != testCase.wantSignal {
				t.Fatalf("ownership = %#v signal = %#v", ownership, signal)
			}
			if signal.ID != "" && signal.Assessment != AssessmentUnknown {
				t.Fatalf("package state became a verdict: %#v", signal)
			}
		})
	}
}

func TestExecutableTriagePropagatesCancellationDuringOwnershipLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "tool")
	ctx, cancel := context.WithCancel(context.Background())
	scanner, err := NewExecutableScanner(ExecutableOptions{
		PackageOwnership: func(context.Context, string) (PackageOwnership, error) {
			cancel()
			return PackageOwnership{}, context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(ctx, []ExecutableCandidate{{Path: path}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(result.Executables) != 0 {
		t.Fatalf("canceled lookup produced a record: %#v", result.Executables)
	}
}

func TestExecutableTriageFalsePositiveAndCancellationGuards(t *testing.T) {
	downloads := filepath.Join(t.TempDir(), "Downloads")
	mustMkdirAll(t, downloads)
	path := filepath.Join(downloads, "known-tool")
	writeExecutable(t, path, "known")
	scanner, err := NewExecutableScanner(ExecutableOptions{
		PackageOwnership: func(context.Context, string) (PackageOwnership, error) {
			return PackageOwnership{Status: PackageOwnershipOwned, Package: "known-package"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Triage(context.Background(), []ExecutableCandidate{{Path: path, New: false}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executables) != 1 || len(result.Executables[0].Signals) != 0 {
		t.Fatalf("known unchanged executable received suspicious signals: %#v", result)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled, err := scanner.Triage(ctx, []ExecutableCandidate{{Path: path}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(canceled.Executables) != 0 {
		t.Fatalf("canceled triage returned records: %#v", canceled.Executables)
	}
}

func TestExecutablePathAndModeHelpersAvoidSubstringFalsePositives(t *testing.T) {
	if riskyExecutableLocation("/opt/MyDownloadsCache/tool") {
		t.Fatal("substring-only Downloads path was treated as a Downloads directory")
	}
	if !riskyExecutableLocation(filepath.Join("home", "user", "Downloads", "tool")) {
		t.Fatal("Downloads path was not recognized")
	}
	if !withinPath("/tmp", "/tmp") || withinPath("/tmp", "/tmp-other/tool") {
		t.Fatal("path boundary handling is incorrect")
	}
	mode := os.FileMode(0o755) | os.ModeSticky
	if got := normalizedMode(mode); got != "01755" {
		t.Fatalf("sticky mode = %q, want 01755", got)
	}
}

func containsSignal(signals []TriageSignal, id string, assessment TriageAssessment) bool {
	for _, signal := range signals {
		if signal.ID == id && signal.Assessment == assessment {
			return true
		}
	}
	return false
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	writeFile(t, path, content, 0o700)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
