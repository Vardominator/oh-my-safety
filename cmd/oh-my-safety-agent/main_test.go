package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/bridge"
	"github.com/Vardominator/oh-my-safety/internal/model"
	"github.com/Vardominator/oh-my-safety/internal/profile"
)

func TestRunInitializesFoundationAndEmitsStableReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "journal.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run(
		[]string{"-state-db", path, "-profile", profile.PresetDeveloper},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}

	var result readiness
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode readiness: %v\n%s", err, stdout.String())
	}
	if result.Schema != readinessSchema ||
		result.SchemaVersion != readinessSchemaVersion ||
		!result.Ready ||
		result.StateDB != path ||
		result.Profile.Preset != profile.PresetDeveloper {
		t.Fatalf("unexpected readiness: %#v", result)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestRunRejectsUnknownProfileWithoutCreatingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	var stdout bytes.Buffer
	err := run(
		[]string{"-state-db", path, "-profile", "unknown"},
		&stdout,
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("database created before profile validation: %v", statErr)
	}
}

func TestDefaultStateDBHonorsXDGStateHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	path, err := defaultStateDB()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "oh-my-safety", "journal.db")
	if path != want {
		t.Fatalf("state path = %q, want %q", path, want)
	}
}

func TestDefaultReadinessExactJSONContractUsesPublishedPersonalPreset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	var stdout bytes.Buffer
	if err := run(
		[]string{"--state-db", path},
		&stdout,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(
		`{"schema":"io.oh-my-safety/agent-readiness","schema_version":1,"ready":true,"state_db":"%s","profile":{"schema":"io.oh-my-safety/profile","schema_version":1,"preset":"personal-balanced","axes":{"workload":"workstation","protection":"balanced","management":"standalone","connectivity":"connected"}}}`+"\n",
		path,
	)
	if stdout.String() != want {
		t.Fatalf("readiness contract changed\nwant: %s\n got: %s", want, stdout.String())
	}
}

func TestRunIngestsStdinAndQueriesHistoryAndFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "journal.db")
	var ingestOutput bytes.Buffer
	err := runWithInput(
		[]string{"--state-db", path, "--ingest-scan", "-"},
		strings.NewReader(commandWarningScan()),
		&ingestOutput,
		&bytes.Buffer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	var ingested bridge.IngestEnvelope
	if err := json.Unmarshal(ingestOutput.Bytes(), &ingested); err != nil {
		t.Fatal(err)
	}
	if ingested.Schema != bridge.IngestSchema ||
		ingested.SchemaVersion != bridge.IngestSchemaVersion ||
		ingested.Results != 1 ||
		ingested.AlreadyIngested {
		t.Fatalf("unexpected ingest output: %#v", ingested)
	}

	var historyOutput bytes.Buffer
	if err := run(
		[]string{"--state-db", path, "--history", "--limit", "2"},
		&historyOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	var history bridge.HistoryEnvelope
	if err := json.Unmarshal(historyOutput.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if history.Schema != bridge.HistorySchema ||
		history.Limit != 2 ||
		history.Count != 2 ||
		len(history.Events) != 2 {
		t.Fatalf("unexpected history output: %#v", history)
	}

	var findingsOutput bytes.Buffer
	if err := run(
		[]string{"--state-db", path, "--findings", "--limit", "1"},
		&findingsOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	var findings bridge.FindingsEnvelope
	if err := json.Unmarshal(findingsOutput.Bytes(), &findings); err != nil {
		t.Fatal(err)
	}
	if findings.Schema != bridge.FindingsSchema ||
		findings.Count != 1 ||
		len(findings.Findings) != 1 ||
		findings.Findings[0].State != model.FindingOpen {
		t.Fatalf("unexpected findings output: %#v", findings)
	}

	var secondOutput bytes.Buffer
	if err := runWithInput(
		[]string{"--state-db", path, "--ingest-scan=-"},
		strings.NewReader(commandWarningScan()),
		&secondOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	var second bridge.IngestEnvelope
	if err := json.Unmarshal(secondOutput.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if !second.AlreadyIngested {
		t.Fatalf("stdin re-ingest was not idempotent: %#v", second)
	}
}

func TestRunIngestsRegularFileWithoutChangingInputPermissions(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "last-scan.tsv")
	if err := os.WriteFile(input, []byte(commandWarningScan()), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(root, "state")
	stateDB := filepath.Join(stateDir, "journal.db")
	var stdout bytes.Buffer
	if err := run(
		[]string{"--state-db", stateDB, "--ingest-scan", input},
		&stdout,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf(
			"input permissions changed from %o to %o",
			before.Mode().Perm(),
			after.Mode().Perm(),
		)
	}
	dbInfo, err := os.Stat(stateDB)
	if err != nil {
		t.Fatal(err)
	}
	if dbInfo.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %o, want 600", dbInfo.Mode().Perm())
	}
	dirInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory permissions = %o, want 700", dirInfo.Mode().Perm())
	}
}

func TestRunRejectsConflictingModesAndMisplacedLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	cases := [][]string{
		{"--state-db", path, "--history", "--findings"},
		{"--state-db", path, "--ingest-scan", "-", "--history"},
		{"--state-db", path, "--ingest-scan=", "--findings"},
		{"--state-db", path, "--limit", "1"},
		{"--state-db", path, "--ingest-scan", "-", "--limit", "1"},
		{"--state-db", path, "--history", "--limit", "0"},
		{"--state-db", path, "--findings", "--limit", "1001"},
		{"--state-db", path, "--ingest-scan="},
	}
	for _, arguments := range cases {
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			err := runWithInput(
				arguments,
				strings.NewReader(commandWarningScan()),
				&bytes.Buffer{},
				&bytes.Buffer{},
			)
			if err == nil {
				t.Fatalf("conflicting/invalid arguments accepted: %v", arguments)
			}
		})
	}
}

func TestMalformedInputDoesNotCreateJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "journal.db")
	err := runWithInput(
		[]string{"--state-db", path, "--ingest-scan", "-"},
		strings.NewReader("schema\t99\n"),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("malformed scan accepted")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("journal created for malformed input: %v", statErr)
	}
}

func TestReadScanSnapshotRejectsTraversalAndNonRegularInputs(t *testing.T) {
	if _, err := readScanSnapshot("../outside.tsv", strings.NewReader("")); err == nil {
		t.Fatal("relative traversal accepted")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target.tsv")
	link := filepath.Join(root, "link.tsv")
	if err := os.WriteFile(target, []byte(commandWarningScan()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readScanSnapshot(link, strings.NewReader("")); err == nil {
		t.Fatal("symlink scan input accepted")
	}
}

func commandWarningScan() string {
	return strings.Join([]string{
		"schema\t1",
		"meta\ttimestamp\t2026-07-29T12:00:00Z",
		"meta\tupdated_at\t2026-07-29T12:00:00Z",
		"meta\tversion\t0.2.3",
		"meta\tplatform\tlinux",
		"meta\tsource\tagent",
		"meta\tscope\tpartial",
		"meta\texit\t1",
		"meta\tfda\tfalse",
		"result\tsecurity\tprocess-audit\twarn\twarn\tSuspicious process observed\tReview the process.\tdocs/checks/security/process-audit.md",
		"detail\tsecurity\tprocess-audit\t[id: human-only] do not parse",
	}, "\n")
}
