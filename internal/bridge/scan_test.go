package bridge

import (
	"strings"
	"testing"
	"time"
)

func TestParseSchemaV1ScanAndIgnoreHumanDetails(t *testing.T) {
	snapshot, err := ParseScan(strings.NewReader(warnScanTSV()))
	if err != nil {
		t.Fatal(err)
	}
	wantTimestamp := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	wantUpdatedAt := wantTimestamp.Add(time.Second)
	if snapshot.SchemaVersion != 1 ||
		!snapshot.Metadata.Timestamp.Equal(wantTimestamp) ||
		!snapshot.Metadata.UpdatedAt.Equal(wantUpdatedAt) ||
		snapshot.Metadata.Scope != ScanScopeFull ||
		snapshot.Metadata.Exit != 1 ||
		!snapshot.Metadata.FDA ||
		snapshot.Metadata.PublicIP != "203.0.113.10" {
		t.Fatalf("unexpected metadata: %#v", snapshot.Metadata)
	}
	if len(snapshot.Results) != 2 {
		t.Fatalf("result count = %d, want 2", len(snapshot.Results))
	}
	result := snapshot.Results[0]
	if result.Category != "security" ||
		result.Name != "secrets-content" ||
		result.Status != CheckStatusWarn ||
		result.Summary != "Credential-like content found" ||
		result.Remediation != "Rotate then remove the credential." ||
		result.Guide != "docs/checks/security/secrets-content.md" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDetailsDoNotAffectSnapshotDigest(t *testing.T) {
	first, err := ParseScan(strings.NewReader(warnScanTSV()))
	if err != nil {
		t.Fatal(err)
	}
	changedDetails := strings.Replace(
		warnScanTSV(),
		"detail\tsecurity\tsecrets-content\t[id: ../../never-parse-this] masked detail",
		"detail\tthis row is intentionally not a structured finding",
		1,
	)
	second, err := ParseScan(strings.NewReader(changedDetails))
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := SnapshotDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := SnapshotDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("human detail changed snapshot identity: %s != %s", firstDigest, secondDigest)
	}

	reordered := first
	reordered.Results = append([]CheckResult(nil), first.Results...)
	reordered.Results[0], reordered.Results[1] = reordered.Results[1], reordered.Results[0]
	reorderedDigest, err := SnapshotDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != reorderedDigest {
		t.Fatalf("result row order changed snapshot identity: %s != %s", firstDigest, reorderedDigest)
	}
}

func TestLegacySchemaV1DefaultsScopeAndUpdatedAt(t *testing.T) {
	legacy := strings.Join([]string{
		"schema\t1",
		"meta\ttimestamp\t2026-07-29T12:00:00Z",
		"meta\tversion\t0.2.3",
		"meta\tplatform\tmacos",
		"meta\tsource\tscan",
		"meta\texit\t0",
		"meta\tfda\tfalse",
		"result\tprivacy\trouting\tok\tinfo\tVPN route is healthy\t\t",
	}, "\n")
	snapshot, err := ParseScan(strings.NewReader(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Metadata.Scope != ScanScopeFull {
		t.Fatalf("legacy scope = %q, want full", snapshot.Metadata.Scope)
	}
	if !snapshot.Metadata.UpdatedAt.Equal(snapshot.Metadata.Timestamp) {
		t.Fatalf(
			"legacy updated_at = %v, want timestamp %v",
			snapshot.Metadata.UpdatedAt,
			snapshot.Metadata.Timestamp,
		)
	}
}

func TestParseRejectsMalformedSchemaV1Scans(t *testing.T) {
	valid := warnScanTSV()
	cases := map[string]string{
		"schema": strings.Replace(valid, "schema\t1", "schema\t2", 1),
		"missing metadata": strings.Replace(
			valid,
			"meta\tfda\ttrue\n",
			"",
			1,
		),
		"unknown metadata": strings.Replace(
			valid,
			"meta\tfda\ttrue",
			"meta\tfda\ttrue\nmeta\tunexpected\tvalue",
			1,
		),
		"duplicate metadata": strings.Replace(
			valid,
			"meta\tfda\ttrue",
			"meta\tfda\ttrue\nmeta\tfda\ttrue",
			1,
		),
		"bad timestamp": strings.Replace(
			valid,
			"2026-07-29T12:00:00Z",
			"not-a-time",
			1,
		),
		"updated before timestamp": strings.Replace(
			valid,
			"2026-07-29T12:00:01Z",
			"2026-07-29T11:59:59Z",
			1,
		),
		"bad scope": strings.Replace(valid, "meta\tscope\tfull", "meta\tscope\tunknown", 1),
		"bad status": strings.Replace(
			valid,
			"\twarn\twarn\tCredential",
			"\talarmed\twarn\tCredential",
			1,
		),
		"bad severity pairing": strings.Replace(
			valid,
			"\twarn\twarn\tCredential",
			"\twarn\tcritical\tCredential",
			1,
		),
		"path-like category": strings.Replace(
			valid,
			"result\tsecurity\tsecrets-content",
			"result\t../security\tsecrets-content",
			1,
		),
		"traversing guide": strings.Replace(
			valid,
			"docs/checks/security/secrets-content.md",
			"../../private.txt",
			1,
		),
		"duplicate result": valid + "\n" +
			"result\tsecurity\tsecrets-content\twarn\twarn\tDuplicate\t\t",
		"exit mismatch":         strings.Replace(valid, "meta\texit\t1", "meta\texit\t0", 1),
		"unknown row":           valid + "\nunknown\tvalue",
		"metadata after result": valid + "\nmeta\tpublic_ip\t203.0.113.11",
		"no results": strings.Join([]string{
			"schema\t1",
			"meta\ttimestamp\t2026-07-29T12:00:00Z",
			"meta\tversion\t0.2.3",
			"meta\tplatform\tmacos",
			"meta\tsource\tscan",
			"meta\texit\t0",
			"meta\tfda\tfalse",
		}, "\n"),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScan(strings.NewReader(input)); err == nil {
				t.Fatal("malformed scan accepted")
			}
		})
	}
}

func TestParseEnforcesInputAndLineBounds(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		input := strings.Repeat("x", MaxScanInputBytes+1)
		if _, err := ParseScan(strings.NewReader(input)); err == nil ||
			!strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized input error = %v", err)
		}
	})

	t.Run("line", func(t *testing.T) {
		input := warnScanTSV() + "\ndetail\t" + strings.Repeat("x", MaxScanLineBytes)
		if _, err := ParseScan(strings.NewReader(input)); err == nil ||
			!strings.Contains(err.Error(), "line exceeds") {
			t.Fatalf("oversized line error = %v", err)
		}
	})
}

func TestParseErrorsDoNotEchoSensitiveInput(t *testing.T) {
	secret := "secret-value-that-must-not-appear"
	input := warnScanTSV() + "\nunknown\t" + secret
	_, err := ParseScan(strings.NewReader(input))
	if err == nil {
		t.Fatal("invalid scan accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error exposes input: %v", err)
	}
}

func warnScanTSV() string {
	return strings.Join([]string{
		"schema\t1",
		"meta\ttimestamp\t2026-07-29T12:00:00Z",
		"meta\tupdated_at\t2026-07-29T12:00:01Z",
		"meta\tversion\t0.2.3",
		"meta\tplatform\tmacos",
		"meta\tsource\tagent",
		"meta\tscope\tfull",
		"meta\texit\t1",
		"meta\tfda\ttrue",
		"meta\tpublic_ip\t203.0.113.10",
		"result\tsecurity\tsecrets-content\twarn\twarn\tCredential-like content found\tRotate then remove the credential.\tdocs/checks/security/secrets-content.md",
		"result\tprivacy\trouting\tok\tinfo\tVPN route is healthy\t\t",
		"detail\tsecurity\tsecrets-content\t[id: ../../never-parse-this] masked detail",
	}, "\n")
}
