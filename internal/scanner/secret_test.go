package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	testPassword    = "CorrectHorseBatteryStaple!42-z9Q"
	testGitHubToken = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	testPrivateBody = "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtdGhhdC1tdXN0LW5vdC1sZWFr"
)

func TestSecretScannerRedactsValuesAndIsDeterministic(t *testing.T) {
	root := t.TempDir()
	firstRoot := filepath.Join(root, "a")
	secondRoot := filepath.Join(root, "b")
	mustMkdirAll(t, firstRoot)
	mustMkdirAll(t, secondRoot)

	firstPath := filepath.Join(firstRoot, "credentials.env")
	writeFile(t, firstPath, strings.Join([]string{
		`secret = "` + testPassword + `"`,
		`github_token = ` + testGitHubToken,
		"",
	}, "\n"), 0o600)
	secondPath := filepath.Join(secondRoot, "identity.pem")
	writeFile(t, secondPath, strings.Join([]string{
		"-----BEGIN PRIVATE KEY-----",
		testPrivateBody,
		"-----END PRIVATE KEY-----",
		"",
	}, "\n"), 0o600)

	key := []byte("0123456789abcdef0123456789abcdef")
	scanner, err := NewSecretScanner(SecretOptions{FingerprintKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// The scanner must own a copy of its fingerprint key.
	key[0] = 'x'

	forward, err := scanner.Scan(context.Background(), firstRoot, secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := scanner.Scan(context.Background(), secondRoot, firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("root order changed deterministic result\nforward: %#v\nreverse: %#v", forward, reversed)
	}
	if forward.Schema != SecretResultSchema ||
		forward.SchemaVersion != SecretResultSchemaVersion ||
		forward.ScannerID != SecretScannerID {
		t.Fatalf("unexpected result contract: %#v", forward)
	}
	if len(forward.Findings) != 3 {
		t.Fatalf("findings = %d, want 3: %#v", len(forward.Findings), forward.Findings)
	}

	detectors := make(map[string]SecretFinding)
	for _, finding := range forward.Findings {
		detectors[finding.DetectorID] = finding
		if finding.Path == "" || finding.Line <= 0 ||
			!strings.HasPrefix(finding.Fingerprint, "hmac-sha256:") ||
			!strings.Contains(finding.RedactedExcerpt, "REDACTED") {
			t.Fatalf("unsafe or incomplete finding: %#v", finding)
		}
	}
	for _, detectorID := range []string{"private-key.pem", "secret.assignment", "token.github"} {
		if _, ok := detectors[detectorID]; !ok {
			t.Fatalf("missing detector %q in %#v", detectorID, forward.Findings)
		}
	}

	assertNoSensitiveText(t, forward, nil, testPassword, testGitHubToken, testPrivateBody)

	encodedForward, err := json.Marshal(forward)
	if err != nil {
		t.Fatal(err)
	}
	encodedReversed, err := json.Marshal(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedForward) != string(encodedReversed) {
		t.Fatalf("JSON contract is nondeterministic\n%s\n%s", encodedForward, encodedReversed)
	}
}

func TestSecretFingerprintStableForSameValueAndKey(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.env")
	second := filepath.Join(root, "second.env")
	line := `password = "` + testPassword + `"` + "\n"
	writeFile(t, first, line, 0o600)
	writeFile(t, second, line, 0o600)

	scanner := newTestSecretScanner(t, DefaultSecretLimits())
	result, err := scanner.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %#v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Fingerprint != result.Findings[1].Fingerprint {
		t.Fatalf("same value produced different fingerprints: %#v", result.Findings)
	}

	differentScanner, err := NewSecretScanner(SecretOptions{
		FingerprintKey: []byte("abcdef0123456789abcdef0123456789"),
	})
	if err != nil {
		t.Fatal(err)
	}
	different, err := differentScanner.Scan(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if different.Findings[0].Fingerprint == result.Findings[0].Fingerprint {
		t.Fatal("different fingerprint keys produced the same fingerprint")
	}
}

func TestSecretScannerSkipsSymlinksBinaryAndOversizeFiles(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	mustMkdirAll(t, root)
	outside := filepath.Join(parent, "outside.env")
	writeFile(t, outside, `secret="`+testPassword+`"`+"\n", 0o600)
	if err := os.Symlink(outside, filepath.Join(root, "linked.env")); err != nil {
		t.Fatal(err)
	}
	writeBytes(t, filepath.Join(root, "binary.dat"), append([]byte{0, 1, 2}, []byte(testGitHubToken)...), 0o600)
	writeFile(t, filepath.Join(root, "oversize.env"), strings.Repeat("x", 80)+testGitHubToken, 0o600)

	limits := SecretLimits{
		MaxFileBytes:  64,
		MaxTotalBytes: 1_024,
		MaxDepth:      4,
		MaxFiles:      10,
		MaxFindings:   10,
	}
	result, err := newTestSecretScanner(t, limits).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("skipped content produced findings: %#v", result.Findings)
	}
	if result.Stats.SymlinksSkipped != 1 ||
		result.Stats.BinarySkipped != 1 ||
		result.Stats.OversizeSkipped != 1 {
		t.Fatalf("unexpected skip stats: %#v", result.Stats)
	}
	assertCoverage(t, result.Coverage, CoverageMaxFileBytes)
}

func TestSecretScannerSkipsDeviceFiles(t *testing.T) {
	if _, err := os.Lstat("/dev/null"); err != nil {
		t.Skipf("no portable device fixture: %v", err)
	}
	result, err := newTestSecretScanner(t, DefaultSecretLimits()).Scan(context.Background(), "/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || result.Stats.NonRegularSkipped != 1 {
		t.Fatalf("device was not skipped safely: %#v", result)
	}
}

func TestSecretScannerHighConfidenceTokenFormats(t *testing.T) {
	root := t.TempDir()
	tokens := []string{
		"AKIAZ3N7Q2W4E6R8T0YU",
		"gl" + "pat-" + "A1b2C3d4E5f6G7h8I9j0",
		"AIza" + strings.Repeat("A1b2C3d", 5),
		"xoxb-1234567890-A1b2C3d4E5f6",
		"sk_live_A1b2C3d4E5f6G7h8I9j0",
	}
	writeFile(t, filepath.Join(root, "tokens.txt"), strings.Join(tokens, "\n"), 0o600)
	result, err := newTestSecretScanner(t, DefaultSecretLimits()).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, finding := range result.Findings {
		got[finding.DetectorID] = true
	}
	for _, detectorID := range []string{
		"token.aws-access-key-id",
		"token.gitlab",
		"token.google-api-key",
		"token.slack",
		"token.stripe-live-secret",
	} {
		if !got[detectorID] {
			t.Fatalf("detector %q did not match high-confidence fixture: %#v", detectorID, result.Findings)
		}
	}
	assertNoSensitiveText(t, result, nil, tokens...)
}

func TestSecretScannerReportsEveryConfiguredCoverageBound(t *testing.T) {
	t.Run("max depth", func(t *testing.T) {
		root := t.TempDir()
		deep := filepath.Join(root, "one", "two")
		mustMkdirAll(t, deep)
		writeFile(t, filepath.Join(deep, "secret.env"), `secret="`+testPassword+`"`, 0o600)
		limits := SecretLimits{MaxFileBytes: 1_024, MaxTotalBytes: 4_096, MaxDepth: 1, MaxFiles: 10, MaxFindings: 10}
		result, err := newTestSecretScanner(t, limits).Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		assertCoverage(t, result.Coverage, CoverageMaxDepth)
		if len(result.Findings) != 0 {
			t.Fatalf("depth-limited file was scanned: %#v", result.Findings)
		}
	})

	t.Run("max files", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "a.txt"), "clean\n", 0o600)
		writeFile(t, filepath.Join(root, "b.txt"), "clean\n", 0o600)
		limits := SecretLimits{MaxFileBytes: 1_024, MaxTotalBytes: 4_096, MaxDepth: 2, MaxFiles: 1, MaxFindings: 10}
		result, err := newTestSecretScanner(t, limits).Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		assertCoverage(t, result.Coverage, CoverageMaxFiles)
	})

	t.Run("max total bytes", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "a.txt"), strings.Repeat("a", 20), 0o600)
		writeFile(t, filepath.Join(root, "b.txt"), strings.Repeat("b", 20), 0o600)
		limits := SecretLimits{MaxFileBytes: 64, MaxTotalBytes: 30, MaxDepth: 2, MaxFiles: 10, MaxFindings: 10}
		result, err := newTestSecretScanner(t, limits).Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		assertCoverage(t, result.Coverage, CoverageMaxTotalBytes)
	})

	t.Run("max findings", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "secrets.env"), strings.Join([]string{
			`password="` + testPassword + `"`,
			`secret="A9z!` + testPassword + `"`,
		}, "\n"), 0o600)
		limits := SecretLimits{MaxFileBytes: 1_024, MaxTotalBytes: 4_096, MaxDepth: 2, MaxFiles: 10, MaxFindings: 1}
		result, err := newTestSecretScanner(t, limits).Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %d, want bounded result of 1", len(result.Findings))
		}
		coverage := assertCoverage(t, result.Coverage, CoverageMaxFindings)
		if coverage.Kind != "coverage_limit" || coverage.Limit != 1 || coverage.Observed != 2 {
			t.Fatalf("unexpected typed coverage finding: %#v", coverage)
		}
	})
}

func TestSecretScannerHonorsCancellationWithoutLeakingContent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "secret.env"), `secret="`+testPassword+`"`, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := newTestSecretScanner(t, DefaultSecretLimits()).Scan(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	assertNoSensitiveText(t, result, err, testPassword)
}

func TestSecretScannerFalsePositiveGuards(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "examples.env"), strings.Join([]string{
		`password = "changeme"`,
		`secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`api_key = "${API_KEY_FROM_ENVIRONMENT}"`,
		`access_token = "<your-access-token-here>"`,
		`# secret = "` + testPassword + `"`,
		`// password = "` + testPassword + `"`,
		`aws_example = AKIAIOSFODNN7EXAMPLE`,
		`stripe_example = sk_test_1234567890abcdefghijklmnop`,
		`ordinary text with -----BEGIN PUBLIC KEY----- in it`,
	}, "\n"), 0o600)

	result, err := newTestSecretScanner(t, DefaultSecretLimits()).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("placeholder/example content produced findings: %#v", result.Findings)
	}
}

func TestAssignmentParsingSupportsConfigurationFormsWithoutLeakingValues(t *testing.T) {
	root := t.TempDir()
	values := []string{
		"DbPassword-CorrectHorse-92!Z",
		"JsonSecret-A1b2C3d4E5f6G7h8",
		"ExportToken-Z9y8X7w6V5u4T3s2",
		"GoSecret-K9j8H7g6F5d4S3a2",
	}
	writeFile(t, filepath.Join(root, "config.txt"), strings.Join([]string{
		`DB_PASSWORD=` + values[0],
		`"secret": "` + values[1] + `"`,
		`export ACCESS_TOKEN='` + values[2] + `'`,
		`var apiKey := "` + values[3] + `"`,
	}, "\n"), 0o600)
	result, err := newTestSecretScanner(t, DefaultSecretLimits()).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != len(values) {
		t.Fatalf("assignment findings = %d, want %d: %#v", len(result.Findings), len(values), result.Findings)
	}
	assertNoSensitiveText(t, result, nil, values...)
}

func newTestSecretScanner(t *testing.T, limits SecretLimits) *SecretScanner {
	t.Helper()
	scanner, err := NewSecretScanner(SecretOptions{
		Limits:         limits,
		FingerprintKey: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func assertNoSensitiveText(t *testing.T, result any, err error, secrets ...string) {
	t.Helper()
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	representations := []string{string(encoded), fmt.Sprintf("%#v", result)}
	if err != nil {
		representations = append(representations, err.Error())
	}
	for _, secret := range secrets {
		for _, representation := range representations {
			if strings.Contains(representation, secret) {
				t.Fatalf("sensitive value leaked in output: %q", representation)
			}
		}
	}
}

func assertCoverage(
	t *testing.T,
	findings []CoverageLimitFinding,
	code CoverageLimitCode,
) CoverageLimitFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			if finding.Kind != "coverage_limit" || finding.ScannerID == "" || finding.Occurrences <= 0 {
				t.Fatalf("invalid coverage finding: %#v", finding)
			}
			return finding
		}
	}
	t.Fatalf("missing coverage code %q in %#v", code, findings)
	return CoverageLimitFinding{}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	writeBytes(t, path, []byte(content), mode)
}

func writeBytes(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}
