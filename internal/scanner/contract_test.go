package scanner

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCoverageLimitsCoalesceAndSortDeterministically(t *testing.T) {
	coverage := newCoverageAccumulator("test-scanner")
	coverage.add(CoverageMaxFiles, "/z", 2, 3)
	coverage.add(CoverageMaxFileBytes, "/b", 10, 11)
	coverage.add(CoverageMaxFiles, "/a", 2, 7)

	got := coverage.findings()
	want := []CoverageLimitFinding{
		{
			Kind:        CoverageFindingLimit,
			ScannerID:   "test-scanner",
			Code:        CoverageMaxFileBytes,
			Path:        "/b",
			Limit:       10,
			Observed:    11,
			Occurrences: 1,
		},
		{
			Kind:        CoverageFindingLimit,
			ScannerID:   "test-scanner",
			Code:        CoverageMaxFiles,
			Path:        "/a",
			Limit:       2,
			Observed:    7,
			Occurrences: 2,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("coverage findings\n got: %#v\nwant: %#v", got, want)
	}
	first, _ := json.Marshal(got)
	second, _ := json.Marshal(coverage.findings())
	if string(first) != string(second) {
		t.Fatalf("coverage JSON is nondeterministic\n%s\n%s", first, second)
	}
}

func TestScannerOptionsRejectInvalidBounds(t *testing.T) {
	validSecret := SecretLimits{
		MaxFileBytes: 1, MaxTotalBytes: 1, MaxDepth: 0, MaxFiles: 1, MaxFindings: 1,
	}
	secretCases := []struct {
		name   string
		limits SecretLimits
		key    []byte
	}{
		{name: "file bytes", limits: SecretLimits{MaxTotalBytes: 1, MaxFiles: 1, MaxFindings: 1}, key: make([]byte, 32)},
		{name: "total bytes", limits: SecretLimits{MaxFileBytes: 1, MaxFiles: 1, MaxFindings: 1}, key: make([]byte, 32)},
		{name: "depth", limits: SecretLimits{MaxFileBytes: 1, MaxTotalBytes: 1, MaxDepth: -1, MaxFiles: 1, MaxFindings: 1}, key: make([]byte, 32)},
		{name: "files", limits: SecretLimits{MaxFileBytes: 1, MaxTotalBytes: 1, MaxFindings: 1}, key: make([]byte, 32)},
		{name: "findings", limits: SecretLimits{MaxFileBytes: 1, MaxTotalBytes: 1, MaxFiles: 1}, key: make([]byte, 32)},
		{name: "key", limits: validSecret, key: []byte("too-short")},
	}
	for _, testCase := range secretCases {
		t.Run("secret "+testCase.name, func(t *testing.T) {
			if _, err := NewSecretScanner(SecretOptions{
				Limits: testCase.limits, FingerprintKey: testCase.key,
			}); err == nil {
				t.Fatal("invalid secret scanner options accepted")
			}
		})
	}

	executableCases := []ExecutableLimits{
		{MaxTotalBytes: 1, MaxFiles: 1},
		{MaxFileBytes: 1, MaxFiles: 1},
		{MaxFileBytes: 1, MaxTotalBytes: 1},
	}
	for index, limits := range executableCases {
		t.Run("executable", func(t *testing.T) {
			if _, err := NewExecutableScanner(ExecutableOptions{Limits: limits}); err == nil {
				t.Fatalf("invalid executable limits %d accepted", index)
			}
		})
	}
}
