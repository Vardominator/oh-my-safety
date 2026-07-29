// Package scanner provides bounded, local-only scanners for credential-like
// content and changed executable triage. It intentionally performs no network
// access, remediation, quarantine, or external command execution.
package scanner

import (
	"sort"
)

const (
	SecretResultSchema            = "io.oh-my-safety/secret-scan"
	SecretResultSchemaVersion     = 1
	ExecutableResultSchema        = "io.oh-my-safety/executable-triage"
	ExecutableResultSchemaVersion = 1

	SecretScannerID     = "local-secret-scanner"
	ExecutableScannerID = "changed-executable-triage"
)

// CoverageLimitCode identifies why a bounded scanner deliberately left part of
// its requested scope uninspected.
type CoverageLimitCode string
type CoverageFindingKind string

const (
	CoverageFindingLimit CoverageFindingKind = "coverage_limit"

	CoverageMaxFileBytes  CoverageLimitCode = "max_file_bytes"
	CoverageMaxTotalBytes CoverageLimitCode = "max_total_bytes"
	CoverageMaxDepth      CoverageLimitCode = "max_depth"
	CoverageMaxFiles      CoverageLimitCode = "max_files"
	CoverageMaxFindings   CoverageLimitCode = "max_findings"
)

// CoverageLimitFinding is a typed, non-verdict finding. Occurrences may
// summarize multiple paths that reached the same limit; Path is the
// lexicographically first affected path.
type CoverageLimitFinding struct {
	Kind        CoverageFindingKind `json:"kind"`
	ScannerID   string              `json:"scanner_id"`
	Code        CoverageLimitCode   `json:"code"`
	Path        string              `json:"path,omitempty"`
	Limit       int64               `json:"limit"`
	Observed    int64               `json:"observed"`
	Occurrences int64               `json:"occurrences"`
}

type coverageAccumulator struct {
	scannerID string
	byCode    map[CoverageLimitCode]CoverageLimitFinding
}

func newCoverageAccumulator(scannerID string) *coverageAccumulator {
	return &coverageAccumulator{
		scannerID: scannerID,
		byCode:    make(map[CoverageLimitCode]CoverageLimitFinding),
	}
}

func (a *coverageAccumulator) add(code CoverageLimitCode, path string, limit, observed int64) {
	finding, ok := a.byCode[code]
	if !ok {
		a.byCode[code] = CoverageLimitFinding{
			Kind:        CoverageFindingLimit,
			ScannerID:   a.scannerID,
			Code:        code,
			Path:        path,
			Limit:       limit,
			Observed:    observed,
			Occurrences: 1,
		}
		return
	}
	finding.Occurrences++
	if path != "" && (finding.Path == "" || path < finding.Path) {
		finding.Path = path
	}
	if observed > finding.Observed {
		finding.Observed = observed
	}
	a.byCode[code] = finding
}

func (a *coverageAccumulator) findings() []CoverageLimitFinding {
	findings := make([]CoverageLimitFinding, 0, len(a.byCode))
	for _, finding := range a.byCode {
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}
