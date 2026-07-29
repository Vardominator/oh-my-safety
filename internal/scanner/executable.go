package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ExecutableLimits struct {
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
	MaxFiles      int   `json:"max_files"`
}

func DefaultExecutableLimits() ExecutableLimits {
	return ExecutableLimits{
		MaxFileBytes:  256 << 20,
		MaxTotalBytes: 1 << 30,
		MaxFiles:      2_000,
	}
}

// ExecutableCandidate is supplied by a local file-change collector. New is an
// observed state transition, not a conclusion about the file.
type ExecutableCandidate struct {
	Path string `json:"path"`
	New  bool   `json:"new"`
}

type PackageOwnershipStatus string

const (
	PackageOwnershipUnknown PackageOwnershipStatus = "unknown"
	PackageOwnershipOwned   PackageOwnershipStatus = "owned"
	PackageOwnershipUnowned PackageOwnershipStatus = "unowned"
)

type PackageOwnership struct {
	Status  PackageOwnershipStatus `json:"status"`
	Package string                 `json:"package,omitempty"`
}

// PackageOwnershipLookup is deliberately injected by the caller. The scanner
// never executes a package-manager command itself.
type PackageOwnershipLookup func(context.Context, string) (PackageOwnership, error)

type TriageAssessment string

const (
	AssessmentSuspicious TriageAssessment = "suspicious"
	AssessmentUnknown    TriageAssessment = "unknown"
)

// TriageSignal is an explainable observation, never a malware verdict.
type TriageSignal struct {
	ID         string           `json:"id"`
	Assessment TriageAssessment `json:"assessment"`
}

type FileOwnership struct {
	Known bool   `json:"known"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
}

type ExecutableRecord struct {
	Path             string           `json:"path"`
	SHA256           string           `json:"sha256"`
	Mode             string           `json:"mode"`
	Size             int64            `json:"size"`
	Ownership        FileOwnership    `json:"ownership"`
	PackageOwnership PackageOwnership `json:"package_ownership"`
	Signals          []TriageSignal   `json:"signals"`
}

type ExecutableStats struct {
	FilesConsidered      int64 `json:"files_considered"`
	FilesTriaged         int64 `json:"files_triaged"`
	BytesHashed          int64 `json:"bytes_hashed"`
	MissingSkipped       int64 `json:"missing_skipped"`
	SymlinksSkipped      int64 `json:"symlinks_skipped"`
	NonRegularSkipped    int64 `json:"non_regular_skipped"`
	NonExecutableSkipped int64 `json:"non_executable_skipped"`
	OversizeSkipped      int64 `json:"oversize_skipped"`
}

type ExecutableResult struct {
	Schema        string                 `json:"schema"`
	SchemaVersion int                    `json:"schema_version"`
	ScannerID     string                 `json:"scanner_id"`
	Executables   []ExecutableRecord     `json:"executables"`
	Coverage      []CoverageLimitFinding `json:"coverage"`
	Stats         ExecutableStats        `json:"stats"`
}

type ExecutableOptions struct {
	Limits           ExecutableLimits
	PackageOwnership PackageOwnershipLookup
}

type ExecutableScanner struct {
	limits           ExecutableLimits
	packageOwnership PackageOwnershipLookup
}

func NewExecutableScanner(options ExecutableOptions) (*ExecutableScanner, error) {
	limits := options.Limits
	if limits == (ExecutableLimits{}) {
		limits = DefaultExecutableLimits()
	}
	switch {
	case limits.MaxFileBytes <= 0:
		return nil, errors.New("max file bytes must be positive")
	case limits.MaxTotalBytes <= 0:
		return nil, errors.New("max total bytes must be positive")
	case limits.MaxFiles <= 0:
		return nil, errors.New("max files must be positive")
	}
	return &ExecutableScanner{
		limits:           limits,
		packageOwnership: options.PackageOwnership,
	}, nil
}

func (s *ExecutableScanner) Triage(
	ctx context.Context,
	candidates []ExecutableCandidate,
) (ExecutableResult, error) {
	result := ExecutableResult{
		Schema:        ExecutableResultSchema,
		SchemaVersion: ExecutableResultSchemaVersion,
		ScannerID:     ExecutableScannerID,
		Executables:   make([]ExecutableRecord, 0),
		Coverage:      make([]CoverageLimitFinding, 0),
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	normalized := normalizeCandidates(candidates)
	coverage := newCoverageAccumulator(ExecutableScannerID)
	for _, candidate := range normalized {
		if err := ctx.Err(); err != nil {
			result.Coverage = coverage.findings()
			return result, err
		}
		if result.Stats.FilesConsidered >= int64(s.limits.MaxFiles) {
			coverage.add(
				CoverageMaxFiles,
				candidate.Path,
				int64(s.limits.MaxFiles),
				result.Stats.FilesConsidered+1,
			)
			break
		}
		result.Stats.FilesConsidered++

		info, err := os.Lstat(candidate.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			result.Stats.MissingSkipped++
			continue
		case err != nil:
			result.Coverage = coverage.findings()
			return result, fmt.Errorf("inspect %q: %w", candidate.Path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			result.Stats.SymlinksSkipped++
			continue
		}
		if !info.Mode().IsRegular() {
			result.Stats.NonRegularSkipped++
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			result.Stats.NonExecutableSkipped++
			continue
		}
		if info.Size() > s.limits.MaxFileBytes {
			result.Stats.OversizeSkipped++
			coverage.add(CoverageMaxFileBytes, candidate.Path, s.limits.MaxFileBytes, info.Size())
			continue
		}
		remaining := s.limits.MaxTotalBytes - result.Stats.BytesHashed
		if remaining <= 0 || info.Size() > remaining {
			coverage.add(
				CoverageMaxTotalBytes,
				candidate.Path,
				s.limits.MaxTotalBytes,
				result.Stats.BytesHashed+info.Size(),
			)
			break
		}

		digest, bytesHashed, exceeded, openedInfo, err := hashExecutableBounded(
			ctx,
			candidate.Path,
			info,
			minInt64(s.limits.MaxFileBytes, remaining),
		)
		result.Stats.BytesHashed += bytesHashed
		if err != nil {
			result.Coverage = coverage.findings()
			return result, err
		}
		if openedInfo == nil {
			result.Stats.NonRegularSkipped++
			continue
		}
		if exceeded {
			code := CoverageMaxFileBytes
			limit := s.limits.MaxFileBytes
			observed := bytesHashed + 1
			if remaining < s.limits.MaxFileBytes {
				code = CoverageMaxTotalBytes
				limit = s.limits.MaxTotalBytes
				observed = result.Stats.BytesHashed + 1
			}
			coverage.add(code, candidate.Path, limit, observed)
			if code == CoverageMaxTotalBytes {
				break
			}
			result.Stats.OversizeSkipped++
			continue
		}

		packageOwnership, packageSignal := s.lookupPackageOwnership(ctx, candidate.Path)
		if err := ctx.Err(); err != nil {
			result.Coverage = coverage.findings()
			return result, err
		}
		signals := executableSignals(candidate, openedInfo.Mode(), packageSignal)
		record := ExecutableRecord{
			Path:             candidate.Path,
			SHA256:           "sha256:" + digest,
			Mode:             normalizedMode(openedInfo.Mode()),
			Size:             openedInfo.Size(),
			Ownership:        ownershipFromFileInfo(openedInfo),
			PackageOwnership: packageOwnership,
			Signals:          signals,
		}
		result.Executables = append(result.Executables, record)
		result.Stats.FilesTriaged++
	}

	sort.Slice(result.Executables, func(i, j int) bool {
		return result.Executables[i].Path < result.Executables[j].Path
	})
	result.Coverage = coverage.findings()
	return result, nil
}

func normalizeCandidates(candidates []ExecutableCandidate) []ExecutableCandidate {
	byPath := make(map[string]ExecutableCandidate, len(candidates))
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Path) == "" {
			continue
		}
		candidate.Path = filepath.Clean(candidate.Path)
		existing, ok := byPath[candidate.Path]
		if ok {
			existing.New = existing.New || candidate.New
			byPath[candidate.Path] = existing
			continue
		}
		byPath[candidate.Path] = candidate
	}
	normalized := make([]ExecutableCandidate, 0, len(byPath))
	for _, candidate := range byPath {
		normalized = append(normalized, candidate)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Path < normalized[j].Path
	})
	return normalized
}

func hashExecutableBounded(
	ctx context.Context,
	path string,
	before os.FileInfo,
	limit int64,
) (string, int64, bool, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()

	after, err := file.Stat()
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("inspect opened file %q: %w", path, err)
	}
	if !after.Mode().IsRegular() ||
		after.Mode().Perm()&0o111 == 0 ||
		!os.SameFile(before, after) {
		return "", 0, false, nil, nil
	}

	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", total, false, nil, err
		}
		remaining := limit - total
		if remaining <= 0 {
			current, statErr := file.Stat()
			if statErr != nil {
				return "", total, false, nil, fmt.Errorf("inspect bounded executable %q: %w", path, statErr)
			}
			if current.Size() > total {
				return "", total, true, current, nil
			}
			after = current
			break
		}
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		count, readErr := file.Read(buffer[:readSize])
		if count > 0 {
			total += int64(count)
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", total, false, nil, fmt.Errorf("hash %q: %w", path, readErr)
		}
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return "", total, false, nil, fmt.Errorf("inspect hashed executable %q: %w", path, err)
	}
	if finalInfo.Size() != total {
		return "", total, true, finalInfo, nil
	}
	return hex.EncodeToString(hash.Sum(nil)), total, false, finalInfo, nil
}

func (s *ExecutableScanner) lookupPackageOwnership(
	ctx context.Context,
	path string,
) (PackageOwnership, TriageSignal) {
	if s.packageOwnership == nil {
		return PackageOwnership{Status: PackageOwnershipUnknown}, TriageSignal{
			ID:         "package-ownership-not-checked",
			Assessment: AssessmentUnknown,
		}
	}
	ownership, err := s.packageOwnership(ctx, path)
	if err != nil {
		return PackageOwnership{Status: PackageOwnershipUnknown}, TriageSignal{
			ID:         "package-ownership-lookup-failed",
			Assessment: AssessmentUnknown,
		}
	}
	switch ownership.Status {
	case PackageOwnershipOwned:
		if strings.TrimSpace(ownership.Package) == "" {
			return PackageOwnership{Status: PackageOwnershipUnknown}, TriageSignal{
				ID:         "package-ownership-invalid-result",
				Assessment: AssessmentUnknown,
			}
		}
		return ownership, TriageSignal{}
	case PackageOwnershipUnowned:
		ownership.Package = ""
		return ownership, TriageSignal{
			ID:         "package-ownership-unowned",
			Assessment: AssessmentUnknown,
		}
	case PackageOwnershipUnknown:
		ownership.Package = ""
		return ownership, TriageSignal{
			ID:         "package-ownership-unknown",
			Assessment: AssessmentUnknown,
		}
	default:
		return PackageOwnership{Status: PackageOwnershipUnknown}, TriageSignal{
			ID:         "package-ownership-invalid-result",
			Assessment: AssessmentUnknown,
		}
	}
}

func executableSignals(
	candidate ExecutableCandidate,
	mode os.FileMode,
	packageSignal TriageSignal,
) []TriageSignal {
	signals := make([]TriageSignal, 0, 5)
	if candidate.New && riskyExecutableLocation(candidate.Path) {
		signals = append(signals, TriageSignal{
			ID:         "new-executable-in-temp-or-downloads",
			Assessment: AssessmentSuspicious,
		})
	}
	if mode&os.ModeSetuid != 0 {
		signals = append(signals, TriageSignal{
			ID:         "setuid-executable",
			Assessment: AssessmentSuspicious,
		})
	}
	if mode&os.ModeSetgid != 0 {
		signals = append(signals, TriageSignal{
			ID:         "setgid-executable",
			Assessment: AssessmentSuspicious,
		})
	}
	base := filepath.Base(candidate.Path)
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		signals = append(signals, TriageSignal{
			ID:         "hidden-executable",
			Assessment: AssessmentSuspicious,
		})
	}
	if packageSignal.ID != "" {
		signals = append(signals, packageSignal)
	}
	sort.Slice(signals, func(i, j int) bool {
		return signals[i].ID < signals[j].ID
	})
	return signals
}

func riskyExecutableLocation(path string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = filepath.Clean(path)
	}
	tempRoots := []string{
		os.TempDir(),
		"/tmp",
		"/var/tmp",
		"/private/tmp",
		"/private/var/tmp",
		"/private/var/folders",
	}
	for _, root := range tempRoots {
		if withinPath(root, absolute) {
			return true
		}
	}
	for _, component := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if strings.EqualFold(component, "Downloads") {
			return true
		}
	}
	return false
}

func withinPath(root, path string) bool {
	root, rootErr := filepath.Abs(root)
	path, pathErr := filepath.Abs(path)
	if rootErr != nil || pathErr != nil {
		return false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func normalizedMode(mode os.FileMode) string {
	value := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		value |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		value |= 0o1000
	}
	if value > 0o777 {
		return fmt.Sprintf("0%04o", value)
	}
	return fmt.Sprintf("%04o", value)
}
