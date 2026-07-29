package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const minimumFingerprintKeyBytes = 32

var (
	errStopSecretScan = errors.New("secret scan bound reached")

	privateKeyBegin = regexp.MustCompile(`^-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|OPENSSH PRIVATE KEY|PRIVATE KEY|ENCRYPTED PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[[:space:]]*$`)
	assignmentLine  = regexp.MustCompile(`(?i)^[[:space:]]*(?:(?:export|const|let|var)[[:space:]]+)?["']?([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token))["']?[[:space:]]*(:=|=|:)[[:space:]]*(.*)$`)
)

type tokenDetector struct {
	id       string
	pattern  *regexp.Regexp
	validate func(string) bool
}

var tokenDetectors = []tokenDetector{
	{
		id:       "token.aws-access-key-id",
		pattern:  regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		validate: validateFormattedToken,
	},
	{
		id:       "token.github",
		pattern:  regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82,255})\b`),
		validate: validateFormattedToken,
	},
	{
		id:       "token.gitlab",
		pattern:  regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,255}\b`),
		validate: validateFormattedToken,
	},
	{
		id:       "token.google-api-key",
		pattern:  regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		validate: validateFormattedToken,
	},
	{
		id:       "token.slack",
		pattern:  regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{20,255}\b`),
		validate: validateFormattedToken,
	},
	{
		id:       "token.stripe-live-secret",
		pattern:  regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,255}\b`),
		validate: validateFormattedToken,
	},
}

// SecretLimits bounds CPU, memory, filesystem traversal, and result size.
type SecretLimits struct {
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
	MaxDepth      int   `json:"max_depth"`
	MaxFiles      int   `json:"max_files"`
	MaxFindings   int   `json:"max_findings"`
}

func DefaultSecretLimits() SecretLimits {
	return SecretLimits{
		MaxFileBytes:  1 << 20,
		MaxTotalBytes: 32 << 20,
		MaxDepth:      8,
		MaxFiles:      2_000,
		MaxFindings:   200,
	}
}

type SecretOptions struct {
	Limits         SecretLimits
	FingerprintKey []byte
}

// SecretFinding contains no matched value. Excerpt is generated from fixed
// detector text or the assignment key/operator with the value replaced.
type SecretFinding struct {
	DetectorID      string `json:"detector_id"`
	Path            string `json:"path"`
	Line            int    `json:"line"`
	Fingerprint     string `json:"fingerprint"`
	RedactedExcerpt string `json:"redacted_excerpt"`
}

type SecretStats struct {
	FilesConsidered   int64 `json:"files_considered"`
	FilesScanned      int64 `json:"files_scanned"`
	BytesRead         int64 `json:"bytes_read"`
	SymlinksSkipped   int64 `json:"symlinks_skipped"`
	NonRegularSkipped int64 `json:"non_regular_skipped"`
	BinarySkipped     int64 `json:"binary_skipped"`
	OversizeSkipped   int64 `json:"oversize_skipped"`
}

type SecretResult struct {
	Schema        string                 `json:"schema"`
	SchemaVersion int                    `json:"schema_version"`
	ScannerID     string                 `json:"scanner_id"`
	Findings      []SecretFinding        `json:"findings"`
	Coverage      []CoverageLimitFinding `json:"coverage"`
	Stats         SecretStats            `json:"stats"`
}

type SecretScanner struct {
	limits SecretLimits
	key    []byte
}

func NewSecretScanner(options SecretOptions) (*SecretScanner, error) {
	limits := options.Limits
	if limits == (SecretLimits{}) {
		limits = DefaultSecretLimits()
	}
	if err := validateSecretLimits(limits); err != nil {
		return nil, err
	}
	if len(options.FingerprintKey) < minimumFingerprintKeyBytes {
		return nil, fmt.Errorf("fingerprint key must contain at least %d bytes", minimumFingerprintKeyBytes)
	}
	key := append([]byte(nil), options.FingerprintKey...)
	return &SecretScanner{limits: limits, key: key}, nil
}

func validateSecretLimits(limits SecretLimits) error {
	switch {
	case limits.MaxFileBytes <= 0:
		return errors.New("max file bytes must be positive")
	case limits.MaxTotalBytes <= 0:
		return errors.New("max total bytes must be positive")
	case limits.MaxDepth < 0:
		return errors.New("max depth cannot be negative")
	case limits.MaxFiles <= 0:
		return errors.New("max files must be positive")
	case limits.MaxFindings <= 0:
		return errors.New("max findings must be positive")
	default:
		return nil
	}
}

func (s *SecretScanner) Scan(ctx context.Context, roots ...string) (SecretResult, error) {
	result := SecretResult{
		Schema:        SecretResultSchema,
		SchemaVersion: SecretResultSchemaVersion,
		ScannerID:     SecretScannerID,
		Findings:      make([]SecretFinding, 0),
		Coverage:      make([]CoverageLimitFinding, 0),
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	normalizedRoots := normalizePaths(roots)
	coverage := newCoverageAccumulator(SecretScannerID)
	seenPaths := make(map[string]struct{})
	stop := false

	for _, root := range normalizedRoots {
		if stop {
			break
		}
		root = filepath.Clean(root)
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return fmt.Errorf("inspect %q: %w", path, walkErr)
			}

			depth, err := relativeDepth(root, path)
			if err != nil {
				return err
			}
			if depth > s.limits.MaxDepth {
				coverage.add(CoverageMaxDepth, path, int64(s.limits.MaxDepth), int64(depth))
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				result.Stats.SymlinksSkipped++
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if _, seen := seenPaths[path]; seen {
				return nil
			}
			seenPaths[path] = struct{}{}

			if result.Stats.FilesConsidered >= int64(s.limits.MaxFiles) {
				coverage.add(
					CoverageMaxFiles,
					path,
					int64(s.limits.MaxFiles),
					result.Stats.FilesConsidered+1,
				)
				return errStopSecretScan
			}
			result.Stats.FilesConsidered++

			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("inspect %q: %w", path, err)
			}
			if !info.Mode().IsRegular() {
				result.Stats.NonRegularSkipped++
				return nil
			}
			if info.Size() > s.limits.MaxFileBytes {
				result.Stats.OversizeSkipped++
				coverage.add(CoverageMaxFileBytes, path, s.limits.MaxFileBytes, info.Size())
				return nil
			}
			remaining := s.limits.MaxTotalBytes - result.Stats.BytesRead
			if remaining <= 0 || info.Size() > remaining {
				coverage.add(
					CoverageMaxTotalBytes,
					path,
					s.limits.MaxTotalBytes,
					result.Stats.BytesRead+info.Size(),
				)
				return errStopSecretScan
			}

			content, bytesRead, exceeded, err := readRegularFileBounded(ctx, path, info, minInt64(s.limits.MaxFileBytes, remaining))
			result.Stats.BytesRead += bytesRead
			if err != nil {
				return err
			}
			if exceeded {
				code := CoverageMaxFileBytes
				limit := s.limits.MaxFileBytes
				observed := bytesRead + 1
				if remaining < s.limits.MaxFileBytes {
					code = CoverageMaxTotalBytes
					limit = s.limits.MaxTotalBytes
					observed = result.Stats.BytesRead + 1
				}
				coverage.add(code, path, limit, observed)
				if code == CoverageMaxTotalBytes {
					return errStopSecretScan
				}
				result.Stats.OversizeSkipped++
				return nil
			}
			if isBinary(content) {
				result.Stats.BinarySkipped++
				return nil
			}
			result.Stats.FilesScanned++

			remainingFindings := s.limits.MaxFindings - len(result.Findings)
			fileFindings, err := s.inspectText(ctx, path, content, remainingFindings+1)
			if err != nil {
				return err
			}
			for _, finding := range fileFindings {
				if len(result.Findings) >= s.limits.MaxFindings {
					coverage.add(
						CoverageMaxFindings,
						path,
						int64(s.limits.MaxFindings),
						int64(len(result.Findings)+1),
					)
					return errStopSecretScan
				}
				result.Findings = append(result.Findings, finding)
			}
			return nil
		})
		switch {
		case walkErr == nil:
		case errors.Is(walkErr, errStopSecretScan):
			stop = true
		case errors.Is(walkErr, context.Canceled), errors.Is(walkErr, context.DeadlineExceeded):
			result.Coverage = coverage.findings()
			sortSecretFindings(result.Findings)
			return result, walkErr
		default:
			result.Coverage = coverage.findings()
			sortSecretFindings(result.Findings)
			return result, walkErr
		}
	}

	sortSecretFindings(result.Findings)
	result.Coverage = coverage.findings()
	return result, nil
}

func (s *SecretScanner) inspectText(
	ctx context.Context,
	path string,
	content []byte,
	limit int,
) ([]SecretFinding, error) {
	lines := bytes.Split(content, []byte{'\n'})
	findings := make([]SecretFinding, 0, minInt(limit, 16))
	appendFinding := func(finding SecretFinding) bool {
		findings = append(findings, finding)
		return len(findings) >= limit
	}
	for index := 0; index < len(lines); index++ {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		if len(findings) >= limit {
			break
		}
		line := strings.TrimSuffix(string(lines[index]), "\r")
		if match := privateKeyBegin.FindStringSubmatch(line); match != nil {
			label := match[1]
			endMarker := "-----END " + label + "-----"
			end := index
			for end+1 < len(lines) {
				end++
				if strings.TrimSpace(strings.TrimSuffix(string(lines[end]), "\r")) == endMarker {
					break
				}
			}
			block := bytes.Join(lines[index:end+1], []byte{'\n'})
			if appendFinding(SecretFinding{
				DetectorID:      "private-key.pem",
				Path:            path,
				Line:            index + 1,
				Fingerprint:     s.fingerprint("private-key.pem", block),
				RedactedExcerpt: "[REDACTED PRIVATE KEY BLOCK]",
			}) {
				break
			}
			index = end
			continue
		}

		trimmed := strings.TrimSpace(line)
		isComment := strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, ";")
		if !isComment {
			for _, detector := range tokenDetectors {
				matches := detector.pattern.FindAllString(line, -1)
				for _, match := range matches {
					if detector.validate != nil && !detector.validate(match) {
						continue
					}
					if appendFinding(SecretFinding{
						DetectorID:      detector.id,
						Path:            path,
						Line:            index + 1,
						Fingerprint:     s.fingerprint(detector.id, []byte(match)),
						RedactedExcerpt: "[REDACTED TOKEN]",
					}) {
						break
					}
				}
				if len(findings) >= limit {
					break
				}
			}

			if len(findings) < limit {
				match := assignmentLine.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				value := assignedValue(match[3])
				if highEntropyAssignment(value) {
					key := strings.ToLower(match[1])
					if appendFinding(SecretFinding{
						DetectorID:      "secret.assignment",
						Path:            path,
						Line:            index + 1,
						Fingerprint:     s.fingerprint("secret.assignment", []byte(value)),
						RedactedExcerpt: key + " " + match[2] + " [REDACTED]",
					}) {
						break
					}
				}
			}
		}
	}
	sortSecretFindings(findings)
	return findings, nil
}

func (s *SecretScanner) fingerprint(detectorID string, value []byte) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(detectorID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	sum := mac.Sum(nil)
	return "hmac-sha256:" + hex.EncodeToString(sum[:16])
}

func normalizePaths(paths []string) []string {
	unique := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		unique[filepath.Clean(path)] = struct{}{}
	}
	normalized := make([]string, 0, len(unique))
	for path := range unique {
		normalized = append(normalized, path)
	}
	sort.Strings(normalized)
	return normalized
}

func relativeDepth(root, path string) (int, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return 0, fmt.Errorf("resolve scan depth for %q: %w", path, err)
	}
	if relative == "." {
		return 0, nil
	}
	return len(strings.Split(relative, string(filepath.Separator))), nil
}

func readRegularFileBounded(
	ctx context.Context,
	path string,
	before os.FileInfo,
	limit int64,
) ([]byte, int64, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, false, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()

	after, err := file.Stat()
	if err != nil {
		return nil, 0, false, fmt.Errorf("inspect opened file %q: %w", path, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, 0, false, nil
	}

	var content bytes.Buffer
	chunk := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, total, false, err
		}
		remaining := limit - total
		if remaining <= 0 {
			current, statErr := file.Stat()
			if statErr != nil {
				return nil, total, false, fmt.Errorf("inspect bounded file %q: %w", path, statErr)
			}
			if current.Size() > total {
				return nil, total, true, nil
			}
			break
		}
		readSize := int64(len(chunk))
		if remaining < readSize {
			readSize = remaining
		}
		count, readErr := file.Read(chunk[:readSize])
		if count > 0 {
			total += int64(count)
			_, _ = content.Write(chunk[:count])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, total, false, fmt.Errorf("read %q: %w", path, readErr)
		}
	}
	return content.Bytes(), total, false, nil
}

func isBinary(content []byte) bool {
	if bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		return true
	}
	if len(content) == 0 {
		return false
	}
	controls := 0
	for _, value := range content {
		if value < 0x20 && value != '\n' && value != '\r' && value != '\t' && value != '\f' {
			controls++
		}
	}
	return controls*100/len(content) > 10
}

func assignedValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if value[0] == '\'' || value[0] == '"' || value[0] == '`' {
		quote := value[0]
		var escaped bool
		for index := 1; index < len(value); index++ {
			switch {
			case escaped:
				escaped = false
			case value[index] == '\\':
				escaped = true
			case value[index] == quote:
				return value[1:index]
			}
		}
		return strings.TrimSpace(value[1:])
	}
	if index := strings.IndexAny(value, " \t\r\n,;#"); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func highEntropyAssignment(value string) bool {
	if len(value) < 16 || len(value) > 4096 {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "", "password", "password123", "changeme", "change_me", "change-me",
		"secret", "example", "example-secret", "example_password", "dummy",
		"placeholder", "redacted", "[redacted]", "not-a-real-secret":
		return false
	}
	if strings.HasPrefix(lower, "${") ||
		strings.HasPrefix(lower, "{{") ||
		strings.HasPrefix(lower, "<") ||
		strings.HasPrefix(lower, "your_") ||
		strings.HasPrefix(lower, "your-") ||
		strings.HasPrefix(lower, "process.env") ||
		strings.HasPrefix(lower, "os.environ") ||
		allSame(value) ||
		repeatedPattern(value) ||
		sequentialASCII(value) {
		return false
	}
	return shannonEntropy(value) >= 3.0
}

func validateFormattedToken(value string) bool {
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "EXAMPLE") ||
		strings.Contains(upper, "PLACEHOLDER") ||
		strings.Contains(upper, "REDACTED") ||
		allSame(value) ||
		repeatedPattern(value) {
		return false
	}
	return shannonEntropy(value) >= 3.0
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[byte]int)
	for index := 0; index < len(value); index++ {
		counts[value[index]]++
	}
	length := float64(len(value))
	var entropy float64
	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func allSame(value string) bool {
	for index := 1; index < len(value); index++ {
		if value[index] != value[0] {
			return false
		}
	}
	return value != ""
}

func repeatedPattern(value string) bool {
	for width := 1; width <= 4 && width*3 <= len(value); width++ {
		if len(value)%width != 0 {
			continue
		}
		pattern := value[:width]
		if strings.Repeat(pattern, len(value)/width) == value {
			return true
		}
	}
	return false
}

func sequentialASCII(value string) bool {
	if len(value) < 8 {
		return false
	}
	ascending := true
	descending := true
	for index := 1; index < len(value); index++ {
		ascending = ascending && value[index] == value[index-1]+1
		descending = descending && value[index]+1 == value[index-1]
	}
	return ascending || descending
}

func sortSecretFindings(findings []SecretFinding) {
	sort.Slice(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		switch {
		case left.Path != right.Path:
			return left.Path < right.Path
		case left.Line != right.Line:
			return left.Line < right.Line
		case left.DetectorID != right.DetectorID:
			return left.DetectorID < right.DetectorID
		default:
			return left.Fingerprint < right.Fingerprint
		}
	})
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
