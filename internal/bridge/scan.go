package bridge

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

const (
	ScanSchemaVersion = 1
	MaxScanInputBytes = 4 << 20
	MaxScanLineBytes  = 64 << 10
	MaxScanResults    = 4096
)

type ScanScope string

const (
	ScanScopeFull      ScanScope = "full"
	ScanScopePartial   ScanScope = "partial"
	ScanScopeComposite ScanScope = "composite"
)

type ScanMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   string    `json:"version"`
	Platform  string    `json:"platform"`
	Source    string    `json:"source"`
	Scope     ScanScope `json:"scope"`
	Exit      int       `json:"exit"`
	FDA       bool      `json:"fda"`
	PublicIP  string    `json:"public_ip,omitempty"`
}

type CheckStatus string

const (
	CheckStatusOK       CheckStatus = "ok"
	CheckStatusWarn     CheckStatus = "warn"
	CheckStatusCritical CheckStatus = "critical"
	CheckStatusSkip     CheckStatus = "skip"
	CheckStatusError    CheckStatus = "error"
)

type CheckResult struct {
	Category    string         `json:"category"`
	Name        string         `json:"name"`
	Status      CheckStatus    `json:"status"`
	Severity    model.Severity `json:"severity"`
	Summary     string         `json:"summary"`
	Remediation string         `json:"remediation,omitempty"`
	Guide       string         `json:"guide,omitempty"`
}

type ScanSnapshot struct {
	SchemaVersion int           `json:"schema_version"`
	Metadata      ScanMetadata  `json:"metadata"`
	Results       []CheckResult `json:"results"`
}

func (snapshot ScanSnapshot) Validate() error {
	if snapshot.SchemaVersion != ScanSchemaVersion {
		return fmt.Errorf("unsupported scan schema version %d", snapshot.SchemaVersion)
	}
	metadata := snapshot.Metadata
	switch {
	case metadata.Timestamp.IsZero():
		return errors.New("scan timestamp is required")
	case metadata.UpdatedAt.IsZero():
		return errors.New("scan updated_at is required")
	case metadata.UpdatedAt.Before(metadata.Timestamp):
		return errors.New("scan updated_at cannot precede timestamp")
	case !validToken(metadata.Version, 64):
		return errors.New("scan version is invalid")
	case !validIdentifier(metadata.Platform):
		return errors.New("scan platform is invalid")
	case !validIdentifier(metadata.Source):
		return errors.New("scan source is invalid")
	case metadata.Scope != ScanScopeFull &&
		metadata.Scope != ScanScopePartial &&
		metadata.Scope != ScanScopeComposite:
		return errors.New("scan scope is invalid")
	case metadata.Exit < 0 || metadata.Exit > 3:
		return errors.New("scan exit must be from 0 through 3")
	case metadata.PublicIP != "" && net.ParseIP(metadata.PublicIP) == nil:
		return errors.New("scan public_ip is invalid")
	case len(snapshot.Results) == 0:
		return errors.New("scan must contain at least one result row")
	case len(snapshot.Results) > MaxScanResults:
		return fmt.Errorf("scan contains more than %d results", MaxScanResults)
	}
	seen := make(map[string]struct{}, len(snapshot.Results))
	for _, result := range snapshot.Results {
		if err := result.Validate(); err != nil {
			return fmt.Errorf("invalid check result: %w", err)
		}
		key := result.Category + "\x00" + result.Name
		if _, duplicate := seen[key]; duplicate {
			return errors.New("scan contains a duplicate check result")
		}
		seen[key] = struct{}{}
	}
	return validateExit(snapshot)
}

func (result CheckResult) Validate() error {
	if !validIdentifier(result.Category) {
		return errors.New("category is invalid")
	}
	if !validIdentifier(result.Name) {
		return errors.New("check name is invalid")
	}
	if !validToken(result.Summary, MaxScanLineBytes) {
		return errors.New("summary is empty or invalid")
	}
	if result.Remediation != "" && !validToken(result.Remediation, MaxScanLineBytes) {
		return errors.New("remediation is invalid")
	}
	if result.Guide != "" && !validGuide(result.Guide) {
		return errors.New("guide path is invalid")
	}

	switch result.Status {
	case CheckStatusOK, CheckStatusSkip:
		if result.Severity != model.SeverityInfo {
			return errors.New("ok and skip results must have info severity")
		}
	case CheckStatusWarn:
		if result.Severity != model.SeverityInfo && result.Severity != model.SeverityWarn {
			return errors.New("warn results must have info or warn severity")
		}
	case CheckStatusCritical, CheckStatusError:
		if result.Severity != model.SeverityCritical {
			return errors.New("critical and error results must have critical severity")
		}
	default:
		return errors.New("status is invalid")
	}
	return nil
}

func ParseScan(reader io.Reader) (ScanSnapshot, error) {
	if reader == nil {
		return ScanSnapshot{}, errors.New("scan input is required")
	}
	content, err := io.ReadAll(io.LimitReader(reader, MaxScanInputBytes+1))
	if err != nil {
		return ScanSnapshot{}, errors.New("read scan input")
	}
	if len(content) > MaxScanInputBytes {
		return ScanSnapshot{}, fmt.Errorf("scan input exceeds %d bytes", MaxScanInputBytes)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64<<10), MaxScanLineBytes)

	var snapshot ScanSnapshot
	snapshot.SchemaVersion = ScanSchemaVersion
	metadata := make(map[string]string)
	resultKeys := make(map[string]struct{})
	schemaSeen := false
	resultSection := false
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if line == "" {
			continue
		}
		if err := validateLineCharacters(line); err != nil {
			return ScanSnapshot{}, fmt.Errorf("scan line %d contains unsupported control characters", lineNumber)
		}
		fields := strings.Split(line, "\t")
		if !schemaSeen {
			if len(fields) != 2 || fields[0] != "schema" || fields[1] != "1" {
				return ScanSnapshot{}, errors.New("scan must begin with schema version 1")
			}
			schemaSeen = true
			continue
		}

		switch fields[0] {
		case "schema":
			return ScanSnapshot{}, fmt.Errorf("duplicate schema row at line %d", lineNumber)
		case "meta":
			if resultSection {
				return ScanSnapshot{}, fmt.Errorf("metadata row after results at line %d", lineNumber)
			}
			if len(fields) != 3 || fields[1] == "" {
				return ScanSnapshot{}, fmt.Errorf("malformed metadata row at line %d", lineNumber)
			}
			if !knownMetadataKey(fields[1]) {
				return ScanSnapshot{}, fmt.Errorf("unknown metadata key at line %d", lineNumber)
			}
			if _, duplicate := metadata[fields[1]]; duplicate {
				return ScanSnapshot{}, fmt.Errorf("duplicate metadata key at line %d", lineNumber)
			}
			metadata[fields[1]] = fields[2]
		case "result":
			resultSection = true
			result, err := parseResult(fields)
			if err != nil {
				return ScanSnapshot{}, fmt.Errorf("invalid result row at line %d: %w", lineNumber, err)
			}
			key := result.Category + "\x00" + result.Name
			if _, duplicate := resultKeys[key]; duplicate {
				return ScanSnapshot{}, fmt.Errorf("duplicate check result at line %d", lineNumber)
			}
			resultKeys[key] = struct{}{}
			snapshot.Results = append(snapshot.Results, result)
			if len(snapshot.Results) > MaxScanResults {
				return ScanSnapshot{}, fmt.Errorf("scan contains more than %d results", MaxScanResults)
			}
		case "detail":
			// Schema-v1 details are human display text, not a stable contract.
			// Deliberately ignore them rather than extracting finding IDs.
			resultSection = true
		default:
			return ScanSnapshot{}, fmt.Errorf("unknown scan row type at line %d", lineNumber)
		}
	}
	if err := scanner.Err(); err != nil {
		return ScanSnapshot{}, fmt.Errorf("scan line exceeds %d bytes", MaxScanLineBytes)
	}
	if !schemaSeen {
		return ScanSnapshot{}, errors.New("scan schema row is required")
	}
	if len(snapshot.Results) == 0 {
		return ScanSnapshot{}, errors.New("scan must contain at least one result row")
	}

	parsedMetadata, err := parseMetadata(metadata)
	if err != nil {
		return ScanSnapshot{}, err
	}
	snapshot.Metadata = parsedMetadata
	if err := snapshot.Validate(); err != nil {
		return ScanSnapshot{}, err
	}
	return snapshot, nil
}

func parseMetadata(values map[string]string) (ScanMetadata, error) {
	for _, key := range []string{"timestamp", "version", "platform", "source", "exit", "fda"} {
		if _, present := values[key]; !present {
			return ScanMetadata{}, fmt.Errorf("required scan metadata %q is missing", key)
		}
	}

	timestamp, err := time.Parse(time.RFC3339Nano, values["timestamp"])
	if err != nil {
		return ScanMetadata{}, errors.New("scan timestamp must be RFC3339")
	}
	updatedAt := timestamp
	if raw, present := values["updated_at"]; present {
		if raw == "" {
			return ScanMetadata{}, errors.New("scan updated_at must be RFC3339")
		}
		updatedAt, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return ScanMetadata{}, errors.New("scan updated_at must be RFC3339")
		}
	}
	timestamp = timestamp.UTC()
	updatedAt = updatedAt.UTC()
	if updatedAt.Before(timestamp) {
		return ScanMetadata{}, errors.New("scan updated_at cannot precede timestamp")
	}

	if !validToken(values["version"], 64) {
		return ScanMetadata{}, errors.New("scan version is invalid")
	}
	if !validIdentifier(values["platform"]) {
		return ScanMetadata{}, errors.New("scan platform is invalid")
	}
	if !validIdentifier(values["source"]) {
		return ScanMetadata{}, errors.New("scan source is invalid")
	}

	scope := ScanScopeFull
	if raw, present := values["scope"]; present {
		if raw == "" {
			return ScanMetadata{}, errors.New("scan scope is invalid")
		}
		scope = ScanScope(raw)
	}
	switch scope {
	case ScanScopeFull, ScanScopePartial, ScanScopeComposite:
	default:
		return ScanMetadata{}, errors.New("scan scope is invalid")
	}

	rawExit := values["exit"]
	if rawExit != "0" && rawExit != "1" && rawExit != "2" && rawExit != "3" {
		return ScanMetadata{}, errors.New("scan exit must be an integer from 0 through 3")
	}
	exitCode, err := strconv.Atoi(rawExit)
	if err != nil {
		return ScanMetadata{}, errors.New("scan exit must be an integer from 0 through 3")
	}
	fda, err := strconv.ParseBool(values["fda"])
	if err != nil || values["fda"] != "true" && values["fda"] != "false" {
		return ScanMetadata{}, errors.New("scan fda must be true or false")
	}
	publicIP := values["public_ip"]
	if publicIP != "" && net.ParseIP(publicIP) == nil {
		return ScanMetadata{}, errors.New("scan public_ip is invalid")
	}

	return ScanMetadata{
		Timestamp: timestamp,
		UpdatedAt: updatedAt,
		Version:   values["version"],
		Platform:  values["platform"],
		Source:    values["source"],
		Scope:     scope,
		Exit:      exitCode,
		FDA:       fda,
		PublicIP:  publicIP,
	}, nil
}

func parseResult(fields []string) (CheckResult, error) {
	if len(fields) != 8 {
		return CheckResult{}, errors.New("result row must contain exactly eight fields")
	}
	result := CheckResult{
		Category:    fields[1],
		Name:        fields[2],
		Status:      CheckStatus(fields[3]),
		Severity:    model.Severity(fields[4]),
		Summary:     fields[5],
		Remediation: fields[6],
		Guide:       fields[7],
	}
	if err := result.Validate(); err != nil {
		return CheckResult{}, err
	}
	return result, nil
}

func validateExit(snapshot ScanSnapshot) error {
	expected := 0
	for _, result := range snapshot.Results {
		switch result.Status {
		case CheckStatusWarn:
			if expected < 1 {
				expected = 1
			}
		case CheckStatusCritical:
			if expected < 2 {
				expected = 2
			}
		case CheckStatusError:
			expected = 3
		}
	}
	if snapshot.Metadata.Exit != expected {
		return fmt.Errorf(
			"scan exit %d is inconsistent with result statuses; expected %d",
			snapshot.Metadata.Exit,
			expected,
		)
	}
	return nil
}

func knownMetadataKey(key string) bool {
	switch key {
	case "timestamp", "updated_at", "version", "platform", "source",
		"scope", "exit", "fda", "public_ip":
		return true
	default:
		return false
	}
}

func validateLineCharacters(line string) error {
	for _, character := range line {
		if character == '\t' {
			continue
		}
		if character == '\r' || character == '\x00' ||
			unicode.IsControl(character) {
			return errors.New("control character")
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("._-", character):
		default:
			return false
		}
	}
	return true
}

func validToken(value string, maximum int) bool {
	if value == "" ||
		len(value) > maximum ||
		value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validGuide(value string) bool {
	if len(value) > 1024 ||
		strings.Contains(value, "\\") ||
		strings.HasPrefix(value, "/") ||
		path.Clean(value) != value ||
		value == "." ||
		value == ".." ||
		strings.HasPrefix(value, "../") {
		return false
	}
	return validToken(value, 1024)
}

func SnapshotDigest(snapshot ScanSnapshot) (string, error) {
	if err := snapshot.Validate(); err != nil {
		return "", err
	}
	canonical := snapshot
	canonical.Metadata.Timestamp = canonical.Metadata.Timestamp.UTC()
	canonical.Metadata.UpdatedAt = canonical.Metadata.UpdatedAt.UTC()
	canonical.Results = append([]CheckResult(nil), snapshot.Results...)
	sortResults(canonical.Results)
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", errors.New("encode canonical scan snapshot")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sortResults(results []CheckResult) {
	for index := 1; index < len(results); index++ {
		current := results[index]
		position := index
		for position > 0 && resultLess(current, results[position-1]) {
			results[position] = results[position-1]
			position--
		}
		results[position] = current
	}
}

func resultLess(left, right CheckResult) bool {
	if left.Category != right.Category {
		return left.Category < right.Category
	}
	return left.Name < right.Name
}
