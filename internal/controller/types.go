// Package controller implements the self-hosted, pull-only organization
// controller. It stores policy and redacted posture data, but deliberately has
// no mechanism for sending commands or opening connections to enrolled agents.
package controller

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Vardominator/oh-my-safety/internal/model"
	"github.com/Vardominator/oh-my-safety/internal/profile"
)

const (
	PolicySchema          = "io.oh-my-safety/organization-policy"
	PolicySchemaVersion   = 1
	ReportSchema          = "io.oh-my-safety/redacted-report"
	ReportSchemaVersion   = 1
	SignedPolicySchema    = "io.oh-my-safety/signed-policy"
	SignedPolicyVersion   = 1
	AdminConfigSchema     = "io.oh-my-safety/controller-admins"
	AdminConfigVersion    = 1
	maxPolicyChecks       = 512
	maxReportFindings     = 2_000
	maxIdentifierLength   = 128
	maxInventoryValueSize = 256
)

var (
	ErrNotFound        = errors.New("controller record not found")
	ErrConflict        = errors.New("controller record conflict")
	ErrUnauthenticated = errors.New("authentication failed")
	ErrInvalidInput    = errors.New("invalid controller input")
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

func (role Role) Valid() bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

func (role Role) Allows(required Role) bool {
	rank := map[Role]int{
		RoleViewer:   1,
		RoleOperator: 2,
		RoleAdmin:    3,
	}
	return role.Valid() && required.Valid() && rank[role] >= rank[required]
}

type Principal struct {
	ID   string `json:"id"`
	Role Role   `json:"role"`

	tokenHash [32]byte
}

type DeviceMetadata struct {
	Name         string `json:"name"`
	Platform     string `json:"platform"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

func (metadata DeviceMetadata) Validate() error {
	switch {
	case !validLabel(metadata.Name, maxInventoryValueSize):
		return fmt.Errorf("%w: invalid device name", ErrInvalidInput)
	case !validLabel(metadata.Platform, 64):
		return fmt.Errorf("%w: invalid platform", ErrInvalidInput)
	case !validLabel(metadata.OSVersion, maxInventoryValueSize):
		return fmt.Errorf("%w: invalid OS version", ErrInvalidInput)
	case !validLabel(metadata.AgentVersion, maxInventoryValueSize):
		return fmt.Errorf("%w: invalid agent version", ErrInvalidInput)
	default:
		return nil
	}
}

type Device struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Platform            string     `json:"platform"`
	OSVersion           string     `json:"os_version"`
	AgentVersion        string     `json:"agent_version"`
	Group               string     `json:"group"`
	EnrolledAt          time.Time  `json:"enrolled_at"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	CredentialRotatedAt time.Time  `json:"credential_rotated_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

type EnrollmentGrant struct {
	DeviceID         string `json:"device_id"`
	DeviceCredential string `json:"device_credential"`
}

type RemediationMode string

const (
	RemediationObserve  RemediationMode = "observe"
	RemediationPrompt   RemediationMode = "prompt"
	RemediationSafeAuto RemediationMode = "safe-automatic"
)

func (mode RemediationMode) Valid() bool {
	switch mode {
	case RemediationObserve, RemediationPrompt, RemediationSafeAuto:
		return true
	default:
		return false
	}
}

// PolicyCheck is intentionally declarative. A check is only an identifier and
// an enabled bit; it cannot contain arguments, source code, or executable data.
type PolicyCheck struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type CadencePolicy struct {
	ScanIntervalSeconds uint32 `json:"scan_interval_seconds"`
	JitterSeconds       uint32 `json:"jitter_seconds"`
}

type ReportingPolicy struct {
	Enabled             bool   `json:"enabled"`
	SyncIntervalSeconds uint32 `json:"sync_interval_seconds"`
}

// PolicyDocument is a closed, versioned data contract. Do not add generic maps,
// json.RawMessage, command, script, arguments, or arbitrary payload fields.
type PolicyDocument struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Revision      uint64          `json:"revision"`
	Checks        []PolicyCheck   `json:"checks"`
	Profile       string          `json:"profile"`
	Cadence       CadencePolicy   `json:"cadence"`
	Reporting     ReportingPolicy `json:"reporting"`
	Remediation   RemediationMode `json:"remediation"`
}

func (document PolicyDocument) Validate() error {
	switch {
	case document.Schema != PolicySchema:
		return fmt.Errorf("%w: unsupported policy schema", ErrInvalidInput)
	case document.SchemaVersion != PolicySchemaVersion:
		return fmt.Errorf("%w: unsupported policy schema version", ErrInvalidInput)
	case !validIdentifier(document.ID):
		return fmt.Errorf("%w: invalid policy id", ErrInvalidInput)
	case document.Revision == 0:
		return fmt.Errorf("%w: policy revision must be positive", ErrInvalidInput)
	case len(document.Checks) == 0 || len(document.Checks) > maxPolicyChecks:
		return fmt.Errorf("%w: invalid policy check count", ErrInvalidInput)
	case document.Cadence.ScanIntervalSeconds < 60 ||
		document.Cadence.ScanIntervalSeconds > 31*24*60*60:
		return fmt.Errorf("%w: invalid scan interval", ErrInvalidInput)
	case document.Cadence.JitterSeconds >= document.Cadence.ScanIntervalSeconds:
		return fmt.Errorf("%w: invalid cadence jitter", ErrInvalidInput)
	case document.Reporting.Enabled &&
		(document.Reporting.SyncIntervalSeconds < 60 ||
			document.Reporting.SyncIntervalSeconds > 31*24*60*60):
		return fmt.Errorf("%w: invalid reporting interval", ErrInvalidInput)
	case !document.Reporting.Enabled && document.Reporting.SyncIntervalSeconds != 0:
		return fmt.Errorf("%w: disabled reporting must have a zero interval", ErrInvalidInput)
	case !document.Remediation.Valid():
		return fmt.Errorf("%w: invalid remediation mode", ErrInvalidInput)
	}
	if _, err := profile.Resolve(document.Profile); err != nil {
		return fmt.Errorf("%w: invalid profile", ErrInvalidInput)
	}
	seen := make(map[string]struct{}, len(document.Checks))
	for _, check := range document.Checks {
		if !validIdentifier(check.ID) {
			return fmt.Errorf("%w: invalid check id", ErrInvalidInput)
		}
		if _, exists := seen[check.ID]; exists {
			return fmt.Errorf("%w: duplicate check id", ErrInvalidInput)
		}
		seen[check.ID] = struct{}{}
	}
	return nil
}

type SignedPolicy struct {
	Schema           string         `json:"schema"`
	SchemaVersion    int            `json:"schema_version"`
	Document         PolicyDocument `json:"document"`
	Algorithm        string         `json:"algorithm"`
	SigningPublicKey string         `json:"signing_public_key"`
	Signature        string         `json:"signature"`
}

// RedactedFinding deliberately excludes titles, summaries, evidence, paths,
// command lines, usernames, hostnames, labels, and arbitrary payloads.
type RedactedFinding struct {
	DetectorID  string             `json:"detector_id"`
	Category    string             `json:"category"`
	Severity    model.Severity     `json:"severity"`
	State       model.FindingState `json:"state"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
	Occurrences uint64             `json:"occurrences"`
}

func (finding RedactedFinding) validate(reportedAt time.Time) error {
	switch {
	case !validIdentifier(finding.DetectorID):
		return fmt.Errorf("%w: invalid detector id", ErrInvalidInput)
	case !validIdentifier(finding.Category):
		return fmt.Errorf("%w: invalid category", ErrInvalidInput)
	case !finding.Severity.Valid():
		return fmt.Errorf("%w: invalid severity", ErrInvalidInput)
	case !finding.State.Valid():
		return fmt.Errorf("%w: invalid finding state", ErrInvalidInput)
	case finding.FirstSeen.IsZero() || finding.LastSeen.IsZero():
		return fmt.Errorf("%w: finding timestamps are required", ErrInvalidInput)
	case finding.LastSeen.Before(finding.FirstSeen):
		return fmt.Errorf("%w: last_seen precedes first_seen", ErrInvalidInput)
	case finding.LastSeen.After(reportedAt.Add(5 * time.Minute)):
		return fmt.Errorf("%w: last_seen is after reported_at", ErrInvalidInput)
	case finding.Occurrences == 0:
		return fmt.Errorf("%w: occurrences must be positive", ErrInvalidInput)
	default:
		return nil
	}
}

type ReportSync struct {
	Schema        string            `json:"schema"`
	SchemaVersion int               `json:"schema_version"`
	ReportedAt    time.Time         `json:"reported_at"`
	Findings      []RedactedFinding `json:"findings"`
}

func (report ReportSync) Validate(now time.Time) error {
	switch {
	case report.Schema != ReportSchema:
		return fmt.Errorf("%w: unsupported report schema", ErrInvalidInput)
	case report.SchemaVersion != ReportSchemaVersion:
		return fmt.Errorf("%w: unsupported report schema version", ErrInvalidInput)
	case report.ReportedAt.IsZero():
		return fmt.Errorf("%w: reported_at is required", ErrInvalidInput)
	case report.ReportedAt.After(now.Add(5 * time.Minute)):
		return fmt.Errorf("%w: reported_at is in the future", ErrInvalidInput)
	case len(report.Findings) > maxReportFindings:
		return fmt.Errorf("%w: too many findings", ErrInvalidInput)
	}
	seen := make(map[string]struct{}, len(report.Findings))
	for _, finding := range report.Findings {
		if err := finding.validate(report.ReportedAt); err != nil {
			return err
		}
		key := finding.DetectorID + "\x00" + finding.Category
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate redacted finding", ErrInvalidInput)
		}
		seen[key] = struct{}{}
	}
	return nil
}

type StoredFinding struct {
	DeviceID   string    `json:"device_id"`
	ReportedAt time.Time `json:"reported_at"`
	RedactedFinding
}

type AuditEntry struct {
	Sequence   int64     `json:"sequence"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > maxIdentifierLength {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validGroup(value string) bool {
	return validIdentifier(value)
}

func validLabel(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
