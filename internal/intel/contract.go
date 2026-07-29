// Package intel provides a bounded, signed, offline-only intelligence bundle
// format. Bundle records are declarative data: this package never executes
// content, invokes commands, accepts filesystem paths, or performs network I/O.
package intel

import "time"

const (
	BundleSchema         = "io.oh-my-safety/intelligence-bundle"
	BundleSchemaVersion  = 1
	TrustStoreSchema     = "io.oh-my-safety/intelligence-trust-store"
	TrustStoreVersion    = 1
	CurrentSchema        = "io.oh-my-safety/intelligence-current"
	CurrentSchemaVersion = 1
)

type RecordType string

const (
	RecordMaliciousSHA256   RecordType = "malicious_sha256"
	RecordRevokedSigner     RecordType = "revoked_signer"
	RecordVulnerablePackage RecordType = "vulnerable_package"
	RecordSecretPattern     RecordType = "secret_detector_pattern"
)

type SignerKind string

const (
	SignerID SignerKind = "signer_id"
	TeamID   SignerKind = "team_id"
)

type ConstraintOperator string

const (
	ConstraintEqual              ConstraintOperator = "eq"
	ConstraintLessThan           ConstraintOperator = "lt"
	ConstraintLessThanOrEqual    ConstraintOperator = "lte"
	ConstraintGreaterThan        ConstraintOperator = "gt"
	ConstraintGreaterThanOrEqual ConstraintOperator = "gte"
)

type VersionConstraint struct {
	Operator ConstraintOperator `json:"operator"`
	Version  string             `json:"version"`
}

type MaliciousSHA256Record struct {
	SHA256 string `json:"sha256"`
}

type RevokedSignerRecord struct {
	Kind       SignerKind `json:"kind"`
	Identifier string     `json:"identifier"`
}

type VulnerablePackageRecord struct {
	Ecosystem   string              `json:"ecosystem"`
	Package     string              `json:"package"`
	Constraints []VersionConstraint `json:"constraints"`
}

// SecretDetectorPatternRecord carries RE2-compatible matching metadata only.
// There is intentionally no command, script, replacement, path, URL, or action.
type SecretDetectorPatternRecord struct {
	DetectorID string `json:"detector_id"`
	Pattern    string `json:"pattern"`
}

// Record is a closed tagged union. Exactly one payload pointer must be present,
// and it must correspond to Type.
type Record struct {
	Type              RecordType                   `json:"type"`
	MaliciousSHA256   *MaliciousSHA256Record       `json:"malicious_sha256,omitempty"`
	RevokedSigner     *RevokedSignerRecord         `json:"revoked_signer,omitempty"`
	VulnerablePackage *VulnerablePackageRecord     `json:"vulnerable_package,omitempty"`
	SecretPattern     *SecretDetectorPatternRecord `json:"secret_detector_pattern,omitempty"`
}

type Bundle struct {
	Schema             string    `json:"schema"`
	SchemaVersion      int       `json:"schema_version"`
	BundleID           string    `json:"bundle_id"`
	Sequence           uint64    `json:"sequence"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	MinimumAgentSchema int       `json:"minimum_agent_schema"`
	Records            []Record  `json:"records"`
	PayloadSHA256      string    `json:"payload_sha256"`
	KeyID              string    `json:"key_id"`
	Signature          string    `json:"signature"`
}

type Limits struct {
	MaxBundleBytes  int64
	MaxRecords      int
	MaxRecordBytes  int
	MaxPatternBytes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxBundleBytes:  4 << 20,
		MaxRecords:      10_000,
		MaxRecordBytes:  8 << 10,
		MaxPatternBytes: 1 << 10,
	}
}

type AcceptanceState struct {
	BundleID      string `json:"bundle_id"`
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type VerifyOptions struct {
	Limits       Limits
	Now          time.Time
	ClockSkew    time.Duration
	AgentSchema  int
	LastAccepted *AcceptanceState
}

type VerifiedBundle struct {
	Bundle    Bundle
	Canonical []byte
	Replay    bool
}

type CurrentMetadata struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	BundleFile    string `json:"bundle_file"`
	BundleID      string `json:"bundle_id"`
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256"`
	BundleSHA256  string `json:"bundle_sha256"`
	KeyID         string `json:"key_id"`
}

func (m CurrentMetadata) AcceptanceState() AcceptanceState {
	return AcceptanceState{
		BundleID:      m.BundleID,
		Sequence:      m.Sequence,
		PayloadSHA256: m.PayloadSHA256,
	}
}

type InstallOptions struct {
	Verify VerifyOptions
}

type InstallResult struct {
	Metadata  CurrentMetadata
	Installed bool
	Replay    bool
}
