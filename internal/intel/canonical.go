package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxBundleIDBytes   = 128
	maxKeyIDBytes      = 128
	maxPackageBytes    = 256
	maxEcosystemBytes  = 32
	maxVersionBytes    = 128
	maxSignerIDBytes   = 128
	maxDetectorIDBytes = 128
	maxConstraints     = 16
)

var (
	safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	safePackage    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@+._:/~-]*$`)
	safeVersion    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]*$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	teamIDPattern  = regexp.MustCompile(`^[A-Z0-9]{10}$`)
)

type payloadEnvelope struct {
	Records []Record `json:"records"`
}

type unsignedEnvelope struct {
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
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	switch {
	case limits.MaxBundleBytes <= 0:
		return Limits{}, errors.New("intel: max bundle bytes must be positive")
	case limits.MaxRecords <= 0:
		return Limits{}, errors.New("intel: max records must be positive")
	case limits.MaxRecordBytes <= 0:
		return Limits{}, errors.New("intel: max record bytes must be positive")
	case limits.MaxPatternBytes <= 0:
		return Limits{}, errors.New("intel: max pattern bytes must be positive")
	case limits.MaxPatternBytes > limits.MaxRecordBytes:
		return Limits{}, errors.New("intel: pattern limit cannot exceed record limit")
	default:
		return limits, nil
	}
}

func prepareBundle(bundle Bundle, limits Limits) (Bundle, []byte, error) {
	if err := validateBundleHeader(bundle); err != nil {
		return Bundle{}, nil, err
	}
	if len(bundle.Records) > limits.MaxRecords {
		return Bundle{}, nil, ErrTooManyRecords
	}

	records, err := canonicalRecords(bundle.Records, limits)
	if err != nil {
		return Bundle{}, nil, err
	}
	bundle.IssuedAt = bundle.IssuedAt.UTC()
	bundle.ExpiresAt = bundle.ExpiresAt.UTC()
	bundle.Records = records

	payload, err := json.Marshal(payloadEnvelope{Records: records})
	if err != nil {
		return Bundle{}, nil, ErrInvalidBundle
	}
	return bundle, payload, nil
}

func validateBundleHeader(bundle Bundle) error {
	switch {
	case bundle.Schema != BundleSchema:
		return ErrInvalidBundle
	case bundle.SchemaVersion != BundleSchemaVersion:
		return ErrInvalidBundle
	case !boundedIdentifier(bundle.BundleID, maxBundleIDBytes):
		return ErrInvalidBundle
	case bundle.Sequence == 0:
		return ErrInvalidBundle
	case bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero():
		return ErrInvalidBundle
	case !bundle.ExpiresAt.After(bundle.IssuedAt):
		return ErrInvalidBundle
	case bundle.MinimumAgentSchema <= 0:
		return ErrInvalidBundle
	case bundle.Records == nil:
		return ErrInvalidBundle
	case !boundedIdentifier(bundle.KeyID, maxKeyIDBytes):
		return ErrInvalidBundle
	default:
		return nil
	}
}

func canonicalRecords(records []Record, limits Limits) ([]Record, error) {
	canonical := make([]Record, 0, len(records))
	duplicates := make(map[string]struct{}, len(records))
	for index, record := range records {
		normalized, identity, err := canonicalRecord(index, record, limits)
		if err != nil {
			return nil, err
		}
		if _, exists := duplicates[identity]; exists {
			return nil, &recordValidationError{
				index: index,
				code:  "duplicate",
				cause: errors.Join(ErrInvalidRecord, ErrDuplicateRecord),
			}
		}
		duplicates[identity] = struct{}{}
		canonical = append(canonical, normalized)
	}
	sort.Slice(canonical, func(i, j int) bool {
		return recordSortKey(canonical[i]) < recordSortKey(canonical[j])
	})
	return canonical, nil
}

func canonicalRecord(index int, record Record, limits Limits) (Record, string, error) {
	payloadCount := 0
	for _, present := range []bool{
		record.MaliciousSHA256 != nil,
		record.RevokedSigner != nil,
		record.VulnerablePackage != nil,
		record.SecretPattern != nil,
	} {
		if present {
			payloadCount++
		}
	}
	if payloadCount != 1 {
		return Record{}, "", invalidRecord(index, "payload_count")
	}

	var identity string
	switch record.Type {
	case RecordMaliciousSHA256:
		if record.MaliciousSHA256 == nil {
			return Record{}, "", invalidRecord(index, "type_payload")
		}
		hash := strings.ToLower(record.MaliciousSHA256.SHA256)
		if !sha256Pattern.MatchString(hash) {
			return Record{}, "", invalidRecord(index, "sha256")
		}
		record = Record{
			Type:            RecordMaliciousSHA256,
			MaliciousSHA256: &MaliciousSHA256Record{SHA256: hash},
		}
		identity = string(record.Type) + ":" + hash

	case RecordRevokedSigner:
		if record.RevokedSigner == nil {
			return Record{}, "", invalidRecord(index, "type_payload")
		}
		revoked := *record.RevokedSigner
		switch revoked.Kind {
		case TeamID:
			if !teamIDPattern.MatchString(revoked.Identifier) {
				return Record{}, "", invalidRecord(index, "team_id")
			}
		case SignerID:
			if !boundedIdentifier(revoked.Identifier, maxSignerIDBytes) {
				return Record{}, "", invalidRecord(index, "signer_id")
			}
		default:
			return Record{}, "", invalidRecord(index, "signer_kind")
		}
		record = Record{Type: RecordRevokedSigner, RevokedSigner: &revoked}
		identity = string(record.Type) + ":" + string(revoked.Kind) + ":" + revoked.Identifier

	case RecordVulnerablePackage:
		if record.VulnerablePackage == nil {
			return Record{}, "", invalidRecord(index, "type_payload")
		}
		pkg := *record.VulnerablePackage
		pkg.Ecosystem = strings.ToLower(pkg.Ecosystem)
		if !boundedMatch(pkg.Ecosystem, maxEcosystemBytes, safeIdentifier) {
			return Record{}, "", invalidRecord(index, "ecosystem")
		}
		if !boundedMatch(pkg.Package, maxPackageBytes, safePackage) ||
			strings.Contains(pkg.Package, "..") {
			return Record{}, "", invalidRecord(index, "package")
		}
		if len(pkg.Constraints) == 0 || len(pkg.Constraints) > maxConstraints {
			return Record{}, "", invalidRecord(index, "constraint_count")
		}
		pkg.Constraints = append([]VersionConstraint(nil), pkg.Constraints...)
		constraintKeys := make(map[string]struct{}, len(pkg.Constraints))
		for _, constraint := range pkg.Constraints {
			if !constraint.Operator.valid() ||
				!boundedMatch(constraint.Version, maxVersionBytes, safeVersion) {
				return Record{}, "", invalidRecord(index, "constraint")
			}
			key := string(constraint.Operator) + ":" + constraint.Version
			if _, exists := constraintKeys[key]; exists {
				return Record{}, "", invalidRecord(index, "duplicate_constraint")
			}
			constraintKeys[key] = struct{}{}
		}
		sort.Slice(pkg.Constraints, func(i, j int) bool {
			left := string(pkg.Constraints[i].Operator) + ":" + pkg.Constraints[i].Version
			right := string(pkg.Constraints[j].Operator) + ":" + pkg.Constraints[j].Version
			return left < right
		})
		record = Record{Type: RecordVulnerablePackage, VulnerablePackage: &pkg}
		identity = string(record.Type) + ":" + pkg.Ecosystem + ":" + pkg.Package

	case RecordSecretPattern:
		if record.SecretPattern == nil {
			return Record{}, "", invalidRecord(index, "type_payload")
		}
		pattern := *record.SecretPattern
		if !boundedIdentifier(pattern.DetectorID, maxDetectorIDBytes) {
			return Record{}, "", invalidRecord(index, "detector_id")
		}
		if len(pattern.Pattern) == 0 ||
			len(pattern.Pattern) > limits.MaxPatternBytes ||
			containsUnsafeControl(pattern.Pattern) {
			return Record{}, "", invalidRecord(index, "pattern_length")
		}
		compiled, err := regexp.Compile(pattern.Pattern)
		if err != nil || compiled.MatchString("") {
			return Record{}, "", invalidRecord(index, "pattern")
		}
		record = Record{Type: RecordSecretPattern, SecretPattern: &pattern}
		identity = string(record.Type) + ":" + pattern.DetectorID

	default:
		return Record{}, "", invalidRecord(index, "record_type")
	}

	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > limits.MaxRecordBytes {
		return Record{}, "", invalidRecord(index, "record_size")
	}
	return record, identity, nil
}

func (operator ConstraintOperator) valid() bool {
	switch operator {
	case ConstraintEqual,
		ConstraintLessThan,
		ConstraintLessThanOrEqual,
		ConstraintGreaterThan,
		ConstraintGreaterThanOrEqual:
		return true
	default:
		return false
	}
}

func boundedIdentifier(value string, limit int) bool {
	return boundedMatch(value, limit, safeIdentifier)
}

func boundedMatch(value string, limit int, pattern *regexp.Regexp) bool {
	return len(value) > 0 && len(value) <= limit && pattern.MatchString(value)
}

func containsUnsafeControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func recordSortKey(record Record) string {
	switch record.Type {
	case RecordMaliciousSHA256:
		return string(record.Type) + ":" + record.MaliciousSHA256.SHA256
	case RecordRevokedSigner:
		return string(record.Type) + ":" +
			string(record.RevokedSigner.Kind) + ":" + record.RevokedSigner.Identifier
	case RecordVulnerablePackage:
		return string(record.Type) + ":" +
			record.VulnerablePackage.Ecosystem + ":" + record.VulnerablePackage.Package
	case RecordSecretPattern:
		return string(record.Type) + ":" + record.SecretPattern.DetectorID
	default:
		return string(record.Type)
	}
}

func canonicalUnsigned(bundle Bundle) ([]byte, error) {
	return json.Marshal(unsignedEnvelope{
		Schema:             bundle.Schema,
		SchemaVersion:      bundle.SchemaVersion,
		BundleID:           bundle.BundleID,
		Sequence:           bundle.Sequence,
		IssuedAt:           bundle.IssuedAt,
		ExpiresAt:          bundle.ExpiresAt,
		MinimumAgentSchema: bundle.MinimumAgentSchema,
		Records:            bundle.Records,
		PayloadSHA256:      bundle.PayloadSHA256,
		KeyID:              bundle.KeyID,
	})
}

func canonicalBundle(bundle Bundle) ([]byte, error) {
	return json.Marshal(bundle)
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func decodeStrict(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidEncoding
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidEncoding
	}
	return nil
}
