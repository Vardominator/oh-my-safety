package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const controllerSchemaVersion = 1

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("controller database path is required")
	}
	if path != ":memory:" {
		if strings.HasPrefix(path, "file:") || strings.IndexByte(path, 0) >= 0 {
			return nil, errors.New("controller database path must be a filesystem path")
		}
		if err := ensureNewPrivateParent(filepath.Dir(path)); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				return nil, errors.New("controller database must be a regular file")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect controller database: %w", err)
		}
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create controller database: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close initialized controller database: %w", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("restrict controller database permissions: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open controller database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) configure() error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = FULL",
		"PRAGMA journal_mode = DELETE",
	} {
		if _, err := store.db.Exec(statement); err != nil {
			return fmt.Errorf("configure controller database: %w", err)
		}
	}
	return nil
}

func (store *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
	token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
	group_name TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	used_at TEXT,
	used_by_device_id TEXT
);

CREATE INDEX IF NOT EXISTS enrollment_tokens_expiry_idx
	ON enrollment_tokens(expires_at);

CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	credential_hash BLOB NOT NULL CHECK(length(credential_hash) = 32),
	name TEXT NOT NULL,
	platform TEXT NOT NULL,
	os_version TEXT NOT NULL,
	agent_version TEXT NOT NULL,
	group_name TEXT NOT NULL,
	enrolled_at TEXT NOT NULL,
	last_seen_at TEXT,
	credential_rotated_at TEXT NOT NULL,
	revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS devices_group_idx
	ON devices(group_name, revoked_at);

CREATE TABLE IF NOT EXISTS policies (
	id TEXT PRIMARY KEY,
	revision INTEGER NOT NULL CHECK(revision > 0),
	document BLOB NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_policy_assignments (
	group_name TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	detector_id TEXT NOT NULL,
	category TEXT NOT NULL,
	severity TEXT NOT NULL,
	state TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	occurrences INTEGER NOT NULL CHECK(occurrences > 0),
	reported_at TEXT NOT NULL,
	PRIMARY KEY(device_id, detector_id, category)
);

CREATE INDEX IF NOT EXISTS findings_state_severity_idx
	ON findings(state, severity, reported_at);

CREATE TABLE IF NOT EXISTS admin_audit (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	actor_id TEXT NOT NULL,
	action TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_id TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS admin_audit_reject_update
BEFORE UPDATE ON admin_audit
BEGIN
	SELECT RAISE(ABORT, 'admin audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS admin_audit_reject_delete
BEFORE DELETE ON admin_audit
BEGIN
	SELECT RAISE(ABORT, 'admin audit is append-only');
END;
`
	transaction, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("begin controller migration: %w", err)
	}
	defer transaction.Rollback()
	var current int
	if err := transaction.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read controller schema version: %w", err)
	}
	if current > controllerSchemaVersion {
		return fmt.Errorf(
			"controller schema version %d is newer than supported version %d",
			current,
			controllerSchemaVersion,
		)
	}
	if current < 1 {
		if _, err := transaction.Exec(schema); err != nil {
			return fmt.Errorf("apply controller schema migration 1: %w", err)
		}
		if _, err := transaction.Exec(
			"INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
			1,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			return fmt.Errorf("record controller schema migration 1: %w", err)
		}
		if _, err := transaction.Exec("PRAGMA user_version = 1"); err != nil {
			return fmt.Errorf("set controller schema version: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit controller migrations: %w", err)
	}
	return nil
}

func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) CreateEnrollmentToken(
	ctx context.Context,
	actorID string,
	group string,
	ttl time.Duration,
	now time.Time,
) (string, time.Time, error) {
	if !validIdentifier(actorID) || !validGroup(group) {
		return "", time.Time{}, ErrInvalidInput
	}
	if ttl < time.Minute || ttl > 7*24*time.Hour {
		return "", time.Time{}, fmt.Errorf("%w: enrollment TTL must be between one minute and seven days", ErrInvalidInput)
	}
	token, tokenHash, err := newCredential()
	if err != nil {
		return "", time.Time{}, err
	}
	now = now.UTC()
	expiresAt := now.Add(ttl)
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("begin enrollment token creation: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO enrollment_tokens (
			token_hash, group_name, expires_at, created_at, created_by
		) VALUES (?, ?, ?, ?, ?)`,
		tokenHash[:],
		group,
		timeText(expiresAt),
		timeText(now),
		actorID,
	); err != nil {
		return "", time.Time{}, fmt.Errorf("store enrollment token: %w", err)
	}
	if err := appendAudit(ctx, transaction, actorID, "enrollment_token.create", "group", group, now); err != nil {
		return "", time.Time{}, err
	}
	if err := transaction.Commit(); err != nil {
		return "", time.Time{}, fmt.Errorf("commit enrollment token creation: %w", err)
	}
	return token, expiresAt, nil
}

func (store *Store) Enroll(
	ctx context.Context,
	token string,
	metadata DeviceMetadata,
	now time.Time,
) (EnrollmentGrant, Device, error) {
	if err := metadata.Validate(); err != nil {
		return EnrollmentGrant{}, Device{}, err
	}
	if token == "" || len(token) > maxBearerTokenBytes {
		return EnrollmentGrant{}, Device{}, ErrUnauthenticated
	}
	tokenHash := sha256.Sum256([]byte(token))
	deviceID, err := newRandomIdentifier()
	if err != nil {
		return EnrollmentGrant{}, Device{}, err
	}
	credential, credentialHash, err := newCredential()
	if err != nil {
		return EnrollmentGrant{}, Device{}, err
	}
	now = now.UTC()
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentGrant{}, Device{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer transaction.Rollback()

	var group string
	err = transaction.QueryRowContext(
		ctx,
		`UPDATE enrollment_tokens
		 SET used_at = ?, used_by_device_id = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		 RETURNING group_name`,
		timeText(now),
		deviceID,
		tokenHash[:],
		timeText(now),
	).Scan(&group)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, Device{}, ErrUnauthenticated
	}
	if err != nil {
		return EnrollmentGrant{}, Device{}, fmt.Errorf("consume enrollment token: %w", err)
	}
	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO devices (
			id, credential_hash, name, platform, os_version, agent_version,
			group_name, enrolled_at, credential_rotated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID,
		credentialHash[:],
		metadata.Name,
		metadata.Platform,
		metadata.OSVersion,
		metadata.AgentVersion,
		group,
		timeText(now),
		timeText(now),
	); err != nil {
		return EnrollmentGrant{}, Device{}, fmt.Errorf("store enrolled device: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentGrant{}, Device{}, fmt.Errorf("commit enrollment: %w", err)
	}
	device := Device{
		ID:                  deviceID,
		Name:                metadata.Name,
		Platform:            metadata.Platform,
		OSVersion:           metadata.OSVersion,
		AgentVersion:        metadata.AgentVersion,
		Group:               group,
		EnrolledAt:          now,
		CredentialRotatedAt: now,
	}
	return EnrollmentGrant{
		DeviceID:         deviceID,
		DeviceCredential: credential,
	}, device, nil
}

func (store *Store) AuthenticateDevice(
	ctx context.Context,
	deviceID string,
	credential string,
) (Device, error) {
	if len(credential) > maxBearerTokenBytes {
		credential = ""
	}
	candidateHash := sha256.Sum256([]byte(credential))
	var storedHash []byte
	var device Device
	var lastSeen, revoked sql.NullString
	var enrolledAt, rotatedAt string
	err := store.db.QueryRowContext(
		ctx,
		`SELECT credential_hash, name, platform, os_version, agent_version,
		        group_name, enrolled_at, last_seen_at, credential_rotated_at, revoked_at
		 FROM devices WHERE id = ?`,
		deviceID,
	).Scan(
		&storedHash,
		&device.Name,
		&device.Platform,
		&device.OSVersion,
		&device.AgentVersion,
		&device.Group,
		&enrolledAt,
		&lastSeen,
		&rotatedAt,
		&revoked,
	)
	found := 1
	if errors.Is(err, sql.ErrNoRows) {
		storedHash = make([]byte, sha256.Size)
		found = 0
	} else if err != nil {
		return Device{}, fmt.Errorf("read device credential: %w", err)
	}
	equal := subtle.ConstantTimeCompare(candidateHash[:], storedHash)
	active := 1
	if revoked.Valid {
		active = 0
	}
	if equal&found&active != 1 {
		return Device{}, ErrUnauthenticated
	}
	device.ID = deviceID
	device.EnrolledAt, err = parseTime(enrolledAt)
	if err != nil {
		return Device{}, err
	}
	device.CredentialRotatedAt, err = parseTime(rotatedAt)
	if err != nil {
		return Device{}, err
	}
	if lastSeen.Valid {
		parsed, err := parseTime(lastSeen.String)
		if err != nil {
			return Device{}, err
		}
		device.LastSeenAt = &parsed
	}
	return device, nil
}

func (store *Store) Heartbeat(
	ctx context.Context,
	deviceID string,
	metadata DeviceMetadata,
	now time.Time,
) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	result, err := store.db.ExecContext(
		ctx,
		`UPDATE devices
		 SET name = ?, platform = ?, os_version = ?, agent_version = ?, last_seen_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		metadata.Name,
		metadata.Platform,
		metadata.OSVersion,
		metadata.AgentVersion,
		timeText(now.UTC()),
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("store device heartbeat: %w", err)
	}
	return requireAffected(result)
}

func (store *Store) RotateDeviceCredential(
	ctx context.Context,
	deviceID string,
	now time.Time,
) (string, error) {
	credential, credentialHash, err := newCredential()
	if err != nil {
		return "", err
	}
	result, err := store.db.ExecContext(
		ctx,
		`UPDATE devices
		 SET credential_hash = ?, credential_rotated_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		credentialHash[:],
		timeText(now.UTC()),
		deviceID,
	)
	if err != nil {
		return "", fmt.Errorf("rotate device credential: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return "", err
	}
	return credential, nil
}

func (store *Store) RevokeDevice(
	ctx context.Context,
	actorID string,
	deviceID string,
	now time.Time,
) error {
	if !validIdentifier(actorID) || !validIdentifier(deviceID) {
		return ErrInvalidInput
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin device revocation: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(
		ctx,
		"UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		timeText(now.UTC()),
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if err := appendAudit(ctx, transaction, actorID, "device.revoke", "device", deviceID, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit device revocation: %w", err)
	}
	return nil
}

func (store *Store) AssignDeviceGroup(
	ctx context.Context,
	actorID string,
	deviceID string,
	group string,
	now time.Time,
) error {
	if !validIdentifier(actorID) || !validIdentifier(deviceID) || !validGroup(group) {
		return ErrInvalidInput
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin device group assignment: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(
		ctx,
		"UPDATE devices SET group_name = ? WHERE id = ?",
		group,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("assign device group: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if err := appendAudit(ctx, transaction, actorID, "device.group.assign", "device", deviceID, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit device group assignment: %w", err)
	}
	return nil
}

func (store *Store) ListDevices(ctx context.Context, limit int) ([]Device, error) {
	limit = boundedLimit(limit, 100, 1_000)
	rows, err := store.db.QueryContext(
		ctx,
		`SELECT id, name, platform, os_version, agent_version, group_name,
		        enrolled_at, last_seen_at, credential_rotated_at, revoked_at
		 FROM devices ORDER BY enrolled_at DESC, id LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var device Device
		var enrolledAt, rotatedAt string
		var lastSeen, revoked sql.NullString
		if err := rows.Scan(
			&device.ID,
			&device.Name,
			&device.Platform,
			&device.OSVersion,
			&device.AgentVersion,
			&device.Group,
			&enrolledAt,
			&lastSeen,
			&rotatedAt,
			&revoked,
		); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		device.EnrolledAt, err = parseTime(enrolledAt)
		if err != nil {
			return nil, err
		}
		device.CredentialRotatedAt, err = parseTime(rotatedAt)
		if err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			parsed, err := parseTime(lastSeen.String)
			if err != nil {
				return nil, err
			}
			device.LastSeenAt = &parsed
		}
		if revoked.Valid {
			parsed, err := parseTime(revoked.String)
			if err != nil {
				return nil, err
			}
			device.RevokedAt = &parsed
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, nil
}

func (store *Store) CreatePolicy(
	ctx context.Context,
	actorID string,
	document PolicyDocument,
	now time.Time,
) error {
	if !validIdentifier(actorID) {
		return ErrInvalidInput
	}
	if err := document.Validate(); err != nil {
		return err
	}
	if document.Revision != 1 {
		return fmt.Errorf("%w: a new policy revision must be 1", ErrInvalidInput)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy creation: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO policies (
			id, revision, document, created_at, updated_at, created_by, updated_by
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		document.ID,
		document.Revision,
		encoded,
		timeText(now.UTC()),
		timeText(now.UTC()),
		actorID,
		actorID,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrConflict
		}
		return fmt.Errorf("store policy: %w", err)
	}
	if err := appendAudit(ctx, transaction, actorID, "policy.create", "policy", document.ID, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit policy creation: %w", err)
	}
	return nil
}

func (store *Store) UpdatePolicy(
	ctx context.Context,
	actorID string,
	document PolicyDocument,
	now time.Time,
) error {
	if !validIdentifier(actorID) {
		return ErrInvalidInput
	}
	if err := document.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy update: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(
		ctx,
		`UPDATE policies
		 SET revision = ?, document = ?, updated_at = ?, updated_by = ?
		 WHERE id = ? AND revision = ?`,
		document.Revision,
		encoded,
		timeText(now.UTC()),
		actorID,
		document.ID,
		document.Revision-1,
	)
	if err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return ErrConflict
	}
	if err := appendAudit(ctx, transaction, actorID, "policy.update", "policy", document.ID, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit policy update: %w", err)
	}
	return nil
}

func (store *Store) DeletePolicy(
	ctx context.Context,
	actorID string,
	policyID string,
	now time.Time,
) error {
	if !validIdentifier(actorID) || !validIdentifier(policyID) {
		return ErrInvalidInput
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy deletion: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", policyID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			return ErrConflict
		}
		return fmt.Errorf("delete policy: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if err := appendAudit(ctx, transaction, actorID, "policy.delete", "policy", policyID, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit policy deletion: %w", err)
	}
	return nil
}

func (store *Store) GetPolicy(ctx context.Context, policyID string) (PolicyDocument, error) {
	if !validIdentifier(policyID) {
		return PolicyDocument{}, ErrInvalidInput
	}
	var encoded []byte
	err := store.db.QueryRowContext(
		ctx,
		"SELECT document FROM policies WHERE id = ?",
		policyID,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyDocument{}, ErrNotFound
	}
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("read policy: %w", err)
	}
	return decodeStoredPolicy(encoded)
}

func (store *Store) ListPolicies(ctx context.Context, limit int) ([]PolicyDocument, error) {
	limit = boundedLimit(limit, 100, 1_000)
	rows, err := store.db.QueryContext(
		ctx,
		"SELECT document FROM policies ORDER BY id LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()
	var policies []PolicyDocument
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		document, err := decodeStoredPolicy(encoded)
		if err != nil {
			return nil, err
		}
		policies = append(policies, document)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}
	return policies, nil
}

func (store *Store) AssignGroupPolicy(
	ctx context.Context,
	actorID string,
	group string,
	policyID string,
	now time.Time,
) error {
	if !validIdentifier(actorID) || !validGroup(group) || !validIdentifier(policyID) {
		return ErrInvalidInput
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin group policy assignment: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO group_policy_assignments (
			group_name, policy_id, updated_at, updated_by
		) VALUES (?, ?, ?, ?)
		ON CONFLICT(group_name) DO UPDATE SET
			policy_id = excluded.policy_id,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
		group,
		policyID,
		timeText(now.UTC()),
		actorID,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			return ErrNotFound
		}
		return fmt.Errorf("assign group policy: %w", err)
	}
	if err := appendAudit(ctx, transaction, actorID, "group.policy.assign", "group", group, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit group policy assignment: %w", err)
	}
	return nil
}

func (store *Store) UnassignGroupPolicy(
	ctx context.Context,
	actorID string,
	group string,
	now time.Time,
) error {
	if !validIdentifier(actorID) || !validGroup(group) {
		return ErrInvalidInput
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin group policy removal: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(
		ctx,
		"DELETE FROM group_policy_assignments WHERE group_name = ?",
		group,
	)
	if err != nil {
		return fmt.Errorf("remove group policy: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if err := appendAudit(ctx, transaction, actorID, "group.policy.remove", "group", group, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit group policy removal: %w", err)
	}
	return nil
}

func (store *Store) PolicyForDevice(
	ctx context.Context,
	deviceID string,
) (PolicyDocument, error) {
	var encoded []byte
	err := store.db.QueryRowContext(
		ctx,
		`SELECT policies.document
		 FROM devices
		 JOIN group_policy_assignments
		   ON group_policy_assignments.group_name = devices.group_name
		 JOIN policies ON policies.id = group_policy_assignments.policy_id
		 WHERE devices.id = ? AND devices.revoked_at IS NULL`,
		deviceID,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyDocument{}, ErrNotFound
	}
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("read device policy: %w", err)
	}
	return decodeStoredPolicy(encoded)
}

func (store *Store) PolicyForGroup(
	ctx context.Context,
	group string,
) (PolicyDocument, error) {
	if !validGroup(group) {
		return PolicyDocument{}, ErrInvalidInput
	}
	var encoded []byte
	err := store.db.QueryRowContext(
		ctx,
		`SELECT policies.document
		 FROM group_policy_assignments
		 JOIN policies ON policies.id = group_policy_assignments.policy_id
		 WHERE group_policy_assignments.group_name = ?`,
		group,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyDocument{}, ErrNotFound
	}
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("read group policy: %w", err)
	}
	return decodeStoredPolicy(encoded)
}

func (store *Store) SyncReport(
	ctx context.Context,
	deviceID string,
	report ReportSync,
	now time.Time,
) error {
	if err := report.Validate(now.UTC()); err != nil {
		return err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin report sync: %w", err)
	}
	defer transaction.Rollback()
	for _, finding := range report.Findings {
		_, err := transaction.ExecContext(
			ctx,
			`INSERT INTO findings (
				device_id, detector_id, category, severity, state, first_seen,
				last_seen, occurrences, reported_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(device_id, detector_id, category) DO UPDATE SET
				severity = excluded.severity,
				state = excluded.state,
				first_seen = excluded.first_seen,
				last_seen = excluded.last_seen,
				occurrences = excluded.occurrences,
				reported_at = excluded.reported_at`,
			deviceID,
			finding.DetectorID,
			finding.Category,
			finding.Severity,
			finding.State,
			timeText(finding.FirstSeen.UTC()),
			timeText(finding.LastSeen.UTC()),
			finding.Occurrences,
			timeText(report.ReportedAt.UTC()),
		)
		if err != nil {
			return fmt.Errorf("store redacted finding: %w", err)
		}
	}
	result, err := transaction.ExecContext(
		ctx,
		"UPDATE devices SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL",
		timeText(now.UTC()),
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("update reporting device heartbeat: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit report sync: %w", err)
	}
	return nil
}

func (store *Store) ListFindings(ctx context.Context, limit int) ([]StoredFinding, error) {
	limit = boundedLimit(limit, 500, 5_000)
	rows, err := store.db.QueryContext(
		ctx,
		`SELECT device_id, detector_id, category, severity, state, first_seen,
		        last_seen, occurrences, reported_at
		 FROM findings ORDER BY reported_at DESC, device_id, detector_id LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list redacted findings: %w", err)
	}
	defer rows.Close()
	var findings []StoredFinding
	for rows.Next() {
		var finding StoredFinding
		var firstSeen, lastSeen, reportedAt string
		if err := rows.Scan(
			&finding.DeviceID,
			&finding.DetectorID,
			&finding.Category,
			&finding.Severity,
			&finding.State,
			&firstSeen,
			&lastSeen,
			&finding.Occurrences,
			&reportedAt,
		); err != nil {
			return nil, fmt.Errorf("scan redacted finding: %w", err)
		}
		finding.FirstSeen, err = parseTime(firstSeen)
		if err != nil {
			return nil, err
		}
		finding.LastSeen, err = parseTime(lastSeen)
		if err != nil {
			return nil, err
		}
		finding.ReportedAt, err = parseTime(reportedAt)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate redacted findings: %w", err)
	}
	return findings, nil
}

func (store *Store) ListAudit(
	ctx context.Context,
	afterSequence int64,
	limit int,
) ([]AuditEntry, error) {
	if afterSequence < 0 {
		return nil, ErrInvalidInput
	}
	limit = boundedLimit(limit, 100, 1_000)
	rows, err := store.db.QueryContext(
		ctx,
		`SELECT sequence, actor_id, action, target_type, target_id, created_at
		 FROM admin_audit WHERE sequence > ? ORDER BY sequence LIMIT ?`,
		afterSequence,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list admin audit: %w", err)
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var createdAt string
		if err := rows.Scan(
			&entry.Sequence,
			&entry.ActorID,
			&entry.Action,
			&entry.TargetType,
			&entry.TargetID,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("scan admin audit: %w", err)
		}
		entry.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin audit: %w", err)
	}
	return entries, nil
}

func appendAudit(
	ctx context.Context,
	transaction *sql.Tx,
	actorID string,
	action string,
	targetType string,
	targetID string,
	now time.Time,
) error {
	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO admin_audit (
			actor_id, action, target_type, target_id, created_at
		) VALUES (?, ?, ?, ?, ?)`,
		actorID,
		action,
		targetType,
		targetID,
		timeText(now.UTC()),
	); err != nil {
		return fmt.Errorf("append admin audit: %w", err)
	}
	return nil
}

func decodeStoredPolicy(encoded []byte) (PolicyDocument, error) {
	var document PolicyDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		return PolicyDocument{}, fmt.Errorf("decode stored policy: %w", err)
	}
	if err := document.Validate(); err != nil {
		return PolicyDocument{}, fmt.Errorf("validate stored policy: %w", err)
	}
	return document, nil
}

func newCredential() (string, [sha256.Size]byte, error) {
	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate credential: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(randomBytes[:])
	tokenHash := sha256.Sum256([]byte(token))
	for index := range randomBytes {
		randomBytes[index] = 0
	}
	return token, tokenHash, nil
}

func newRandomIdentifier() (string, error) {
	var randomBytes [18]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	identifier := base64.RawURLEncoding.EncodeToString(randomBytes[:])
	for index := range randomBytes {
		randomBytes[index] = 0
	}
	return identifier, nil
}

func requireAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected row count: %w", err)
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func timeText(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp: %w", err)
	}
	return parsed, nil
}

func boundedLimit(value, fallback, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func isUniqueConstraint(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "unique constraint") ||
		strings.Contains(lower, "primary key")
}
