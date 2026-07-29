package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollmentIsExpiringOneTimeAndConcurrentSafe(t *testing.T) {
	t.Parallel()
	store, err := OpenStore(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	expiring, _, err := store.CreateEnrollmentToken(
		ctx,
		"admin",
		"engineering",
		time.Minute,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Enroll(
		ctx,
		expiring,
		testDeviceMetadata("expired"),
		now.Add(time.Minute),
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("enroll at expiration error = %v, want authentication failure", err)
	}

	oneTimeToken, _, err := store.CreateEnrollmentToken(
		ctx,
		"admin",
		"engineering",
		time.Hour,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 24
	var successful atomic.Int32
	grants := make(chan EnrollmentGrant, attempts)
	var group sync.WaitGroup
	for index := 0; index < attempts; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			grant, _, err := store.Enroll(
				ctx,
				oneTimeToken,
				testDeviceMetadata("concurrent-device"),
				now.Add(time.Second),
			)
			switch {
			case err == nil:
				successful.Add(1)
				grants <- grant
			case errors.Is(err, ErrUnauthenticated):
			default:
				t.Errorf("concurrent enrollment %d: %v", index, err)
			}
		}(index)
	}
	group.Wait()
	close(grants)
	if got := successful.Load(); got != 1 {
		t.Fatalf("successful concurrent enrollments = %d, want 1", got)
	}
	grant := <-grants
	if grant.DeviceCredential == "" || grant.DeviceID == "" {
		t.Fatalf("incomplete enrollment grant: %#v", grant)
	}
	if _, _, err := store.Enroll(
		ctx,
		oneTimeToken,
		testDeviceMetadata("reuse"),
		now.Add(2*time.Second),
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("reused token error = %v, want authentication failure", err)
	}

	var storedTokenHash, storedCredentialHash []byte
	if err := store.db.QueryRow(
		"SELECT token_hash FROM enrollment_tokens WHERE used_by_device_id = ?",
		grant.DeviceID,
	).Scan(&storedTokenHash); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(
		"SELECT credential_hash FROM devices WHERE id = ?",
		grant.DeviceID,
	).Scan(&storedCredentialHash); err != nil {
		t.Fatal(err)
	}
	expectedTokenHash := sha256.Sum256([]byte(oneTimeToken))
	expectedCredentialHash := sha256.Sum256([]byte(grant.DeviceCredential))
	if !bytes.Equal(storedTokenHash, expectedTokenHash[:]) ||
		!bytes.Equal(storedCredentialHash, expectedCredentialHash[:]) {
		t.Fatal("stored credential digests do not match SHA-256 hashes")
	}
	if bytes.Contains(storedTokenHash, []byte(oneTimeToken)) ||
		bytes.Contains(storedCredentialHash, []byte(grant.DeviceCredential)) {
		t.Fatal("plaintext credential material was stored")
	}
}

func TestDeviceCredentialRotationAndRevocation(t *testing.T) {
	t.Parallel()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	now := time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC)
	grant := enrollTestDevice(t, store, now, "operations")

	if _, err := store.AuthenticateDevice(ctx, grant.DeviceID, grant.DeviceCredential); err != nil {
		t.Fatalf("authenticate initial credential: %v", err)
	}
	rotated, err := store.RotateDeviceCredential(ctx, grant.DeviceID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate credential: %v", err)
	}
	if rotated == "" || rotated == grant.DeviceCredential {
		t.Fatal("credential rotation did not produce a new credential")
	}
	if _, err := store.AuthenticateDevice(
		ctx,
		grant.DeviceID,
		grant.DeviceCredential,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old credential authentication error = %v", err)
	}
	if _, err := store.AuthenticateDevice(ctx, grant.DeviceID, rotated); err != nil {
		t.Fatalf("authenticate rotated credential: %v", err)
	}
	if err := store.RevokeDevice(
		ctx,
		"admin",
		grant.DeviceID,
		now.Add(2*time.Minute),
	); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := store.AuthenticateDevice(
		ctx,
		grant.DeviceID,
		rotated,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked device authentication error = %v", err)
	}
}

func TestAuditIsAppendOnlyAtDatabaseBoundary(t *testing.T) {
	t.Parallel()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 29, 14, 0, 0, 0, time.UTC)
	if _, _, err := store.CreateEnrollmentToken(
		context.Background(),
		"admin",
		"engineering",
		time.Hour,
		now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(
		"UPDATE admin_audit SET actor_id = 'attacker' WHERE sequence = 1",
	); err == nil {
		t.Fatal("admin audit update unexpectedly succeeded")
	}
	if _, err := store.db.Exec(
		"DELETE FROM admin_audit WHERE sequence = 1",
	); err == nil {
		t.Fatal("admin audit delete unexpectedly succeeded")
	}
	entries, err := store.ListAudit(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 ||
		entries[0].ActorID != "admin" ||
		entries[0].Action != "enrollment_token.create" {
		t.Fatalf("audit entries after tampering attempts = %#v", entries)
	}
	var migrationCount int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
	).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 1 {
		t.Fatalf("schema migration count = %d, want 1", migrationCount)
	}
}

func TestStorePersistsInventoryPoliciesAndCredentialsAcrossRestart(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "controller.db")
	ctx := context.Background()
	now := time.Date(2026, 7, 29, 15, 0, 0, 0, time.UTC)
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := enrollTestDevice(t, store, now, "engineering")
	document := validPolicy("engineering-policy", 1)
	if err := store.CreatePolicy(ctx, "operator", document, now); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignGroupPolicy(
		ctx,
		"operator",
		"engineering",
		document.ID,
		now,
	); err != nil {
		t.Fatal(err)
	}
	report := ReportSync{
		Schema:        ReportSchema,
		SchemaVersion: ReportSchemaVersion,
		ReportedAt:    now,
		Findings: []RedactedFinding{{
			DetectorID:  "security.secrets",
			Category:    "credential",
			Severity:    "critical",
			State:       "open",
			FirstSeen:   now.Add(-time.Hour),
			LastSeen:    now,
			Occurrences: 2,
		}},
	}
	if err := store.SyncReport(ctx, grant.DeviceID, report, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if _, err := restarted.AuthenticateDevice(
		ctx,
		grant.DeviceID,
		grant.DeviceCredential,
	); err != nil {
		t.Fatalf("authenticate after restart: %v", err)
	}
	persistedPolicy, err := restarted.PolicyForDevice(ctx, grant.DeviceID)
	if err != nil {
		t.Fatalf("policy after restart: %v", err)
	}
	if persistedPolicy.ID != document.ID || persistedPolicy.Revision != 1 {
		t.Fatalf("persisted policy = %#v", persistedPolicy)
	}
	findings, err := restarted.ListFindings(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Occurrences != 2 {
		t.Fatalf("persisted findings = %#v", findings)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %o, want 600", got)
	}
}

func enrollTestDevice(
	t *testing.T,
	store *Store,
	now time.Time,
	group string,
) EnrollmentGrant {
	t.Helper()
	token, _, err := store.CreateEnrollmentToken(
		context.Background(),
		"admin",
		group,
		time.Hour,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := store.Enroll(
		context.Background(),
		token,
		testDeviceMetadata("test-device"),
		now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func testDeviceMetadata(name string) DeviceMetadata {
	return DeviceMetadata{
		Name:         name,
		Platform:     "linux",
		OSVersion:    "Ubuntu 24.04",
		AgentVersion: "1.0.0",
	}
}
