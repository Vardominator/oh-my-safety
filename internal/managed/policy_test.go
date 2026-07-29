package managed

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/controller"
)

func TestVerifiedPolicyPersistenceRejectsRollbackAndEquivocation(t *testing.T) {
	t.Parallel()
	private, pinned, _ := testStateMaterial(t, "https://controller.example")
	public := private.Public().(ed25519.PublicKey)
	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	if err := createState(
		statePath,
		testEnrollmentState("https://controller.example", pinned),
	); err != nil {
		t.Fatal(err)
	}
	revisionTwo := testPolicy(true)
	revisionTwo.Revision = 2
	signedRevisionTwo := signTestPolicy(t, private, public, revisionTwo)
	path, err := persistVerifiedPolicy(statePath, signedRevisionTwo)
	if err != nil {
		t.Fatalf("persist revision 2: %v", err)
	}
	if path != PolicyPath(statePath) {
		t.Fatalf("policy path = %q, want %q", path, PolicyPath(statePath))
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("policy mode = %v, want regular 0600", info.Mode())
	}

	revisionOne := revisionTwo
	revisionOne.Revision = 1
	if _, err := persistVerifiedPolicy(
		statePath,
		signTestPolicy(t, private, public, revisionOne),
	); err == nil {
		t.Fatal("lower policy revision was accepted")
	}
	equivocation := revisionTwo
	equivocation.Checks = append([]controller.PolicyCheck(nil), revisionTwo.Checks...)
	equivocation.Checks[0].Enabled = !equivocation.Checks[0].Enabled
	if _, err := persistVerifiedPolicy(
		statePath,
		signTestPolicy(t, private, public, equivocation),
	); err == nil {
		t.Fatal("different content at the same revision was accepted")
	}
	if _, err := persistVerifiedPolicy(statePath, signedRevisionTwo); err != nil {
		t.Fatalf("identical policy at the same revision was rejected: %v", err)
	}
	persisted, err := LoadPolicy(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Revision != 2 || !persisted.Checks[0].Enabled {
		t.Fatalf("protected policy was changed: %#v", persisted)
	}

	revisionThree := revisionTwo
	revisionThree.Revision = 3
	if _, err := persistVerifiedPolicy(
		statePath,
		signTestPolicy(t, private, public, revisionThree),
	); err != nil {
		t.Fatalf("higher policy revision rejected: %v", err)
	}
	persisted, err = LoadPolicy(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Revision != 3 {
		t.Fatalf("persisted revision = %d, want 3", persisted.Revision)
	}

	otherPolicy := testPolicy(true)
	otherPolicy.ID = "other-managed-policy"
	if _, err := persistVerifiedPolicy(
		statePath,
		signTestPolicy(t, private, public, otherPolicy),
	); err != nil {
		t.Fatalf("switch to another policy id: %v", err)
	}
	if _, err := persistVerifiedPolicy(
		statePath,
		signedRevisionTwo,
	); err == nil {
		t.Fatal("rollback was accepted after switching away from and back to a policy id")
	}
	ledgerInfo, err := os.Lstat(policyRevisionLedgerPath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if !ledgerInfo.Mode().IsRegular() || ledgerInfo.Mode().Perm() != 0o600 {
		t.Fatalf("policy revision ledger mode = %v", ledgerInfo.Mode())
	}
}

func TestManagedPolicyRejectsSymlinkAndUnknownFields(t *testing.T) {
	t.Parallel()
	private, pinned, _ := testStateMaterial(t, "https://controller.example")
	public := private.Public().(ed25519.PublicKey)
	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	if err := createState(
		statePath,
		testEnrollmentState("https://controller.example", pinned),
	); err != nil {
		t.Fatal(err)
	}
	path := PolicyPath(statePath)
	target := filepath.Join(filepath.Dir(path), "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(statePath); err == nil {
		t.Fatal("symlink policy was accepted")
	}
	validSigned := signTestPolicy(t, private, public, testPolicy(true))
	if _, err := persistVerifiedPolicy(statePath, validSigned); err == nil {
		t.Fatal("verified policy replaced an unsafe symlink")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var unknownObject map[string]any
	if err := json.Unmarshal(mustMarshal(t, validSigned), &unknownObject); err != nil {
		t.Fatal(err)
	}
	unknownObject["command"] = "whoami"
	unknown := mustMarshal(t, unknownObject)
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(statePath); err == nil {
		t.Fatal("managed policy with unknown command field was accepted")
	}
}

func TestManagedPolicyReverifiesCachedSignatureAndAdvisoryLockRecovers(t *testing.T) {
	t.Parallel()
	private, pinned, _ := testStateMaterial(t, "https://controller.example")
	public := private.Public().(ed25519.PublicKey)
	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	if err := createState(
		statePath,
		testEnrollmentState("https://controller.example", pinned),
	); err != nil {
		t.Fatal(err)
	}
	signed := signTestPolicy(t, private, public, testPolicy(true))
	if _, err := persistVerifiedPolicy(statePath, signed); err != nil {
		t.Fatal(err)
	}
	path := PolicyPath(statePath)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cached controller.SignedPolicy
	if err := json.Unmarshal(encoded, &cached); err != nil {
		t.Fatal(err)
	}
	cached.Document.Checks[0].Enabled = false
	if err := os.WriteFile(path, mustMarshal(t, cached), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(statePath); err == nil {
		t.Fatal("locally tampered cached policy passed signature verification")
	}

	parent := filepath.Dir(statePath)
	release, err := acquirePolicyWriteLock(parent)
	if err != nil {
		t.Fatalf("acquire first policy lock: %v", err)
	}
	if _, err := acquirePolicyWriteLock(parent); err == nil {
		t.Fatal("concurrent advisory policy lock was acquired")
	}
	release()
	if _, err := os.Lstat(filepath.Join(parent, ".managed-policy.lock")); err != nil {
		t.Fatalf("persistent advisory lock file disappeared: %v", err)
	}
	reacquired, err := acquirePolicyWriteLock(parent)
	if err != nil {
		t.Fatalf("reacquire released/stale policy lock: %v", err)
	}
	reacquired()
}
