package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrincipalConfigRequiresMode600AndHashedTokens(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "admins.json")
	plaintext := "admin-secret-that-is-never-written"
	config := principalConfig{
		Schema:        AdminConfigSchema,
		SchemaVersion: AdminConfigVersion,
		Principals: []PrincipalSpec{{
			ID:          "security-admin",
			Role:        RoleAdmin,
			TokenSHA256: HashToken(plaintext),
		}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), plaintext) {
		t.Fatal("admin config contains a plaintext token")
	}
	principals, err := LoadPrincipalSet(path)
	if err != nil {
		t.Fatalf("load mode-600 config: %v", err)
	}
	principal, ok := principals.AuthenticateBearer("Bearer " + plaintext)
	if !ok || principal.ID != "security-admin" || principal.Role != RoleAdmin {
		t.Fatalf("authenticated principal = %#v, %v", principal, ok)
	}
	for _, invalid := range []string{
		"",
		"Bearer",
		"bearer " + plaintext,
		"Bearer wrong",
		"Bearer " + plaintext + " extra",
	} {
		if _, ok := principals.AuthenticateBearer(invalid); ok {
			t.Fatalf("unexpected authentication for %q", invalid)
		}
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrincipalSet(path); err == nil {
		t.Fatal("mode-644 admin config was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	withPlaintextField := `{
		"schema":"` + AdminConfigSchema + `",
		"schema_version":1,
		"principals":[{
			"id":"security-admin",
			"role":"admin",
			"token_sha256":"` + HashToken(plaintext) + `",
			"token":"` + plaintext + `"
		}]
	}`
	if err := os.WriteFile(path, []byte(withPlaintextField), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrincipalSet(path); err == nil {
		t.Fatal("plaintext token field was accepted")
	}
}

func TestPrincipalSetRejectsAmbiguityAndRequiresAdmin(t *testing.T) {
	t.Parallel()
	hash := HashToken("same-token")
	testCases := []struct {
		name  string
		specs []PrincipalSpec
	}{
		{
			name: "no admin",
			specs: []PrincipalSpec{{
				ID: "viewer", Role: RoleViewer, TokenSHA256: HashToken("viewer"),
			}},
		},
		{
			name: "duplicate id",
			specs: []PrincipalSpec{
				{ID: "same", Role: RoleAdmin, TokenSHA256: HashToken("one")},
				{ID: "same", Role: RoleViewer, TokenSHA256: HashToken("two")},
			},
		},
		{
			name: "duplicate token hash",
			specs: []PrincipalSpec{
				{ID: "admin", Role: RoleAdmin, TokenSHA256: hash},
				{ID: "viewer", Role: RoleViewer, TokenSHA256: hash},
			},
		},
		{
			name: "invalid hash",
			specs: []PrincipalSpec{{
				ID: "admin", Role: RoleAdmin, TokenSHA256: "plaintext",
			}},
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPrincipalSet(testCase.specs); err == nil {
				t.Fatal("invalid principal set was accepted")
			}
		})
	}
}

func TestSigningKeyPersistsAndDetectsTampering(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys", "policy-signing.json")
	first, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("signing key mode = %o, want 600", got)
	}
	document := validPolicy("workstations", 1)
	signed, err := first.Sign(document)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	if err := VerifySignedPolicy(signed); err != nil {
		t.Fatalf("verify policy: %v", err)
	}

	second, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	if !reflect.DeepEqual(first.publicKey, second.publicKey) {
		t.Fatal("signing public key changed after restart")
	}
	restartedSignature, err := second.Sign(document)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature != restartedSignature.Signature {
		t.Fatal("persistent key produced a different deterministic signature")
	}

	tampered := signed
	tampered.Document.Checks = append([]PolicyCheck(nil), signed.Document.Checks...)
	tampered.Document.Checks[0].Enabled = !tampered.Document.Checks[0].Enabled
	if err := VerifySignedPolicy(tampered); err == nil {
		t.Fatal("tampered policy signature was accepted")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(path); err == nil {
		t.Fatal("mode-644 signing key was accepted")
	}
}

func validPolicy(id string, revision uint64) PolicyDocument {
	return PolicyDocument{
		Schema:        PolicySchema,
		SchemaVersion: PolicySchemaVersion,
		ID:            id,
		Revision:      revision,
		Checks: []PolicyCheck{
			{ID: "security.secrets", Enabled: true},
			{ID: "security.persistence", Enabled: true},
		},
		Profile: "managed-workstation",
		Cadence: CadencePolicy{
			ScanIntervalSeconds: 900,
			JitterSeconds:       60,
		},
		Reporting: ReportingPolicy{
			Enabled:             true,
			SyncIntervalSeconds: 900,
		},
		Remediation: RemediationPrompt,
	}
}
