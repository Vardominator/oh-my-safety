package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeAdminConfig(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private", "admins.json")

	token, err := InitializeAdminConfig(path, "security-admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != bootstrapTokenBytes*2 {
		t.Fatalf("unexpected token length %d", len(token))
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected config mode %v", info.Mode())
	}
	principals, err := LoadPrincipalSet(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := principals.AuthenticateBearer("Bearer " + token)
	if !ok || principal.ID != "security-admin" || principal.Role != RoleAdmin {
		t.Fatal("generated administrator token did not authenticate")
	}
	if _, err := InitializeAdminConfig(path, "replacement"); err == nil {
		t.Fatal("expected replacement attempt to fail")
	}
}

func TestInitializeAdminConfigRejectsInvalidID(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "admins.json")
	if _, err := InitializeAdminConfig(path, "not an id"); err == nil {
		t.Fatal("expected invalid id to fail")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unexpected config file after failure: %v", err)
	}
}
