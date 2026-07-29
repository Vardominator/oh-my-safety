package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/controller"
)

func TestBootstrapInitializesControllerSecrets(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	adminPath := filepath.Join(directory, "admins.json")
	signingPath := filepath.Join(directory, "signing.json")
	var output bytes.Buffer
	var errors bytes.Buffer

	err := run(context.Background(), []string{
		"-bootstrap",
		"-admin-id", "security-admin",
		"-admin-config", adminPath,
		"-signing-key", signingPath,
	}, &output, &errors)
	if err != nil {
		t.Fatal(err)
	}
	var result controller.BootstrapResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != "io.oh-my-safety/controller-bootstrap" ||
		result.SchemaVersion != 1 ||
		result.AdminID != "security-admin" ||
		result.AdminToken == "" ||
		result.SigningPublicKey == "" {
		t.Fatalf("unexpected bootstrap result: %+v", result)
	}
	for _, path := range []string{adminPath, signingPath} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s has unsafe mode %v", path, info.Mode())
		}
	}
	principals, err := controller.LoadPrincipalSet(adminPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := principals.AuthenticateBearer("Bearer " + result.AdminToken); !ok {
		t.Fatal("bootstrap token did not authenticate")
	}
}

func TestBootstrapRefusesServerFlags(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), []string{
		"-bootstrap",
		"-admin-config", filepath.Join(t.TempDir(), "admins.json"),
		"-signing-key", filepath.Join(t.TempDir(), "signing.json"),
		"-listen", "127.0.0.1:8080",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected mixed bootstrap/server flags to fail")
	}
}
