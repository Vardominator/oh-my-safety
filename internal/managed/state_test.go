package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentStateIsMode600AtomicAndRejectsSymlinks(t *testing.T) {
	t.Parallel()
	_, publicKey, state := testStateMaterial(t, "https://controller.example")
	path := filepath.Join(t.TempDir(), "managed", "enrollment.json")
	state.PolicyPublicKey = publicKey
	if err := createState(path, state); err != nil {
		t.Fatalf("create state: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, want regular 0600", info.Mode())
	}
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded != state {
		t.Fatalf("loaded state = %#v, want %#v", loaded, state)
	}
	if err := createState(path, EnrollmentState{}); err == nil {
		t.Fatal("existing state was overwritten")
	}

	updated := state
	updated.DeviceCredential = strings.Repeat("b", 43)
	if err := replaceState(path, updated); err != nil {
		t.Fatalf("replace state: %v", err)
	}
	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DeviceCredential != updated.DeviceCredential {
		t.Fatal("state replacement did not persist credential")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("mode-644 state was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(filepath.Dir(path), "symlink.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(symlink); err == nil {
		t.Fatal("symlink state was accepted")
	}
	if err := replaceState(symlink, updated); err == nil {
		t.Fatal("symlink state was replaced")
	}
}

func TestEnrollmentStateRejectsUnknownFieldsAndPublicDirectories(t *testing.T) {
	t.Parallel()
	_, publicKey, state := testStateMaterial(t, "https://controller.example")
	state.PolicyPublicKey = publicKey
	directory := t.TempDir()
	publicDirectory := filepath.Join(directory, "public")
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createState(filepath.Join(publicDirectory, "state.json"), state); err == nil {
		t.Fatal("state was written into a group/world-accessible directory")
	}

	path := filepath.Join(directory, "unknown.json")
	object := map[string]any{}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["token"] = "must-not-be-accepted"
	encoded, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}

func TestControllerURLRequiresHTTPSExceptLoopback(t *testing.T) {
	t.Parallel()
	accepted := map[string]string{
		"https://controller.example":  "https://controller.example",
		"https://controller.example/": "https://controller.example",
		"http://127.0.0.1:8080":       "http://127.0.0.1:8080",
		"http://[::1]:8080":           "http://[::1]:8080",
		"http://localhost:8080":       "http://localhost:8080",
	}
	for input, expected := range accepted {
		actual, err := validateControllerURL(input)
		if err != nil {
			t.Fatalf("%q rejected: %v", input, err)
		}
		if actual != expected {
			t.Fatalf("canonical URL = %q, want %q", actual, expected)
		}
	}
	for _, input := range []string{
		"http://controller.example",
		"http://192.0.2.20:8080",
		"http://0.0.0.0:8080",
		"http://localhost",
		"ftp://controller.example",
		"https://user:password@controller.example",
		"https://controller.example/path",
		"https://controller.example?token=secret",
		"https://controller.example#fragment",
	} {
		if _, err := validateControllerURL(input); err == nil {
			t.Fatalf("unsafe controller URL %q was accepted", input)
		}
	}
}

func testStateMaterial(
	t *testing.T,
	controllerURL string,
) (ed25519.PrivateKey, string, EnrollmentState) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic := base64.RawStdEncoding.EncodeToString(public)
	return private, encodedPublic, EnrollmentState{
		Schema:           StateSchema,
		SchemaVersion:    StateSchemaVersion,
		ControllerURL:    controllerURL,
		DeviceID:         "device-123",
		DeviceCredential: strings.Repeat("a", 43),
		PolicyPublicKey:  encodedPublic,
		EnrolledAt:       time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	}
}
