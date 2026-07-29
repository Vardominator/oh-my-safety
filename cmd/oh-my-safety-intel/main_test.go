package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/intel"
)

var cliTestTime = time.Date(2026, 7, 29, 15, 0, 0, 0, time.UTC)

func testApplication(output *bytes.Buffer) application {
	return application{
		stdout: output,
		now:    func() time.Time { return cliTestTime },
		random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	}
}

func runCommand(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	var output bytes.Buffer
	err := testApplication(&output).run(arguments)
	return output.String(), err
}

func generateTestKey(t *testing.T, directory string) (string, string) {
	t.Helper()
	privatePath := filepath.Join(directory, "private-key.json")
	trustPath := filepath.Join(directory, "trust-store.json")
	if _, err := runCommand(
		t,
		"keygen",
		"--key-id", "release-2026",
		"--private-key", privatePath,
		"--trust-store", trustPath,
	); err != nil {
		t.Fatalf("keygen error = %v", err)
	}
	return privatePath, trustPath
}

func writeUnsignedBundle(t *testing.T, path string) {
	t.Helper()
	bundle := unsignedBundle{
		BundleID:           "production",
		Sequence:           1,
		IssuedAt:           cliTestTime.Add(-time.Hour),
		ExpiresAt:          cliTestTime.Add(time.Hour),
		MinimumAgentSchema: 1,
		Records: []intel.Record{
			{
				Type: intel.RecordMaliciousSHA256,
				MaliciousSHA256: &intel.MaliciousSHA256Record{
					SHA256: strings.Repeat("a", 64),
				},
			},
			{
				Type: intel.RecordSecretPattern,
				SecretPattern: &intel.SecretDetectorPatternRecord{
					DetectorID: "example-token",
					Pattern:    `token_[A-Za-z0-9]{20,40}`,
				},
			},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestKeygenCreatesLoadableMode600FilesAndRefusesOverwrite(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private-key.json")
	trustPath := filepath.Join(directory, "trust-store.json")
	output, err := runCommand(
		t,
		"keygen",
		"--key-id", "release-2026",
		"--private-key", privatePath,
		"--trust-store", trustPath,
	)
	if err != nil {
		t.Fatalf("keygen error = %v", err)
	}
	var status keygenOutput
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("keygen output is not JSON: %v", err)
	}
	if status.Command != "keygen" || status.KeyID != "release-2026" {
		t.Fatalf("keygen output = %+v", status)
	}
	assertFileMode(t, privatePath, 0o600)
	assertFileMode(t, trustPath, 0o600)
	if _, err := intel.LoadTrustStore(trustPath); err != nil {
		t.Fatalf("generated trust store is invalid: %v", err)
	}
	keyID, privateKey, err := loadPrivateKey(privatePath)
	if err != nil || keyID != "release-2026" || len(privateKey) == 0 {
		t.Fatalf("generated private key is invalid: key=%q err=%v", keyID, err)
	}

	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"keygen",
		"--key-id", "release-2026",
		"--private-key", privatePath,
		"--trust-store", trustPath,
	); !errors.Is(err, errRefuseOverwrite) {
		t.Fatalf("second keygen error = %v, want refuse overwrite", err)
	}
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("keygen modified an existing private key")
	}
}

func TestOfflineLifecycleSignVerifyInstallCurrent(t *testing.T) {
	directory := t.TempDir()
	privatePath, trustPath := generateTestKey(t, directory)
	unsignedPath := filepath.Join(directory, "unsigned.json")
	signedPath := filepath.Join(directory, "signed.json")
	installDirectory := filepath.Join(directory, "installed")
	writeUnsignedBundle(t, unsignedPath)

	signJSON, err := runCommand(
		t,
		"sign",
		"--input", unsignedPath,
		"--private-key", privatePath,
		"--output", signedPath,
	)
	if err != nil {
		t.Fatalf("sign error = %v", err)
	}
	var signedStatus signOutput
	if err := json.Unmarshal([]byte(signJSON), &signedStatus); err != nil {
		t.Fatal(err)
	}
	if signedStatus.Bundle.RecordCount != 2 || signedStatus.Bundle.KeyID != "release-2026" {
		t.Fatalf("sign output = %+v", signedStatus)
	}
	assertFileMode(t, signedPath, 0o600)

	verifyJSON, err := runCommand(
		t,
		"verify",
		"--bundle", signedPath,
		"--trust-store", trustPath,
	)
	if err != nil {
		t.Fatalf("verify error = %v", err)
	}
	var verifiedStatus verifyOutput
	if err := json.Unmarshal([]byte(verifyJSON), &verifiedStatus); err != nil {
		t.Fatal(err)
	}
	if !verifiedStatus.Valid || verifiedStatus.Bundle.PayloadSHA256 == "" {
		t.Fatalf("verify output = %+v", verifiedStatus)
	}

	installJSON, err := runCommand(
		t,
		"install",
		"--bundle", signedPath,
		"--trust-store", trustPath,
		"--dir", installDirectory,
	)
	if err != nil {
		t.Fatalf("install error = %v", err)
	}
	var installedStatus installOutput
	if err := json.Unmarshal([]byte(installJSON), &installedStatus); err != nil {
		t.Fatal(err)
	}
	if !installedStatus.Installed || installedStatus.Replay {
		t.Fatalf("install output = %+v", installedStatus)
	}

	currentJSON, err := runCommand(
		t,
		"current",
		"--dir", installDirectory,
		"--trust-store", trustPath,
	)
	if err != nil {
		t.Fatalf("current error = %v", err)
	}
	var current currentOutput
	if err := json.Unmarshal([]byte(currentJSON), &current); err != nil {
		t.Fatal(err)
	}
	if current.Metadata.Sequence != 1 ||
		current.Bundle.RecordCount != 2 ||
		len(current.Records) != 2 {
		t.Fatalf("current output = %+v", current)
	}

	replayJSON, err := runCommand(
		t,
		"install",
		"--bundle", signedPath,
		"--trust-store", trustPath,
		"--dir", installDirectory,
	)
	if err != nil {
		t.Fatalf("replay install error = %v", err)
	}
	var replay installOutput
	if err := json.Unmarshal([]byte(replayJSON), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Installed || !replay.Replay {
		t.Fatalf("replay install output = %+v", replay)
	}
}

func TestSensitiveFilesRequireMode600AndInputsRejectSymlinks(t *testing.T) {
	directory := t.TempDir()
	privatePath, trustPath := generateTestKey(t, directory)
	unsignedPath := filepath.Join(directory, "unsigned.json")
	signedPath := filepath.Join(directory, "signed.json")
	writeUnsignedBundle(t, unsignedPath)

	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"sign",
		"--input", unsignedPath,
		"--private-key", privatePath,
		"--output", signedPath,
	); !errors.Is(err, errSensitiveMode) {
		t.Fatalf("sign with mode-0644 key error = %v", err)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := runCommand(
		t,
		"sign",
		"--input", unsignedPath,
		"--private-key", privatePath,
		"--output", signedPath,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(trustPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"verify",
		"--bundle", signedPath,
		"--trust-store", trustPath,
	); !errors.Is(err, intel.ErrInsecurePermissions) {
		t.Fatalf("verify with mode-0644 trust store error = %v", err)
	}

	link := filepath.Join(directory, "bundle-link.json")
	if err := os.Symlink(signedPath, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(trustPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"verify",
		"--bundle", link,
		"--trust-store", trustPath,
	); !errors.Is(err, errUnsafeLocalFile) {
		t.Fatalf("verify symlink error = %v", err)
	}
}

func TestSignRejectsUnknownCommandFieldsWithoutEchoAndBoundsInput(t *testing.T) {
	directory := t.TempDir()
	privatePath, _ := generateTestKey(t, directory)
	maliciousPath := filepath.Join(directory, "malicious.json")
	outputPath := filepath.Join(directory, "signed.json")
	malicious := `{"bundle_id":"production","sequence":1,` +
		`"issued_at":"2026-07-29T14:00:00Z","expires_at":"2026-07-29T16:00:00Z",` +
		`"minimum_agent_schema":1,"records":[],"command":"do-not-echo-this"}`
	if err := os.WriteFile(maliciousPath, []byte(malicious), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runCommand(
		t,
		"sign",
		"--input", maliciousPath,
		"--private-key", privatePath,
		"--output", outputPath,
	)
	if !errors.Is(err, errInvalidJSON) {
		t.Fatalf("sign malicious input error = %v", err)
	}
	if strings.Contains(err.Error(), "do-not-echo-this") {
		t.Fatalf("safe error echoed input content: %v", err)
	}
	if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected input created an output: %v", err)
	}

	oversizedPath := filepath.Join(directory, "oversized.json")
	oversized := bytes.Repeat([]byte(" "), int(intel.DefaultLimits().MaxBundleBytes)+1)
	if err := os.WriteFile(oversizedPath, oversized, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"sign",
		"--input", oversizedPath,
		"--private-key", privatePath,
		"--output", outputPath,
	); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("sign oversized input error = %v", err)
	}
}

func TestSignRefusesToOverwriteOutput(t *testing.T) {
	directory := t.TempDir()
	privatePath, _ := generateTestKey(t, directory)
	unsignedPath := filepath.Join(directory, "unsigned.json")
	outputPath := filepath.Join(directory, "signed.json")
	writeUnsignedBundle(t, unsignedPath)
	if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"sign",
		"--input", unsignedPath,
		"--private-key", privatePath,
		"--output", outputPath,
	); !errors.Is(err, errRefuseOverwrite) {
		t.Fatalf("sign overwrite error = %v", err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "preserve" {
		t.Fatal("sign modified an existing output")
	}
}

func TestKeygenDoesNotLeavePrivateKeyWhenTrustPathExists(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.json")
	trustPath := filepath.Join(directory, "trust.json")
	if err := os.WriteFile(trustPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(
		t,
		"keygen",
		"--key-id", "release-2026",
		"--private-key", privatePath,
		"--trust-store", trustPath,
	); !errors.Is(err, errRefuseOverwrite) {
		t.Fatalf("keygen error = %v", err)
	}
	if _, err := os.Lstat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keygen left a private key behind: %v", err)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
	}
}
