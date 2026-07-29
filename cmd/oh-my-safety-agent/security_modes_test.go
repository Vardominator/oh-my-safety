package main

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- required to verify the HIBP k-anonymity request.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/exposure"
	"github.com/Vardominator/oh-my-safety/internal/scanner"
)

const (
	testPassword = "correct horse battery staple for CLI"
	testEmail    = "alice+security@example.com"
	testAPIKey   = "0123456789abcdef0123456789abcdef"
)

func TestSecretScanCLIUsesStablePrivateKeyAndNeverOutputsSecretValues(t *testing.T) {
	root := t.TempDir()
	firstRoot := filepath.Join(root, "first")
	secondRoot := filepath.Join(root, "second")
	if err := os.MkdirAll(firstRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	const secretValue = "c1Q9vT2mX7kP4sN8dR6wF3hJ0zL5bY"
	if err := os.WriteFile(
		filepath.Join(firstRoot, "credentials.env"),
		[]byte("API_KEY="+secretValue+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(secondRoot, "ordinary.txt"),
		[]byte("ordinary local content\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	stateDB := filepath.Join(root, "state", "journal.db")
	arguments := []string{
		"--state-db", stateDB,
		"--scan-secrets", firstRoot,
		"--scan-secrets", secondRoot,
	}
	dependencies := agentDependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, fingerprintKeyBytes)),
	}
	firstOutput := runSecurityCommand(t, arguments, strings.NewReader(""), dependencies)
	if strings.Contains(firstOutput, secretValue) {
		t.Fatalf("secret scan output disclosed matched value: %s", firstOutput)
	}
	var first scanner.SecretResult
	if err := json.Unmarshal([]byte(firstOutput), &first); err != nil {
		t.Fatal(err)
	}
	if first.Schema != scanner.SecretResultSchema ||
		first.SchemaVersion != scanner.SecretResultSchemaVersion ||
		first.ScannerID != scanner.SecretScannerID ||
		len(first.Findings) != 1 ||
		first.Stats.FilesScanned != 2 {
		t.Fatalf("unexpected secret scan result: %#v", first)
	}
	if first.Findings[0].RedactedExcerpt != "api_key = [REDACTED]" ||
		!strings.HasPrefix(first.Findings[0].Fingerprint, "hmac-sha256:") {
		t.Fatalf("finding is not safely redacted: %#v", first.Findings[0])
	}

	keyPath := filepath.Join(filepath.Dir(stateDB), defaultFingerprintKeyName)
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !keyInfo.Mode().IsRegular() ||
		keyInfo.Mode()&os.ModeSymlink != 0 ||
		keyInfo.Mode().Perm() != 0o600 ||
		keyInfo.Size() != fingerprintKeyBytes {
		t.Fatalf("unsafe fingerprint key metadata: %#v", keyInfo)
	}
	if _, err := os.Stat(stateDB); !os.IsNotExist(err) {
		t.Fatalf("local scan unexpectedly created journal: %v", err)
	}

	secondOutput := runSecurityCommand(
		t,
		arguments,
		strings.NewReader(""),
		agentDependencies{
			Random: errorReader{err: errors.New("randomness must not be reused")},
		},
	)
	var second scanner.SecretResult
	if err := json.Unmarshal([]byte(secondOutput), &second); err != nil {
		t.Fatal(err)
	}
	if second.Findings[0].Fingerprint != first.Findings[0].Fingerprint {
		t.Fatalf(
			"persistent key did not preserve fingerprint identity: %q != %q",
			second.Findings[0].Fingerprint,
			first.Findings[0].Fingerprint,
		)
	}
}

func TestSecretScanCLIPreservesDefaultCoverageLimits(t *testing.T) {
	root := t.TempDir()
	oversize := filepath.Join(root, "oversize.txt")
	file, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(scanner.DefaultSecretLimits().MaxFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output := runSecurityCommand(
		t,
		[]string{
			"--state-db", filepath.Join(root, "state", "journal.db"),
			"--scan-secrets", root,
		},
		strings.NewReader(""),
		agentDependencies{
			Random: bytes.NewReader(bytes.Repeat([]byte{0x23}, fingerprintKeyBytes)),
		},
	)
	var result scanner.SecretResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Stats.OversizeSkipped != 1 ||
		len(result.Coverage) != 1 ||
		result.Coverage[0].Code != scanner.CoverageMaxFileBytes ||
		result.Coverage[0].Limit != scanner.DefaultSecretLimits().MaxFileBytes {
		t.Fatalf("CLI changed scanner bounds: %#v", result)
	}
}

func TestSecretScanCLIRejectsUnsafeRootsAndKeyFiles(t *testing.T) {
	root := t.TempDir()
	targetRoot := filepath.Join(root, "target")
	if err := os.Mkdir(targetRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(root, "root-link")
	if err := os.Symlink(targetRoot, rootLink); err != nil {
		t.Fatal(err)
	}
	stateDB := filepath.Join(root, "state", "journal.db")

	rootCases := map[string]string{
		"empty":      "",
		"traversal":  "../outside",
		"root":       string(filepath.Separator),
		"symlink":    rootLink,
		"dash":       "-",
		"whitespace": " " + targetRoot,
	}
	for name, scanRoot := range rootCases {
		t.Run(name, func(t *testing.T) {
			err := runWithDependencies(
				[]string{
					"--state-db", stateDB,
					"--scan-secrets", scanRoot,
				},
				strings.NewReader(""),
				&bytes.Buffer{},
				&bytes.Buffer{},
				agentDependencies{},
			)
			if err == nil {
				t.Fatalf("unsafe root %q accepted", scanRoot)
			}
		})
	}

	keyCases := map[string]func(string){
		"symlink": func(path string) {
			target := path + ".target"
			writeKeyFile(t, target, 0o600, fingerprintKeyBytes)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"permissive": func(path string) {
			writeKeyFile(t, path, 0o644, fingerprintKeyBytes)
		},
		"short": func(path string) {
			writeKeyFile(t, path, 0o600, fingerprintKeyBytes-1)
		},
	}
	for name, prepare := range keyCases {
		t.Run("key_"+name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "fingerprint.key")
			prepare(keyPath)
			var stdout bytes.Buffer
			err := runWithDependencies(
				[]string{
					"--state-db", stateDB,
					"--scan-secrets", targetRoot,
					"--fingerprint-key", keyPath,
				},
				strings.NewReader(""),
				&stdout,
				&bytes.Buffer{},
				agentDependencies{},
			)
			if err == nil {
				t.Fatalf("unsafe key file %s accepted", name)
			}
			if stdout.Len() != 0 {
				t.Fatalf("unsafe key emitted output: %s", stdout.String())
			}
		})
	}
}

func TestExecutableTriageCLIIsRepeatableBoundedAndLocal(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "tool")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	stateDB := filepath.Join(root, "state", "journal.db")
	output := runSecurityCommand(
		t,
		[]string{
			"--state-db", stateDB,
			"--triage-executable", missing,
			"--triage-executable", executable,
		},
		strings.NewReader(""),
		agentDependencies{},
	)
	var result scanner.ExecutableResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != scanner.ExecutableResultSchema ||
		result.SchemaVersion != scanner.ExecutableResultSchemaVersion ||
		len(result.Executables) != 1 ||
		result.Executables[0].Path != executable ||
		result.Stats.FilesConsidered != 2 ||
		result.Stats.MissingSkipped != 1 {
		t.Fatalf("unexpected executable result: %#v", result)
	}
	if _, err := os.Stat(stateDB); !os.IsNotExist(err) {
		t.Fatalf("triage unexpectedly created journal: %v", err)
	}

	oversize := filepath.Join(root, "large-tool")
	file, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(scanner.DefaultExecutableLimits().MaxFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(oversize, 0o755); err != nil {
		t.Fatal(err)
	}
	boundedOutput := runSecurityCommand(
		t,
		[]string{"--triage-executable", oversize},
		strings.NewReader(""),
		agentDependencies{},
	)
	var bounded scanner.ExecutableResult
	if err := json.Unmarshal([]byte(boundedOutput), &bounded); err != nil {
		t.Fatal(err)
	}
	if bounded.Stats.OversizeSkipped != 1 ||
		len(bounded.Coverage) != 1 ||
		bounded.Coverage[0].Limit != scanner.DefaultExecutableLimits().MaxFileBytes {
		t.Fatalf("CLI changed executable scanner bounds: %#v", bounded)
	}
}

func TestExecutableTriageCLIRejectsAmbiguousPaths(t *testing.T) {
	for name, path := range map[string]string{
		"empty":     "",
		"dash":      "-",
		"traversal": "../tool",
		"nul":       "tool\x00other",
	} {
		t.Run(name, func(t *testing.T) {
			err := runWithInput(
				[]string{"--triage-executable", path},
				strings.NewReader(""),
				&bytes.Buffer{},
				&bytes.Buffer{},
			)
			if err == nil {
				t.Fatalf("ambiguous executable path %q accepted", path)
			}
		})
	}
}

func TestPwnedPasswordCLIUsesStdinKAnonymityAndRedactedJSON(t *testing.T) {
	prefix, suffix, fullHash := passwordHashParts(testPassword)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/range/"+prefix {
			t.Errorf("request path = %q, want prefix-only path", request.URL.Path)
		}
		if request.Header.Get("Add-Padding") != "true" {
			t.Error("HIBP padding header missing")
		}
		if strings.Contains(request.RequestURI, testPassword) ||
			strings.Contains(request.RequestURI, fullHash) ||
			strings.Contains(request.RequestURI, suffix) {
			t.Fatalf("request disclosed password-derived material: %q", request.RequestURI)
		}
		_, _ = fmt.Fprintf(writer, "%s:42\n%s:1\n", suffix, strings.Repeat("A", 35))
	}))
	defer server.Close()

	stateDB := filepath.Join(t.TempDir(), "journal.db")
	output := runSecurityCommand(
		t,
		[]string{
			"--state-db", stateDB,
			"--check-pwned-password",
			"--allow-network",
		},
		strings.NewReader(testPassword+"\r\n"),
		agentDependencies{
			PwnedPasswordsHTTP: exposure.HTTPOptions{
				Client:  server.Client(),
				BaseURL: server.URL + "/range",
			},
		},
	)
	if requests.Load() != 1 {
		t.Fatalf("network requests = %d, want 1", requests.Load())
	}
	assertSensitiveStringsAbsent(t, output, testPassword, fullHash, suffix)
	var envelope pwnedPasswordCheckEnvelope
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != pwnedPasswordCheckSchema ||
		envelope.SchemaVersion != securityModeSchemaVersion ||
		envelope.Contract.ID != exposure.AdapterPwnedPasswords ||
		envelope.Result.State != exposure.ResultFound ||
		envelope.Result.PwnedCount != 42 {
		t.Fatalf("unexpected pwned-password envelope: %#v", envelope)
	}
	if _, err := os.Stat(stateDB); !os.IsNotExist(err) {
		t.Fatalf("password check unexpectedly created journal: %v", err)
	}
}

func TestPwnedPasswordCLIRequiresOptInAndHonorsOfflineWithoutNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	dependencies := agentDependencies{
		PwnedPasswordsHTTP: exposure.HTTPOptions{
			Client:  server.Client(),
			BaseURL: server.URL + "/range",
		},
	}
	tests := []struct {
		name      string
		arguments []string
		reason    exposure.UnsupportedReason
	}{
		{
			name:      "disabled",
			arguments: []string{"--check-pwned-password"},
			reason:    exposure.UnsupportedDisabled,
		},
		{
			name: "offline",
			arguments: []string{
				"--check-pwned-password",
				"--allow-network",
				"--offline",
			},
			reason: exposure.UnsupportedOffline,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := runSecurityCommand(
				t,
				test.arguments,
				strings.NewReader(testPassword),
				dependencies,
			)
			var envelope pwnedPasswordCheckEnvelope
			if err := json.Unmarshal([]byte(output), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Result.State != exposure.ResultUnsupported ||
				envelope.Result.Unsupported == nil ||
				envelope.Result.Unsupported.Reason != test.reason {
				t.Fatalf("unexpected gated result: %#v", envelope.Result)
			}
			assertSensitiveStringsAbsent(t, output, testPassword)
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("gated password checks made %d request(s)", requests.Load())
	}
}

func TestPwnedPasswordCLIRejectsUnboundedOrMultipleInputsWithoutEcho(t *testing.T) {
	oversize := strings.Repeat("p", maxPasswordInputBytes+1)
	cases := map[string]io.Reader{
		"empty":      strings.NewReader(""),
		"two values": strings.NewReader("first-private\nsecond-private\n"),
		"oversize":   strings.NewReader(oversize),
		"nul":        strings.NewReader("private\x00password"),
		"invalid utf8": bytes.NewReader([]byte{
			0xff,
		}),
		"reader error": errorReader{err: errors.New("reader-private-detail")},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runWithDependencies(
				[]string{"--check-pwned-password"},
				input,
				&stdout,
				&bytes.Buffer{},
				agentDependencies{},
			)
			if err == nil {
				t.Fatal("invalid password input accepted")
			}
			assertSensitiveStringsAbsent(
				t,
				err.Error(),
				"first-private",
				"second-private",
				oversize,
				"private\x00password",
				"reader-private-detail",
			)
			if stdout.Len() != 0 {
				t.Fatalf("invalid input emitted output: %s", stdout.String())
			}
		})
	}

	err := runWithInput(
		[]string{"--check-pwned-password", testPassword},
		strings.NewReader("ignored"),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("password positional argument accepted")
	}
	assertSensitiveStringsAbsent(t, err.Error(), testPassword)
}

func TestBreachedAccountCLIUsesNamedEnvironmentAndRedactsSensitiveInput(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/account/"+testEmail {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if request.Header.Get("hibp-api-key") != testAPIKey {
			t.Error("HIBP API key header missing")
		}
		if request.URL.Query().Get("truncateResponse") != "false" {
			t.Error("truncateResponse contract missing")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(
			writer,
			`[{"Name":"Example","Title":"Example breach","Domain":"example.com","PwnCount":7}]`,
		)
	}))
	defer server.Close()

	const environmentName = "OMS_TEST_HIBP_KEY"
	dependencies := agentDependencies{
		LookupEnv: func(name string) (string, bool) {
			if name != environmentName {
				t.Fatalf("environment name = %q, want %q", name, environmentName)
			}
			return testAPIKey, true
		},
		BreachedAccountHTTP: exposure.HTTPOptions{
			Client:  server.Client(),
			BaseURL: server.URL + "/account",
		},
	}
	output := runSecurityCommand(
		t,
		[]string{
			"--check-breached-account",
			"--allow-network",
			"--hibp-api-key-env", environmentName,
		},
		strings.NewReader(testEmail+"\n"),
		dependencies,
	)
	if requests.Load() != 1 {
		t.Fatalf("network requests = %d, want 1", requests.Load())
	}
	assertSensitiveStringsAbsent(t, output, testEmail, testAPIKey)
	var envelope breachedAccountCheckEnvelope
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != breachedAccountCheckSchema ||
		envelope.Contract.ID != exposure.AdapterBreachedAccount ||
		envelope.Result.State != exposure.ResultFound ||
		len(envelope.Result.Breaches) != 1 ||
		envelope.Result.Breaches[0].Name != "Example" {
		t.Fatalf("unexpected breached-account envelope: %#v", envelope)
	}
}

func TestBreachedAccountCLIGatesNetworkWithoutRequiringAPIKey(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	dependencies := agentDependencies{
		LookupEnv: func(string) (string, bool) {
			t.Fatal("gated account check read an API key")
			return "", false
		},
		BreachedAccountHTTP: exposure.HTTPOptions{
			Client:  server.Client(),
			BaseURL: server.URL + "/account",
		},
	}
	tests := []struct {
		name      string
		arguments []string
		reason    exposure.UnsupportedReason
	}{
		{
			name:      "disabled",
			arguments: []string{"--check-breached-account"},
			reason:    exposure.UnsupportedDisabled,
		},
		{
			name: "offline",
			arguments: []string{
				"--check-breached-account",
				"--allow-network",
				"--offline",
			},
			reason: exposure.UnsupportedOffline,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := runSecurityCommand(
				t,
				test.arguments,
				strings.NewReader(testEmail),
				dependencies,
			)
			var envelope breachedAccountCheckEnvelope
			if err := json.Unmarshal([]byte(output), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Result.State != exposure.ResultUnsupported ||
				envelope.Result.Unsupported == nil ||
				envelope.Result.Unsupported.Reason != test.reason {
				t.Fatalf("unexpected gated account result: %#v", envelope.Result)
			}
			assertSensitiveStringsAbsent(t, output, testEmail, testAPIKey)
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("gated account checks made %d request(s)", requests.Load())
	}
}

func TestBreachedAccountCLIErrorsNeverEchoKeyOrEmail(t *testing.T) {
	const invalidKey = "private-invalid-HIBP-key-value"
	missingKey := agentDependencies{
		LookupEnv: func(string) (string, bool) {
			return "", false
		},
	}
	invalidKeyDependencies := agentDependencies{
		LookupEnv: func(string) (string, bool) {
			return invalidKey, true
		},
	}
	for name, dependencies := range map[string]agentDependencies{
		"missing": missingKey,
		"invalid": invalidKeyDependencies,
	} {
		t.Run(name, func(t *testing.T) {
			err := runWithDependencies(
				[]string{
					"--check-breached-account",
					"--allow-network",
				},
				strings.NewReader(testEmail),
				&bytes.Buffer{},
				&bytes.Buffer{},
				dependencies,
			)
			if err == nil {
				t.Fatal("invalid API-key configuration accepted")
			}
			assertSensitiveStringsAbsent(t, err.Error(), invalidKey, testEmail)
		})
	}

	const invalidEmail = "private invalid@example.com"
	err := runWithDependencies(
		[]string{
			"--check-breached-account",
			"--allow-network",
		},
		strings.NewReader(invalidEmail),
		&bytes.Buffer{},
		&bytes.Buffer{},
		agentDependencies{
			LookupEnv: func(string) (string, bool) {
				return testAPIKey, true
			},
		},
	)
	if err == nil {
		t.Fatal("invalid email accepted")
	}
	assertSensitiveStringsAbsent(t, err.Error(), invalidEmail, testAPIKey)

	err = runWithDependencies(
		[]string{
			"--check-breached-account",
			"--allow-network",
			"--hibp-api-key-env", "BAD-NAME",
		},
		strings.NewReader(testEmail),
		&bytes.Buffer{},
		&bytes.Buffer{},
		agentDependencies{},
	)
	if err == nil {
		t.Fatal("invalid environment variable name accepted")
	}
	assertSensitiveStringsAbsent(t, err.Error(), testEmail, testAPIKey)
}

func TestExposureContractsCLIIsSecretlessDeterministicAndNetworkFree(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	stateDB := filepath.Join(t.TempDir(), "journal.db")
	output := runSecurityCommand(
		t,
		[]string{
			"--state-db", stateDB,
			"--exposure-contracts",
		},
		strings.NewReader(""),
		agentDependencies{
			LookupEnv: func(string) (string, bool) {
				t.Fatal("contracts mode read an environment secret")
				return "", false
			},
			PwnedPasswordsHTTP: exposure.HTTPOptions{
				Client:  server.Client(),
				BaseURL: server.URL + "/range",
			},
			BreachedAccountHTTP: exposure.HTTPOptions{
				Client:  server.Client(),
				BaseURL: server.URL + "/account",
			},
		},
	)
	if requests.Load() != 0 {
		t.Fatalf("contracts mode made %d request(s)", requests.Load())
	}
	var envelope exposureContractsEnvelope
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != exposureContractsSchema ||
		envelope.SchemaVersion != securityModeSchemaVersion ||
		len(envelope.Contracts) != 2 ||
		envelope.Contracts[0].ID != exposure.AdapterBreachedAccount ||
		envelope.Contracts[1].ID != exposure.AdapterPwnedPasswords {
		t.Fatalf("unexpected contracts envelope: %#v", envelope)
	}
	if _, err := os.Stat(stateDB); !os.IsNotExist(err) {
		t.Fatalf("contracts mode unexpectedly created journal: %v", err)
	}
}

func TestSecurityModesAreMutuallyExclusiveAndAuxiliaryFlagsAreScoped(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "tool")
	if err := os.WriteFile(executable, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"--scan-secrets", root, "--history"},
		{"--scan-secrets", root, "--triage-executable", executable},
		{"--triage-executable", executable, "--findings"},
		{"--check-pwned-password", "--check-breached-account"},
		{"--exposure-contracts", "--history"},
		{"--exposure-contracts", "--allow-network"},
		{"--allow-network"},
		{"--offline"},
		{"--fingerprint-key", filepath.Join(root, "key")},
		{"--hibp-api-key-env", "CUSTOM_KEY"},
		{"--scan-secrets", root, "--limit", "1"},
	}
	for _, arguments := range cases {
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			err := runWithInput(
				arguments,
				strings.NewReader(testPassword),
				&bytes.Buffer{},
				&bytes.Buffer{},
			)
			if err == nil {
				t.Fatalf("conflicting or misplaced flags accepted: %v", arguments)
			}
		})
	}
}

func runSecurityCommand(
	t *testing.T,
	arguments []string,
	stdin io.Reader,
	dependencies agentDependencies,
) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runWithDependencies(
		arguments,
		stdin,
		&stdout,
		&stderr,
		dependencies,
	); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	return stdout.String()
}

func writeKeyFile(t *testing.T, path string, mode os.FileMode, length int) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x41}, length), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func passwordHashParts(password string) (prefix, suffix, full string) {
	digest := sha1.Sum([]byte(password))
	full = strings.ToUpper(hex.EncodeToString(digest[:]))
	return full[:5], full[5:], full
}

func assertSensitiveStringsAbsent(t *testing.T, output string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(output, value) {
			t.Fatalf("sensitive value appears in output: %q in %s", value, output)
		}
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
