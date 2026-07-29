package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Vardominator/oh-my-safety/internal/controller"
	"github.com/Vardominator/oh-my-safety/internal/managed"
)

func TestManagedAgentEnrollSyncAndRotateModes(t *testing.T) {
	enrollmentToken := strings.Repeat("one-time-enrollment-token-", 2)
	t.Setenv("OMS_CLI_ENROLLMENT_TOKEN", enrollmentToken)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinned := base64.RawStdEncoding.EncodeToString(public)
	policy := controller.PolicyDocument{
		Schema:        controller.PolicySchema,
		SchemaVersion: controller.PolicySchemaVersion,
		ID:            "managed-workstations",
		Revision:      1,
		Checks: []controller.PolicyCheck{{
			ID:      "security.secrets",
			Enabled: true,
		}},
		Profile: "managed-workstation",
		Cadence: controller.CadencePolicy{
			ScanIntervalSeconds: 900,
			JitterSeconds:       30,
		},
		Reporting: controller.ReportingPolicy{
			Enabled:             true,
			SyncIntervalSeconds: 900,
		},
		Remediation: controller.RemediationPrompt,
	}
	encodedPolicy, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	signed := controller.SignedPolicy{
		Schema:           controller.SignedPolicySchema,
		SchemaVersion:    controller.SignedPolicyVersion,
		Document:         policy,
		Algorithm:        "Ed25519",
		SigningPublicKey: pinned,
		Signature: base64.RawStdEncoding.EncodeToString(
			ed25519.Sign(private, encodedPolicy),
		),
	}
	oldCredential := strings.Repeat("o", 43)
	newCredential := strings.Repeat("n", 43)
	var mutex sync.Mutex
	var receivedEnrollmentToken string
	var authorizations []string
	var report controller.ReportSync
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/v1/agent/enroll":
			var body struct {
				EnrollmentToken string                    `json:"enrollment_token"`
				Device          controller.DeviceMetadata `json:"device"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode enrollment: %v", err)
			}
			mutex.Lock()
			receivedEnrollmentToken = body.EnrollmentToken
			mutex.Unlock()
			if body.Device.Name != "employee-laptop" ||
				body.Device.Platform == "" ||
				body.Device.AgentVersion != agentVersion {
				t.Errorf("local enrollment metadata = %#v", body.Device)
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(controller.EnrollmentGrant{
				DeviceID:         "device-cli",
				DeviceCredential: oldCredential,
			})
		case "/v1/agent/heartbeat":
			mutex.Lock()
			authorizations = append(
				authorizations,
				request.Header.Get("Authorization"),
			)
			mutex.Unlock()
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/agent/policy":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(signed)
		case "/v1/agent/reports":
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Errorf("decode report: %v", err)
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(map[string]int{
				"accepted": len(report.Findings),
			})
		case "/v1/agent/credentials/rotate":
			mutex.Lock()
			authorizations = append(
				authorizations,
				request.Header.Get("Authorization"),
			)
			mutex.Unlock()
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(controller.EnrollmentGrant{
				DeviceID:         "device-cli",
				DeviceCredential: newCredential,
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	statePath := filepath.Join(root, "private", "managed.json")
	stateDB := filepath.Join(root, "private", "journal.db")
	var enrollOutput bytes.Buffer
	if err := run(
		[]string{
			"--state-db", stateDB,
			"--managed-enroll",
			"--managed-state", statePath,
			"--controller-url", server.URL,
			"--controller-policy-key", pinned,
			"--enrollment-token-env", "OMS_CLI_ENROLLMENT_TOKEN",
			"--device-name", "employee-laptop",
		},
		&enrollOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("managed enrollment: %v", err)
	}
	mutex.Lock()
	actualEnrollmentToken := receivedEnrollmentToken
	mutex.Unlock()
	if actualEnrollmentToken != enrollmentToken {
		t.Fatal("managed enrollment did not use the named environment variable")
	}
	for _, secret := range []string{enrollmentToken, oldCredential} {
		if strings.Contains(enrollOutput.String(), secret) {
			t.Fatalf("managed enrollment output disclosed a credential: %s", enrollOutput.String())
		}
	}
	var enrollmentResult managedEnrollmentResult
	if err := json.Unmarshal(enrollOutput.Bytes(), &enrollmentResult); err != nil {
		t.Fatal(err)
	}
	if !enrollmentResult.Enrolled ||
		enrollmentResult.Schema != managedEnrollmentSchema ||
		enrollmentResult.DeviceID != "device-cli" {
		t.Fatalf("managed enrollment result = %#v", enrollmentResult)
	}
	info, err := os.Lstat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("managed state mode = %v", info.Mode())
	}

	var syncOutput bytes.Buffer
	if err := run(
		[]string{
			"--state-db", stateDB,
			"--managed-sync",
			"--managed-state", statePath,
		},
		&syncOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("managed sync: %v", err)
	}
	if strings.Contains(syncOutput.String(), oldCredential) {
		t.Fatal("managed sync output disclosed the device credential")
	}
	var syncResult managedSyncResult
	if err := json.Unmarshal(syncOutput.Bytes(), &syncResult); err != nil {
		t.Fatal(err)
	}
	if syncResult.Schema != managedSyncSchema ||
		syncResult.Result.PolicyID != policy.ID ||
		syncResult.Result.PolicyRevision != policy.Revision ||
		syncResult.Result.PolicyPath != managed.PolicyPath(statePath) ||
		!syncResult.Result.ReportingEnabled {
		t.Fatalf("managed sync result = %#v", syncResult)
	}
	if report.Schema != controller.ReportSchema ||
		report.SchemaVersion != controller.ReportSchemaVersion {
		t.Fatalf("managed report = %#v", report)
	}
	policyInfo, err := os.Lstat(managed.PolicyPath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if !policyInfo.Mode().IsRegular() || policyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("cached policy mode = %v", policyInfo.Mode())
	}
	var flatPolicy bytes.Buffer
	if err := run(
		[]string{
			"--state-db", stateDB,
			"--managed-policy",
			"--managed-state", statePath,
		},
		&flatPolicy,
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("emit managed policy: %v", err)
	}
	wantFlatPolicy := strings.Join([]string{
		"schema\tio.oh-my-safety/managed-policy-flat\t1",
		"policy_id\tmanaged-workstations",
		"revision\t1",
		"profile\tmanaged-workstation",
		"cadence_scan_interval_seconds\t900",
		"cadence_jitter_seconds\t30",
		"reporting_enabled\ttrue",
		"reporting_sync_interval_seconds\t900",
		"remediation\tprompt",
		"check\tsecurity.secrets\ttrue",
		"",
	}, "\n")
	if flatPolicy.String() != wantFlatPolicy {
		t.Fatalf(
			"flat managed policy mismatch\nwant:\n%s\ngot:\n%s",
			wantFlatPolicy,
			flatPolicy.String(),
		)
	}
	for _, secret := range []string{enrollmentToken, oldCredential, newCredential} {
		if strings.Contains(flatPolicy.String(), secret) {
			t.Fatal("flat managed policy disclosed credential material")
		}
	}

	var rotateOutput bytes.Buffer
	if err := run(
		[]string{
			"--state-db", stateDB,
			"--managed-rotate-credential",
			"--managed-state", statePath,
		},
		&rotateOutput,
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("managed credential rotation: %v", err)
	}
	for _, secret := range []string{oldCredential, newCredential} {
		if strings.Contains(rotateOutput.String(), secret) {
			t.Fatalf("managed rotation output disclosed a credential: %s", rotateOutput.String())
		}
	}
	persisted, err := managed.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DeviceCredential != newCredential {
		t.Fatal("managed rotation did not persist the new credential")
	}
	mutex.Lock()
	observedAuthorization := append([]string(nil), authorizations...)
	mutex.Unlock()
	if len(observedAuthorization) != 2 ||
		observedAuthorization[0] != "Bearer "+oldCredential ||
		observedAuthorization[1] != "Bearer "+oldCredential {
		t.Fatalf("managed authorization headers = %#v", observedAuthorization)
	}
}

func TestManagedAgentFlagsAreScopedAndNeverAcceptTokenOnArgv(t *testing.T) {
	t.Parallel()
	stateDB := filepath.Join(t.TempDir(), "journal.db")
	testCases := [][]string{
		{"--state-db", stateDB, "--managed-sync", "--managed-rotate-credential"},
		{"--state-db", stateDB, "--managed-policy", "--managed-sync"},
		{"--state-db", stateDB, "--controller-url", "https://controller.example"},
		{"--state-db", stateDB, "--controller-policy-key", "invalid"},
		{"--state-db", stateDB, "--enrollment-token-env", "TOKEN_ENV"},
		{"--state-db", stateDB, "--device-name", "endpoint"},
		{"--state-db", stateDB, "--managed-sync", "--controller-url", "https://controller.example"},
		{"--state-db", stateDB, "--managed-enroll"},
		{"--state-db", stateDB, "--enrollment-token=must-not-be-an-argv-option"},
	}
	for _, arguments := range testCases {
		arguments := arguments
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatalf("invalid managed arguments accepted: %v", arguments)
			}
		})
	}
}

func TestManagedEnrollmentHelpAndDeviceNameErrorsAreNonDisclosing(t *testing.T) {
	t.Setenv(defaultEnrollmentTokenEnv, strings.Repeat("e", 43))
	var help bytes.Buffer
	err := run([]string{"--help"}, &bytes.Buffer{}, &help)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}
	for _, flagName := range []string{
		"-managed-enroll",
		"-managed-sync",
		"-managed-policy",
		"-managed-rotate-credential",
		"-managed-state",
		"-controller-url",
		"-controller-policy-key",
		"-enrollment-token-env",
		"-device-name",
	} {
		if !strings.Contains(help.String(), flagName) {
			t.Fatalf("managed help omits %s", flagName)
		}
	}
	if strings.Contains(help.String(), "\n  -enrollment-token ") {
		t.Fatal("CLI help exposes a plaintext enrollment-token argv flag")
	}
	if !strings.Contains(help.String(), defaultEnrollmentTokenEnv) {
		t.Fatal("CLI help does not document the default enrollment-token environment")
	}

	sensitiveName := strings.Repeat("private-device-name", 32)
	public := make([]byte, ed25519.PublicKeySize)
	err = run(
		[]string{
			"--state-db", filepath.Join(t.TempDir(), "journal.db"),
			"--managed-enroll",
			"--controller-url", "https://controller.example",
			"--controller-policy-key",
			base64.RawStdEncoding.EncodeToString(public),
			"--device-name", sensitiveName,
		},
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("oversized device name was accepted")
	}
	if strings.Contains(err.Error(), sensitiveName) {
		t.Fatal("device-name validation error reflected the supplied device name")
	}
}
