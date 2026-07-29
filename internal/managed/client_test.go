package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/controller"
	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/model"
)

var _ FindingSource = (*journal.Store)(nil)

func TestEnrollReadsNamedEnvironmentAndPersistsNoEnrollmentToken(t *testing.T) {
	enrollmentToken := strings.Repeat("enrollment-secret-", 3)
	t.Setenv("OMS_TEST_ENROLLMENT_TOKEN", enrollmentToken)
	_, pinnedKey, _ := testStateMaterial(t, "https://unused.example")
	var received enrollmentRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/v1/agent/enroll" || request.Method != http.MethodPost {
			http.NotFound(writer, request)
			return
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("decode enrollment: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(controller.EnrollmentGrant{
			DeviceID:         "device-enrolled",
			DeviceCredential: strings.Repeat("c", 43),
		})
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	state, err := EnrollFromEnvironment(context.Background(), EnrollmentOptions{
		StatePath:       statePath,
		ControllerURL:   server.URL,
		TokenEnv:        "OMS_TEST_ENROLLMENT_TOKEN",
		PolicyPublicKey: pinnedKey,
		Metadata:        testMetadata(),
		HTTPClient:      server.Client(),
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if received.EnrollmentToken != enrollmentToken {
		t.Fatal("controller did not receive the token from the named environment variable")
	}
	if received.Device != testMetadata() {
		t.Fatalf("enrollment metadata = %#v", received.Device)
	}
	if state.DeviceCredential == "" || state.DeviceID != "device-enrolled" {
		t.Fatalf("enrollment state = %#v", state)
	}
	onDisk, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte(enrollmentToken)) {
		t.Fatal("one-time enrollment token was persisted")
	}
	if _, err := LoadState(statePath); err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	optionsType := reflect.TypeOf(EnrollmentOptions{})
	for index := 0; index < optionsType.NumField(); index++ {
		if strings.EqualFold(optionsType.Field(index).Name, "token") {
			t.Fatal("EnrollmentOptions exposes a plaintext token field")
		}
	}
}

func TestEnrollmentAndAgentErrorsDoNotDiscloseSecrets(t *testing.T) {
	token := strings.Repeat("top-secret-enrollment-token", 2)
	t.Setenv("OMS_TEST_SECRET_TOKEN", token)
	_, pinnedKey, state := testStateMaterial(t, "https://controller.example")
	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return nil, errors.New(
			"malicious transport echoed " +
				request.Header.Get("Authorization") +
				string(body),
		)
	})
	_, err := EnrollFromEnvironment(context.Background(), EnrollmentOptions{
		StatePath:       statePath,
		ControllerURL:   "https://controller.example",
		TokenEnv:        "OMS_TEST_SECRET_TOKEN",
		PolicyPublicKey: pinnedKey,
		Metadata:        testMetadata(),
		HTTPClient:      &http.Client{Transport: transport},
	})
	if err == nil {
		t.Fatal("malicious transport error was not returned")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("enrollment error disclosed the enrollment token")
	}

	state.ControllerURL = "https://controller.example"
	if err := createState(statePath, state); err != nil {
		t.Fatal(err)
	}
	client, err := Open(statePath, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Heartbeat(context.Background(), testMetadata())
	if err == nil {
		t.Fatal("malicious agent transport error was not returned")
	}
	if strings.Contains(err.Error(), state.DeviceCredential) {
		t.Fatal("agent error disclosed the device credential")
	}
}

func TestFetchPolicyRequiresPinnedSignerAndUntamperedStrictEnvelope(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinned := base64.RawStdEncoding.EncodeToString(public)
	envelope := signTestPolicy(t, private, public, testPolicy(true))
	var mutex sync.RWMutex
	var responseBody []byte
	responseBody = mustMarshal(t, envelope)
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/v1/agent/policy" {
			http.NotFound(writer, request)
			return
		}
		mutex.RLock()
		body := append([]byte(nil), responseBody...)
		mutex.RUnlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	state := testEnrollmentState(server.URL, pinned)
	if err := createState(statePath, state); err != nil {
		t.Fatal(err)
	}
	client, err := Open(statePath, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := client.FetchPolicy(context.Background())
	if err != nil {
		t.Fatalf("fetch valid policy: %v", err)
	}
	if policy.ID != "managed-policy" {
		t.Fatalf("policy id = %q", policy.ID)
	}

	tampered := envelope
	tampered.Document.Checks = append([]controller.PolicyCheck(nil), envelope.Document.Checks...)
	tampered.Document.Checks[0].Enabled = false
	mutex.Lock()
	responseBody = mustMarshal(t, tampered)
	mutex.Unlock()
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatal("tampered policy was accepted")
	}

	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner := signTestPolicy(t, otherPrivate, otherPublic, testPolicy(true))
	mutex.Lock()
	responseBody = mustMarshal(t, wrongSigner)
	mutex.Unlock()
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatal("valid policy from an unpinned signer was accepted")
	}

	object := map[string]any{}
	if err := json.Unmarshal(mustMarshal(t, envelope), &object); err != nil {
		t.Fatal(err)
	}
	object["command"] = "run this"
	mutex.Lock()
	responseBody = mustMarshal(t, object)
	mutex.Unlock()
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatal("policy envelope with an unknown command field was accepted")
	}
}

func TestSyncUsesJournalAndSendsOnlyRedactedAllowlist(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinned := base64.RawStdEncoding.EncodeToString(public)
	envelope := signTestPolicy(t, private, public, testPolicy(true))
	var heartbeat controller.DeviceMetadata
	var reportBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("d", 43) ||
			request.Header.Get("X-Device-ID") != "device-123" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/v1/agent/heartbeat":
			if err := json.NewDecoder(request.Body).Decode(&heartbeat); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/agent/policy":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(envelope)
		case "/v1/agent/reports":
			reportBody, _ = io.ReadAll(request.Body)
			var report controller.ReportSync
			if err := json.Unmarshal(reportBody, &report); err != nil {
				t.Errorf("decode report: %v", err)
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(map[string]int{
				"accepted": len(report.Findings),
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "managed", "state.json")
	state := testEnrollmentState(server.URL, pinned)
	if err := createState(statePath, state); err != nil {
		t.Fatal(err)
	}
	client, err := Open(statePath, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	local, err := journal.Open(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	secretMarker := "/Users/employee/private/acme-production-token"
	observation := model.FindingObservation{
		DetectorID: "security.secrets",
		Category:   "credential",
		Title:      "hostname endpoint-01 contains a secret",
		Summary:    secretMarker,
		Severity:   model.SeverityCritical,
		Evidence: []model.Evidence{{
			Type:    "path",
			Ref:     secretMarker,
			Summary: "raw secret evidence",
		}},
		Remediation: &model.Remediation{
			Summary: "run a command",
			Guide:   "rm " + secretMarker,
		},
		Labels: map[string]string{
			"hostname": "endpoint-01",
			"path":     secretMarker,
		},
	}
	event, err := model.NewEvent(
		model.EventFindingObserved,
		"scanner",
		now.Add(-time.Minute),
		now.Add(-time.Minute),
		observation,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.FindingID = "local-sensitive-finding"
	if _, err := local.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	metadata := testMetadata()
	metadata.Name = "endpoint-01"
	result, err := client.Sync(context.Background(), local, metadata, now)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if heartbeat != metadata {
		t.Fatalf("heartbeat metadata = %#v, want %#v", heartbeat, metadata)
	}
	if result.FindingsSent != 1 ||
		result.PolicyID != "managed-policy" ||
		!result.ReportingEnabled {
		t.Fatalf("sync result = %#v", result)
	}
	if len(reportBody) == 0 {
		t.Fatal("report was not submitted")
	}
	for _, forbidden := range []string{
		secretMarker,
		"endpoint-01",
		"title",
		"summary",
		"evidence",
		"labels",
		"path",
		"command",
		"remediation",
		"hostname",
	} {
		if bytes.Contains(bytes.ToLower(reportBody), []byte(strings.ToLower(forbidden))) {
			t.Fatalf("redacted report contains %q: %s", forbidden, reportBody)
		}
	}
	var reportObject struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(reportBody, &reportObject); err != nil {
		t.Fatal(err)
	}
	if len(reportObject.Findings) != 1 {
		t.Fatalf("report findings = %#v", reportObject.Findings)
	}
	allowed := map[string]bool{
		"detector_id": true,
		"category":    true,
		"severity":    true,
		"state":       true,
		"first_seen":  true,
		"last_seen":   true,
		"occurrences": true,
	}
	for field := range reportObject.Findings[0] {
		if !allowed[field] {
			t.Fatalf("report finding contains non-allowlisted field %q", field)
		}
	}
}

func TestRotationPersistsCredentialAndSubsequentRequestsUseIt(t *testing.T) {
	t.Parallel()
	_, pinned, _ := testStateMaterial(t, "https://unused.example")
	oldCredential := strings.Repeat("d", 43)
	newCredential := strings.Repeat("e", 43)
	var observed []string
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		observed = append(observed, request.Header.Get("Authorization"))
		switch request.URL.Path {
		case "/v1/agent/credentials/rotate":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(controller.EnrollmentGrant{
				DeviceID:         "device-123",
				DeviceCredential: newCredential,
			})
		case "/v1/agent/heartbeat":
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "managed", "state.json")
	state := testEnrollmentState(server.URL, pinned)
	state.DeviceCredential = oldCredential
	if err := createState(path, state); err != nil {
		t.Fatal(err)
	}
	client, err := Open(path, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RotateCredential(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := client.Heartbeat(context.Background(), testMetadata()); err != nil {
		t.Fatalf("heartbeat with rotated credential: %v", err)
	}
	if len(observed) != 2 ||
		observed[0] != "Bearer "+oldCredential ||
		observed[1] != "Bearer "+newCredential {
		t.Fatalf("observed authorization headers = %#v", observed)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte(oldCredential)) ||
		!bytes.Contains(onDisk, []byte(newCredential)) {
		t.Fatal("rotated credential was not atomically persisted")
	}
}

func TestResponseBoundsRedirectRefusalAndTimeout(t *testing.T) {
	t.Parallel()
	_, pinned, _ := testStateMaterial(t, "https://unused.example")
	var followed bool
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		followed = true
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(mustMarshal(t, testPolicy(true)))
	}))
	defer redirectTarget.Close()
	mode := "oversized"
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch mode {
		case "oversized":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(bytes.Repeat([]byte(" "), maxPolicyResponseBytes+1))
		case "redirect":
			http.Redirect(writer, request, redirectTarget.URL, http.StatusTemporaryRedirect)
		case "timeout":
			<-request.Context().Done()
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "managed", "state.json")
	if err := createState(path, testEnrollmentState(server.URL, pinned)); err != nil {
		t.Fatal(err)
	}
	client, err := Open(path, &http.Client{
		Transport: server.Client().Transport,
		Timeout:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatalf("oversized response error = %v", err)
	}
	mode = "redirect"
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatal("redirected policy response was accepted")
	}
	if followed {
		t.Fatal("controller redirect was followed")
	}
	mode = "timeout"
	start := time.Now()
	if _, err := client.FetchPolicy(context.Background()); err == nil {
		t.Fatal("timed-out policy request succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("configured managed-client timeout was not enforced")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testEnrollmentState(controllerURL, pinned string) EnrollmentState {
	return EnrollmentState{
		Schema:           StateSchema,
		SchemaVersion:    StateSchemaVersion,
		ControllerURL:    controllerURL,
		DeviceID:         "device-123",
		DeviceCredential: strings.Repeat("d", 43),
		PolicyPublicKey:  pinned,
		EnrolledAt:       time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	}
}

func testMetadata() controller.DeviceMetadata {
	return controller.DeviceMetadata{
		Name:         "endpoint-test",
		Platform:     "linux",
		OSVersion:    "linux-amd64",
		AgentVersion: "test",
	}
}

func testPolicy(reporting bool) controller.PolicyDocument {
	interval := uint32(0)
	if reporting {
		interval = 900
	}
	return controller.PolicyDocument{
		Schema:        controller.PolicySchema,
		SchemaVersion: controller.PolicySchemaVersion,
		ID:            "managed-policy",
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
			Enabled:             reporting,
			SyncIntervalSeconds: interval,
		},
		Remediation: controller.RemediationPrompt,
	}
}

func signTestPolicy(
	t *testing.T,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
	document controller.PolicyDocument,
) controller.SignedPolicy {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return controller.SignedPolicy{
		Schema:           controller.SignedPolicySchema,
		SchemaVersion:    controller.SignedPolicyVersion,
		Document:         document,
		Algorithm:        "Ed25519",
		SigningPublicKey: base64.RawStdEncoding.EncodeToString(public),
		Signature: base64.RawStdEncoding.EncodeToString(
			ed25519.Sign(private, encoded),
		),
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
