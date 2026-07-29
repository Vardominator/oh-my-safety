package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

const (
	testAdminToken    = "test-admin-token-with-enough-entropy"
	testOperatorToken = "test-operator-token-with-enough-entropy"
	testViewerToken   = "test-viewer-token-with-enough-entropy"
)

type httpFixture struct {
	store   *Store
	server  *Server
	handler http.Handler
	now     time.Time
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	principals, err := NewPrincipalSet([]PrincipalSpec{
		{ID: "admin", Role: RoleAdmin, TokenSHA256: HashToken(testAdminToken)},
		{ID: "operator", Role: RoleOperator, TokenSHA256: HashToken(testOperatorToken)},
		{ID: "viewer", Role: RoleViewer, TokenSHA256: HashToken(testViewerToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "signing.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, principals, signer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 29, 16, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	return &httpFixture{
		store:   store,
		server:  server,
		handler: server.Handler(),
		now:     now,
	}
}

func (fixture *httpFixture) request(
	t *testing.T,
	method string,
	path string,
	token string,
	deviceID string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if deviceID != "" {
		request.Header.Set("X-Device-ID", deviceID)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestRBACAndNonDisclosingAuthenticationErrors(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t)

	viewerRead := fixture.request(
		t, http.MethodGet, "/v1/admin/devices", testViewerToken, "", nil,
	)
	if viewerRead.Code != http.StatusOK {
		t.Fatalf("viewer list devices status = %d, body %s", viewerRead.Code, viewerRead.Body)
	}
	enrollmentBody := []byte(`{"group":"engineering","ttl_seconds":3600}`)
	viewerWrite := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/enrollment-tokens",
		testViewerToken,
		"",
		enrollmentBody,
	)
	if viewerWrite.Code != http.StatusForbidden {
		t.Fatalf("viewer write status = %d, want 403", viewerWrite.Code)
	}
	operatorWrite := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/enrollment-tokens",
		testOperatorToken,
		"",
		enrollmentBody,
	)
	if operatorWrite.Code != http.StatusCreated {
		t.Fatalf("operator write status = %d, body %s", operatorWrite.Code, operatorWrite.Body)
	}
	operatorAudit := fixture.request(
		t, http.MethodGet, "/v1/admin/audit", testOperatorToken, "", nil,
	)
	if operatorAudit.Code != http.StatusForbidden {
		t.Fatalf("operator audit status = %d, want 403", operatorAudit.Code)
	}
	adminAudit := fixture.request(
		t, http.MethodGet, "/v1/admin/audit", testAdminToken, "", nil,
	)
	if adminAudit.Code != http.StatusOK {
		t.Fatalf("admin audit status = %d, body %s", adminAudit.Code, adminAudit.Body)
	}

	var expectedBody string
	for index, authorization := range []string{
		"",
		"Bearer wrong",
		"bearer " + testAdminToken,
		"Bearer " + testAdminToken + " extra",
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/devices", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("invalid authorization %d status = %d", index, recorder.Code)
		}
		if index == 0 {
			expectedBody = recorder.Body.String()
		} else if recorder.Body.String() != expectedBody {
			t.Fatalf(
				"authentication response disclosed failure type: %q vs %q",
				recorder.Body.String(),
				expectedBody,
			)
		}
		if strings.Contains(recorder.Body.String(), testAdminToken) {
			t.Fatal("authentication response contains token")
		}
	}
}

func TestAgentJourneyPolicyReportRotationAndRevocation(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t)
	document := validPolicy("managed", 1)
	if err := fixture.store.CreatePolicy(
		context.Background(),
		"operator",
		document,
		fixture.now,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.AssignGroupPolicy(
		context.Background(),
		"operator",
		"engineering",
		document.ID,
		fixture.now,
	); err != nil {
		t.Fatal(err)
	}

	createToken := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/enrollment-tokens",
		testOperatorToken,
		"",
		[]byte(`{"group":"engineering","ttl_seconds":3600}`),
	)
	if createToken.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", createToken.Code, createToken.Body)
	}
	var tokenResponse struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.Unmarshal(createToken.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	enrollBody, err := json.Marshal(enrollmentRequest{
		EnrollmentToken: tokenResponse.EnrollmentToken,
		Device:          testDeviceMetadata("employee-laptop"),
	})
	if err != nil {
		t.Fatal(err)
	}
	enroll := fixture.request(
		t, http.MethodPost, "/v1/agent/enroll", "", "", enrollBody,
	)
	if enroll.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", enroll.Code, enroll.Body)
	}
	var grant EnrollmentGrant
	if err := json.Unmarshal(enroll.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	reuse := fixture.request(
		t, http.MethodPost, "/v1/agent/enroll", "", "", enrollBody,
	)
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("reused enrollment token status = %d", reuse.Code)
	}

	policyResponse := fixture.request(
		t,
		http.MethodGet,
		"/v1/agent/policy",
		grant.DeviceCredential,
		grant.DeviceID,
		nil,
	)
	if policyResponse.Code != http.StatusOK {
		t.Fatalf("fetch policy: %d %s", policyResponse.Code, policyResponse.Body)
	}
	var signed SignedPolicy
	if err := json.Unmarshal(policyResponse.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedPolicy(signed); err != nil {
		t.Fatalf("verify fetched policy: %v", err)
	}

	report := ReportSync{
		Schema:        ReportSchema,
		SchemaVersion: ReportSchemaVersion,
		ReportedAt:    fixture.now,
		Findings: []RedactedFinding{{
			DetectorID:  "security.secrets",
			Category:    "credential",
			Severity:    model.SeverityCritical,
			State:       model.FindingOpen,
			FirstSeen:   fixture.now.Add(-time.Hour),
			LastSeen:    fixture.now,
			Occurrences: 3,
		}},
	}
	reportBody, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportResponse := fixture.request(
		t,
		http.MethodPost,
		"/v1/agent/reports",
		grant.DeviceCredential,
		grant.DeviceID,
		reportBody,
	)
	if reportResponse.Code != http.StatusAccepted {
		t.Fatalf("sync report: %d %s", reportResponse.Code, reportResponse.Body)
	}
	rotation := fixture.request(
		t,
		http.MethodPost,
		"/v1/agent/credentials/rotate",
		grant.DeviceCredential,
		grant.DeviceID,
		nil,
	)
	if rotation.Code != http.StatusOK {
		t.Fatalf("rotate credential: %d %s", rotation.Code, rotation.Body)
	}
	var rotated EnrollmentGrant
	if err := json.Unmarshal(rotation.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	oldCredential := fixture.request(
		t,
		http.MethodGet,
		"/v1/agent/policy",
		grant.DeviceCredential,
		grant.DeviceID,
		nil,
	)
	if oldCredential.Code != http.StatusUnauthorized {
		t.Fatalf("old credential status = %d", oldCredential.Code)
	}
	revoke := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/devices/"+grant.DeviceID+"/revoke",
		testAdminToken,
		"",
		nil,
	)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke device: %d %s", revoke.Code, revoke.Body)
	}
	revokedCredential := fixture.request(
		t,
		http.MethodGet,
		"/v1/agent/policy",
		rotated.DeviceCredential,
		grant.DeviceID,
		nil,
	)
	if revokedCredential.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential status = %d", revokedCredential.Code)
	}
}

func TestStrictSchemasRejectCommandsAndSensitiveReportFields(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t)
	grant := enrollTestDevice(t, fixture.store, fixture.now, "engineering")

	policyMap := marshalObject(t, validPolicy("closed-contract", 1))
	for _, forbidden := range []string{"command", "script", "payload", "arguments"} {
		copyMap := cloneObject(policyMap)
		copyMap[forbidden] = "curl https://attacker.invalid"
		response := fixture.request(
			t,
			http.MethodPost,
			"/v1/admin/policies",
			testOperatorToken,
			"",
			mustJSON(t, copyMap),
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("policy field %q status = %d, body %s", forbidden, response.Code, response.Body)
		}
	}
	nestedPolicy := cloneObject(policyMap)
	nestedPolicy["checks"] = []map[string]any{{
		"id":      "security.secrets",
		"enabled": true,
		"script":  "rm -rf /",
	}}
	nestedResponse := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/policies",
		testOperatorToken,
		"",
		mustJSON(t, nestedPolicy),
	)
	if nestedResponse.Code != http.StatusBadRequest {
		t.Fatalf("nested script field status = %d", nestedResponse.Code)
	}

	report := map[string]any{
		"schema":         ReportSchema,
		"schema_version": ReportSchemaVersion,
		"reported_at":    fixture.now,
		"findings": []map[string]any{{
			"detector_id": "security.secrets",
			"category":    "credential",
			"severity":    "critical",
			"state":       "open",
			"first_seen":  fixture.now.Add(-time.Minute),
			"last_seen":   fixture.now,
			"occurrences": 1,
		}},
	}
	for _, forbidden := range []string{
		"evidence", "path", "command", "raw_summary", "summary",
	} {
		altered := cloneObject(report)
		findings := altered["findings"].([]map[string]any)
		finding := make(map[string]any, len(findings[0])+1)
		for key, value := range findings[0] {
			finding[key] = value
		}
		finding[forbidden] = "/home/employee/private.txt"
		altered["findings"] = []map[string]any{finding}
		response := fixture.request(
			t,
			http.MethodPost,
			"/v1/agent/reports",
			grant.DeviceCredential,
			grant.DeviceID,
			mustJSON(t, altered),
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("report field %q status = %d, body %s", forbidden, response.Code, response.Body)
		}
		if strings.Contains(response.Body.String(), "/home/employee") {
			t.Fatalf("error response reflected sensitive field %q", forbidden)
		}
	}
	validResponse := fixture.request(
		t,
		http.MethodPost,
		"/v1/agent/reports",
		grant.DeviceCredential,
		grant.DeviceID,
		mustJSON(t, report),
	)
	if validResponse.Code != http.StatusAccepted {
		t.Fatalf("valid redacted report: %d %s", validResponse.Code, validResponse.Body)
	}
	list := fixture.request(
		t,
		http.MethodGet,
		"/v1/admin/findings",
		testViewerToken,
		"",
		nil,
	)
	if list.Code != http.StatusOK {
		t.Fatalf("list findings: %d %s", list.Code, list.Body)
	}
	lower := strings.ToLower(list.Body.String())
	for _, forbidden := range []string{
		"evidence", `"path"`, `"command"`, "raw_summary", `"summary"`, "/home/employee",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("findings response contains forbidden data marker %q: %s", forbidden, list.Body)
		}
	}
}

func TestPolicyAndReportContractsHaveNoArbitraryPayloadSurface(t *testing.T) {
	t.Parallel()
	assertJSONFields(t, reflect.TypeOf(PolicyDocument{}), []string{
		"cadence", "checks", "id", "profile", "remediation", "reporting",
		"revision", "schema", "schema_version",
	})
	assertJSONFields(t, reflect.TypeOf(PolicyCheck{}), []string{"enabled", "id"})
	assertJSONFields(t, reflect.TypeOf(RedactedFinding{}), []string{
		"category", "detector_id", "first_seen", "last_seen", "occurrences",
		"severity", "state",
	})
	assertJSONFields(t, reflect.TypeOf(ReportSync{}), []string{
		"findings", "reported_at", "schema", "schema_version",
	})
	for _, endpoint := range EndpointSummary() {
		lower := strings.ToLower(endpoint)
		if strings.Contains(lower, "command") ||
			strings.Contains(lower, "execute") ||
			strings.Contains(lower, "script") {
			t.Fatalf("command-capable endpoint exposed: %s", endpoint)
		}
	}
	for _, filename := range []string{
		"auth.go", "server.go", "signing.go", "store.go", "types.go",
	} {
		source, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{
			`"os/exec"`, "exec.Command(", "exec.CommandContext(",
			"http.Client{", "net.Dial(", "net.Dialer{",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains outbound/command primitive %q", filename, forbidden)
			}
		}
	}
}

func TestUnknownFieldsBodyLimitsAndSecurityHeaders(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t)
	unknown := fixture.request(
		t,
		http.MethodPost,
		"/v1/admin/enrollment-tokens",
		testOperatorToken,
		"",
		[]byte(`{"group":"engineering","ttl_seconds":3600,"token":"plaintext"}`),
	)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", unknown.Code)
	}
	oversizedRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/admin/enrollment-tokens",
		strings.NewReader(strings.Repeat(" ", int(defaultJSONBodyLimit)+1)),
	)
	oversizedRequest.Header.Set("Authorization", "Bearer "+testOperatorToken)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	oversized := httptest.NewRecorder()
	fixture.handler.ServeHTTP(oversized, oversizedRequest)
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, body %s", oversized.Code, oversized.Body)
	}

	notFound := fixture.request(t, http.MethodGet, "/missing", "", "", nil)
	if notFound.Header().Get("X-Content-Type-Options") != "nosniff" ||
		notFound.Header().Get("Cache-Control") != "no-store" ||
		notFound.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers = %#v", notFound.Header())
	}
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("missing route status = %d", notFound.Code)
	}
}

func TestListenTLSGateAndHTTPServerLimits(t *testing.T) {
	t.Parallel()
	for _, address := range []string{
		"127.0.0.1:8443",
		"[::1]:8443",
		"localhost:8443",
	} {
		if err := ValidateListenConfiguration(address, "", ""); err != nil {
			t.Fatalf("loopback %s rejected: %v", address, err)
		}
	}
	for _, address := range []string{
		":8443",
		"0.0.0.0:8443",
		"[::]:8443",
		"192.0.2.10:8443",
		"controller.example:8443",
	} {
		if err := ValidateListenConfiguration(address, "", ""); err == nil {
			t.Fatalf("non-loopback %s accepted without TLS", address)
		}
		if err := ValidateListenConfiguration(address, "cert.pem", "key.pem"); err != nil {
			t.Fatalf("non-loopback %s rejected with TLS: %v", address, err)
		}
	}
	if err := ValidateListenConfiguration(
		"127.0.0.1:8443",
		"cert.pem",
		"",
	); err == nil {
		t.Fatal("partial TLS configuration was accepted")
	}
	if err := ValidateListenConfiguration("127.0.0.1", "", ""); err == nil {
		t.Fatal("listen address without port was accepted")
	}
	httpServer := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if httpServer.ReadHeaderTimeout <= 0 ||
		httpServer.ReadTimeout <= 0 ||
		httpServer.WriteTimeout <= 0 ||
		httpServer.IdleTimeout <= 0 ||
		httpServer.MaxHeaderBytes <= 0 ||
		httpServer.TLSConfig == nil {
		t.Fatalf("unsafe HTTP server limits: %#v", httpServer)
	}
}

func assertJSONFields(t *testing.T, valueType reflect.Type, expected []string) {
	t.Helper()
	var actual []string
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			actual = append(actual, tag)
		}
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s JSON fields = %v, want %v", valueType, actual, expected)
	}
}

func marshalObject(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded := mustJSON(t, value)
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func cloneObject(original map[string]any) map[string]any {
	cloned := make(map[string]any, len(original)+1)
	for key, value := range original {
		cloned[key] = value
	}
	return cloned
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
