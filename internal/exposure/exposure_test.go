package exposure

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const validTestAPIKey = "00000000000000000000000000000000"

func TestPwnedPasswordsSuccessUsesKAnonymityAndPadding(t *testing.T) {
	const password = "correct horse battery staple"
	prefix, suffix, fullHash := testPasswordHash(password)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/range/"+prefix {
			t.Errorf("path = %q, want prefix-only path", request.URL.Path)
		}
		if request.Header.Get("Add-Padding") != "true" {
			t.Errorf("Add-Padding = %q, want true", request.Header.Get("Add-Padding"))
		}
		if strings.Contains(request.RequestURI, password) ||
			strings.Contains(request.RequestURI, fullHash) ||
			strings.Contains(request.RequestURI, suffix) {
			t.Errorf("request discloses password or more than the hash prefix: %q", request.RequestURI)
		}
		fmt.Fprintf(writer, "%s:42\r\n%s:0\r\n", strings.ToLower(suffix), strings.Repeat("F", 35))
	}))
	defer server.Close()

	client := testPwnedPasswordsClient(t, server, 0)
	result, err := client.Check(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != ResultFound || result.PwnedCount != 42 || result.Unsupported != nil {
		t.Fatalf("unexpected result: %#v", result)
	}
	assertNoSecrets(t, result, password, fullHash, suffix)
}

func TestPwnedPasswordsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(writer, "%s:12\n", strings.Repeat("A", 35))
	}))
	defer server.Close()

	result, err := testPwnedPasswordsClient(t, server, 0).
		Check(context.Background(), "a password not in the response")
	if err != nil {
		t.Fatal(err)
	}
	if result.State != ResultNotFound || result.PwnedCount != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPwnedPasswordsRejectsMalformedResponses(t *testing.T) {
	const password = "malformed-response-secret"
	_, suffix, _ := testPasswordHash(password)
	tests := map[string]string{
		"empty":          "",
		"short suffix":   "ABC:1\n",
		"non hex suffix": strings.Repeat("Z", 35) + ":1\n",
		"bad count":      strings.Repeat("A", 35) + ":many\n",
		"extra colon":    strings.Repeat("A", 35) + ":1:2\n",
		"duplicate":      suffix + ":1\n" + suffix + ":2\n",
	}
	for name, responseBody := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, responseBody)
			}))
			defer server.Close()

			_, err := testPwnedPasswordsClient(t, server, 0).
				Check(context.Background(), password)
			assertError(t, err, ErrorResponse, 0, false, 0)
			assertNoSecrets(t, err, password, suffix)
		})
	}
}

func TestPwnedPasswordsRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("A", 65))
	}))
	defer server.Close()

	_, err := testPwnedPasswordsClient(t, server, 64).
		Check(context.Background(), "oversized-password-secret")
	assertError(t, err, ErrorResponse, 0, false, 0)
}

func TestPwnedPasswordsCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	client := testPwnedPasswordsClient(t, server, 0)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Check(ctx, "cancel-me")
		result <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		assertError(t, err, ErrorCanceled, 0, false, 0)
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request did not return")
	}
}

func TestHTTPStatusRetrySemantics(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		retryAfter string
		retryable  bool
		wantAfter  time.Duration
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, retryAfter: "7"},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "7", retryable: true, wantAfter: 7 * time.Second},
		{name: "bounded retry", status: http.StatusTooManyRequests, retryAfter: "999999", retryable: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, retryable: true},
		{name: "redirect", status: http.StatusFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var redirected atomic.Bool
			redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				redirected.Store(true)
			}))
			defer redirectTarget.Close()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.retryAfter != "" {
					writer.Header().Set("Retry-After", test.retryAfter)
				}
				if test.status == http.StatusFound {
					writer.Header().Set("Location", redirectTarget.URL)
				}
				writer.WriteHeader(test.status)
			}))
			defer server.Close()

			_, err := testPwnedPasswordsClient(t, server, 0).
				Check(context.Background(), "status-secret")
			assertError(t, err, ErrorStatus, test.status, test.retryable, test.wantAfter)
			if redirected.Load() {
				t.Fatal("adapter followed a redirect")
			}
		})
	}
}

func TestAccessPoliciesReturnTypedUnsupportedWithoutNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	policies := []struct {
		name   string
		policy AccessPolicy
		reason UnsupportedReason
	}{
		{name: "disabled", policy: AccessPolicy{}, reason: UnsupportedDisabled},
		{name: "offline", policy: AccessPolicy{Enabled: true, Offline: true}, reason: UnsupportedOffline},
	}
	for _, test := range policies {
		t.Run(test.name, func(t *testing.T) {
			passwordClient, err := NewPwnedPasswordsClient(PwnedPasswordsConfig{
				Policy: test.policy,
				HTTP:   HTTPOptions{BaseURL: server.URL + "/range"},
			})
			if err != nil {
				t.Fatal(err)
			}
			passwordResult, err := passwordClient.Check(context.Background(), "never-send-password")
			if err != nil {
				t.Fatal(err)
			}
			assertUnsupported(t, passwordResult.State, passwordResult.Unsupported, test.reason)

			accountClient, err := NewBreachedAccountClient(BreachedAccountConfig{
				Policy: test.policy,
				HTTP:   HTTPOptions{BaseURL: server.URL + "/account"},
				APIKey: validTestAPIKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			accountResult, err := accountClient.Check(context.Background(), "never-send@example.com")
			if err != nil {
				t.Fatal(err)
			}
			assertUnsupported(t, accountResult.State, accountResult.Unsupported, test.reason)
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("unsupported adapters made %d network request(s)", requests.Load())
	}
}

func TestBreachedAccountSuccessAndRequestContract(t *testing.T) {
	const (
		email  = "alice+security@example.com"
		apiKey = validTestAPIKey
	)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/account/"+email {
			t.Errorf("path = %q, want monitored email", request.URL.Path)
		}
		if !strings.Contains(request.RequestURI, "alice%2Bsecurity%40example.com") {
			t.Errorf("email is not URL-encoded in RequestURI: %q", request.RequestURI)
		}
		if request.URL.Query().Get("truncateResponse") != "false" {
			t.Errorf("truncateResponse = %q", request.URL.Query().Get("truncateResponse"))
		}
		if request.Header.Get("hibp-api-key") != apiKey {
			t.Error("HIBP API key header missing")
		}
		if request.Header.Get("User-Agent") != "oms-test" {
			t.Errorf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `[{
			"Name":"Example",
			"Title":"Example breach",
			"Domain":"example.com",
			"BreachDate":"2026-01-02",
			"PwnCount":123,
			"DataClasses":["Email addresses"],
			"IsVerified":true,
			"Description":"ignored provider field"
		}]`)
	}))
	defer server.Close()

	client, err := NewBreachedAccountClient(BreachedAccountConfig{
		Policy:    AccessPolicy{Enabled: true},
		HTTP:      HTTPOptions{BaseURL: server.URL + "/account"},
		APIKey:    apiKey,
		UserAgent: "oms-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Check(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != ResultFound ||
		len(result.Breaches) != 1 ||
		result.Breaches[0].Name != "Example" ||
		result.Breaches[0].PwnCount != 123 {
		t.Fatalf("unexpected result: %#v", result)
	}
	assertNoSecrets(t, result, email, apiKey)
}

func TestBreachedAccountNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, "provider body is ignored")
	}))
	defer server.Close()

	result, err := testBreachedAccountClient(t, server, 0).
		Check(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.State != ResultNotFound || len(result.Breaches) != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBreachedAccountRejectsMalformedAndOversizedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		max  int64
	}{
		{name: "invalid JSON", body: `{"not":"an array"}`},
		{name: "null response", body: `null`},
		{name: "missing breach name", body: `[{"Domain":"example.com"}]`},
		{name: "oversized", body: strings.Repeat("x", 65), max: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			_, err := testBreachedAccountClient(t, server, test.max).
				Check(context.Background(), "malformed@example.com")
			assertError(t, err, ErrorResponse, 0, false, 0)
			assertNoSecrets(t, err, "malformed@example.com", validTestAPIKey)
		})
	}
}

func TestTypedConfigurationAndInputErrors(t *testing.T) {
	_, err := NewBreachedAccountClient(BreachedAccountConfig{})
	assertError(t, err, ErrorConfiguration, 0, false, 0)

	_, err = NewBreachedAccountClient(BreachedAccountConfig{
		APIKey: strings.Repeat("g", 32),
	})
	assertError(t, err, ErrorConfiguration, 0, false, 0)

	_, err = NewPwnedPasswordsClient(PwnedPasswordsConfig{
		HTTP: HTTPOptions{BaseURL: "http://example.com/range"},
	})
	assertError(t, err, ErrorConfiguration, 0, false, 0)

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid input reached server")
	}))
	defer server.Close()
	client := testBreachedAccountClient(t, server, 0)
	_, err = client.Check(context.Background(), "not-an-email")
	assertError(t, err, ErrorInput, 0, false, 0)

	_, err = client.Check(nil, "valid@example.com")
	assertError(t, err, ErrorInput, 0, false, 0)
}

func TestBreachedAccountCancellationAndRetryStatus(t *testing.T) {
	t.Run("pre-canceled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("pre-canceled request reached server")
		}))
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := testBreachedAccountClient(t, server, 0).
			Check(ctx, "cancel@example.com")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		assertError(t, err, ErrorCanceled, 0, false, 0)
	})

	t.Run("rate limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Retry-After", "11")
			writer.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		_, err := testBreachedAccountClient(t, server, 0).
			Check(context.Background(), "limited@example.com")
		assertError(t, err, ErrorStatus, http.StatusTooManyRequests, true, 11*time.Second)
	})
}

func TestDisclosureMetadataIsExactAndDefensivelyCopied(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	passwordClient := testPwnedPasswordsClient(t, server, 0)
	passwordContract := passwordClient.Contract()
	if passwordContract.Endpoint != server.URL+"/range" ||
		len(passwordContract.DisclosedData) != 1 ||
		passwordContract.DisclosedData[0].Field != "password_sha1_prefix" ||
		!strings.Contains(passwordContract.DisclosedData[0].Form, "first 5") ||
		passwordContract.Credential.Required ||
		passwordContract.Credential.Scope != "none" ||
		passwordContract.Offline.Supported {
		t.Fatalf("unexpected password disclosure contract: %#v", passwordContract)
	}
	if err := passwordContract.Validate(); err != nil {
		t.Fatal(err)
	}
	passwordContract.DisclosedData[0].Field = "mutated"
	if passwordClient.Contract().DisclosedData[0].Field != "password_sha1_prefix" {
		t.Fatal("password contract was not defensively copied")
	}

	accountClient := testBreachedAccountClient(t, server, 0)
	accountContract := accountClient.Contract()
	if accountContract.Endpoint != server.URL+"/account" ||
		len(accountContract.DisclosedData) != 1 ||
		accountContract.DisclosedData[0].Field != "monitored_email" ||
		!strings.Contains(accountContract.DisclosedData[0].Form, "complete") ||
		!accountContract.Credential.Required ||
		accountContract.Credential.Location != "hibp-api-key request header" ||
		accountContract.Offline.Supported {
		t.Fatalf("unexpected account disclosure contract: %#v", accountContract)
	}
	if err := accountContract.Validate(); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, accountContract, validTestAPIKey, "person@example.com")
}

func TestErrorsAndResultsNeverExposeSecretsOrFullHashes(t *testing.T) {
	const (
		password = "unique-password-that-must-never-escape"
		email    = "private-person@example.com"
		apiKey   = "abcdef0123456789abcdef0123456789"
	)
	_, suffix, fullHash := testPasswordHash(password)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf(
			"transport leaked request %s %s %s %s",
			request.URL.String(),
			password,
			email,
			apiKey,
		)
	})
	httpClient := &http.Client{Transport: transport}

	passwordClient, err := NewPwnedPasswordsClient(PwnedPasswordsConfig{
		Policy: AccessPolicy{Enabled: true},
		HTTP: HTTPOptions{
			Client:  httpClient,
			BaseURL: "http://127.0.0.1/range",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	passwordResult, passwordErr := passwordClient.Check(context.Background(), password)
	if passwordErr == nil {
		t.Fatal("expected password request error")
	}
	assertNoSecrets(t, passwordErr, password, fullHash, suffix, apiKey, email)
	assertNoSecrets(t, passwordResult, password, fullHash, suffix)

	accountClient, err := NewBreachedAccountClient(BreachedAccountConfig{
		Policy: AccessPolicy{Enabled: true},
		HTTP: HTTPOptions{
			Client:  httpClient,
			BaseURL: "http://127.0.0.1/account",
		},
		APIKey: apiKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	accountResult, accountErr := accountClient.Check(context.Background(), email)
	if accountErr == nil {
		t.Fatal("expected account request error")
	}
	assertNoSecrets(t, accountErr, password, fullHash, suffix, apiKey, email)
	assertNoSecrets(t, accountResult, apiKey, email)

	_, configErr := NewBreachedAccountClient(BreachedAccountConfig{
		APIKey: apiKey + "\n",
	})
	assertNoSecrets(t, configErr, apiKey)

	t.Run("provider response bodies", func(t *testing.T) {
		prefix, _, _ := testPasswordHash(password)
		passwordServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if !strings.HasSuffix(request.URL.Path, prefix) {
				t.Error("unexpected password prefix")
			}
			_, _ = fmt.Fprintf(writer, "%s:%s", fullHash, password)
		}))
		defer passwordServer.Close()
		_, responseErr := testPwnedPasswordsClient(t, passwordServer, 0).
			Check(context.Background(), password)
		assertNoSecrets(t, responseErr, password, fullHash, suffix)

		accountServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(writer, "%s %s", email, apiKey)
		}))
		defer accountServer.Close()
		_, responseErr = testBreachedAccountClientWithKey(t, accountServer, apiKey).
			Check(context.Background(), email)
		assertNoSecrets(t, responseErr, email, apiKey)
	})
}

func testPwnedPasswordsClient(
	t *testing.T,
	server *httptest.Server,
	maxResponseBytes int64,
) *PwnedPasswordsClient {
	t.Helper()
	client, err := NewPwnedPasswordsClient(PwnedPasswordsConfig{
		Policy: AccessPolicy{Enabled: true},
		HTTP: HTTPOptions{
			Client:           server.Client(),
			BaseURL:          server.URL + "/range",
			MaxResponseBytes: maxResponseBytes,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testBreachedAccountClient(
	t *testing.T,
	server *httptest.Server,
	maxResponseBytes int64,
) *BreachedAccountClient {
	t.Helper()
	client, err := NewBreachedAccountClient(BreachedAccountConfig{
		Policy: AccessPolicy{Enabled: true},
		HTTP: HTTPOptions{
			Client:           server.Client(),
			BaseURL:          server.URL + "/account",
			MaxResponseBytes: maxResponseBytes,
		},
		APIKey: validTestAPIKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testBreachedAccountClientWithKey(
	t *testing.T,
	server *httptest.Server,
	apiKey string,
) *BreachedAccountClient {
	t.Helper()
	client, err := NewBreachedAccountClient(BreachedAccountConfig{
		Policy: AccessPolicy{Enabled: true},
		HTTP: HTTPOptions{
			Client:  server.Client(),
			BaseURL: server.URL + "/account",
		},
		APIKey: apiKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testPasswordHash(password string) (prefix, suffix, fullHash string) {
	sum := sha1.Sum([]byte(password))
	fullHash = strings.ToUpper(hex.EncodeToString(sum[:]))
	return fullHash[:5], fullHash[5:], fullHash
}

func assertError(
	t *testing.T,
	err error,
	kind ErrorKind,
	statusCode int,
	retryable bool,
	retryAfter time.Duration,
) {
	t.Helper()
	if err == nil {
		t.Fatal("expected adapter error")
	}
	if !errors.Is(err, ErrAdapter) {
		t.Fatalf("error %v does not match ErrAdapter", err)
	}
	var adapterError *AdapterError
	if !errors.As(err, &adapterError) {
		t.Fatalf("error type = %T, want *AdapterError", err)
	}
	if adapterError.Kind != kind ||
		adapterError.StatusCode != statusCode ||
		adapterError.Retryable != retryable ||
		adapterError.RetryAfter != retryAfter {
		t.Fatalf(
			"error = %#v, want kind=%s status=%d retryable=%v retry_after=%s",
			adapterError,
			kind,
			statusCode,
			retryable,
			retryAfter,
		)
	}
}

func assertUnsupported(
	t *testing.T,
	state ResultState,
	unsupported *UnsupportedResult,
	reason UnsupportedReason,
) {
	t.Helper()
	if state != ResultUnsupported || unsupported == nil || unsupported.Reason != reason {
		t.Fatalf("state = %q unsupported = %#v, want reason %q", state, unsupported, reason)
	}
}

func assertNoSecrets(t *testing.T, value any, secrets ...string) {
	t.Helper()
	rendered, err := json.Marshal(value)
	if err != nil {
		rendered = []byte(fmt.Sprintf("%v", value))
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(rendered), secret) {
			t.Fatalf("value leaks secret %q: %s", secret, rendered)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
