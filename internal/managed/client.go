package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/controller"
)

const (
	defaultRequestTimeout      = 15 * time.Second
	maxRequestTimeout          = 30 * time.Second
	maxEnrollmentRequestBytes  = 64 << 10
	maxEnrollmentResponseBytes = 32 << 10
	maxHeartbeatRequestBytes   = 64 << 10
	maxPolicyResponseBytes     = 512 << 10
	maxReportRequestBytes      = 1 << 20
	maxReportResponseBytes     = 32 << 10
	maxRotationResponseBytes   = 32 << 10
)

type RemoteError struct {
	Operation  string
	StatusCode int
}

func (err *RemoteError) Error() string {
	if err.StatusCode == 0 {
		return "managed controller request failed"
	}
	return fmt.Sprintf("managed controller request failed with status %d", err.StatusCode)
}

type EnrollmentOptions struct {
	StatePath       string
	ControllerURL   string
	TokenEnv        string
	PolicyPublicKey string
	Metadata        controller.DeviceMetadata
	HTTPClient      *http.Client
}

type Client struct {
	statePath  string
	policyPath string
	state      EnrollmentState
	http       *http.Client
}

type enrollmentRequest struct {
	EnrollmentToken string                    `json:"enrollment_token"`
	Device          controller.DeviceMetadata `json:"device"`
}

func EnrollFromEnvironment(
	ctx context.Context,
	options EnrollmentOptions,
) (EnrollmentState, error) {
	if ctx == nil {
		return EnrollmentState{}, errors.New("managed enrollment context is required")
	}
	if !validEnvironmentName(options.TokenEnv) {
		return EnrollmentState{}, errors.New("enrollment token environment variable name is invalid")
	}
	token, present := os.LookupEnv(options.TokenEnv)
	if !present || !safeCredential(token) {
		return EnrollmentState{}, errors.New("enrollment token environment variable is missing or invalid")
	}
	if err := options.Metadata.Validate(); err != nil {
		return EnrollmentState{}, errors.New("local device metadata is invalid")
	}
	canonicalURL, err := validateControllerURL(options.ControllerURL)
	if err != nil {
		return EnrollmentState{}, err
	}
	if _, err := decodePublicKey(options.PolicyPublicKey); err != nil {
		return EnrollmentState{}, err
	}
	if strings.TrimSpace(options.StatePath) == "" {
		return EnrollmentState{}, errors.New("managed enrollment state path is required")
	}
	if _, err := os.Lstat(options.StatePath); err == nil {
		return EnrollmentState{}, errors.New("managed enrollment state already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnrollmentState{}, errors.New("inspect managed enrollment state destination")
	}
	if _, err := ensurePrivateStateDirectory(options.StatePath); err != nil {
		return EnrollmentState{}, err
	}

	httpClient := boundedHTTPClient(options.HTTPClient)
	requestBody := enrollmentRequest{
		EnrollmentToken: token,
		Device:          options.Metadata,
	}
	var grant controller.EnrollmentGrant
	if err := performJSON(
		ctx,
		httpClient,
		http.MethodPost,
		canonicalURL+"/v1/agent/enroll",
		"",
		"",
		requestBody,
		maxEnrollmentRequestBytes,
		http.StatusCreated,
		&grant,
		maxEnrollmentResponseBytes,
		"enroll",
	); err != nil {
		return EnrollmentState{}, err
	}
	state := EnrollmentState{
		Schema:           StateSchema,
		SchemaVersion:    StateSchemaVersion,
		ControllerURL:    canonicalURL,
		DeviceID:         grant.DeviceID,
		DeviceCredential: grant.DeviceCredential,
		PolicyPublicKey:  options.PolicyPublicKey,
		EnrolledAt:       time.Now().UTC(),
	}
	if err := createState(options.StatePath, state); err != nil {
		return EnrollmentState{}, err
	}
	return state, nil
}

func Open(statePath string, httpClient *http.Client) (*Client, error) {
	state, err := LoadState(statePath)
	if err != nil {
		return nil, err
	}
	return &Client{
		statePath:  statePath,
		policyPath: PolicyPath(statePath),
		state:      state,
		http:       boundedHTTPClient(httpClient),
	}, nil
}

func LocalDeviceMetadata(agentVersion string) (controller.DeviceMetadata, error) {
	return LocalDeviceMetadataForName(agentVersion, "")
}

func LocalDeviceMetadataForName(
	agentVersion string,
	deviceName string,
) (controller.DeviceMetadata, error) {
	if deviceName == "" {
		hostname, err := os.Hostname()
		if err != nil || strings.TrimSpace(hostname) == "" {
			return controller.DeviceMetadata{}, errors.New("read local hostname")
		}
		deviceName = hostname
	}
	metadata := controller.DeviceMetadata{
		Name:         deviceName,
		Platform:     runtime.GOOS,
		OSVersion:    runtime.GOOS + "-" + runtime.GOARCH,
		AgentVersion: agentVersion,
	}
	if err := metadata.Validate(); err != nil {
		return controller.DeviceMetadata{}, errors.New("local device metadata is invalid")
	}
	return metadata, nil
}

func (client *Client) Heartbeat(
	ctx context.Context,
	metadata controller.DeviceMetadata,
) error {
	if ctx == nil {
		return errors.New("managed heartbeat context is required")
	}
	if err := metadata.Validate(); err != nil {
		return errors.New("local device metadata is invalid")
	}
	return performJSON(
		ctx,
		client.http,
		http.MethodPost,
		client.state.ControllerURL+"/v1/agent/heartbeat",
		client.state.DeviceID,
		client.state.DeviceCredential,
		metadata,
		maxHeartbeatRequestBytes,
		http.StatusNoContent,
		nil,
		0,
		"heartbeat",
	)
}

func (client *Client) FetchPolicy(ctx context.Context) (controller.PolicyDocument, error) {
	if ctx == nil {
		return controller.PolicyDocument{}, errors.New("managed policy context is required")
	}
	var signed controller.SignedPolicy
	if err := performJSON(
		ctx,
		client.http,
		http.MethodGet,
		client.state.ControllerURL+"/v1/agent/policy",
		client.state.DeviceID,
		client.state.DeviceCredential,
		nil,
		0,
		http.StatusOK,
		&signed,
		maxPolicyResponseBytes,
		"fetch policy",
	); err != nil {
		return controller.PolicyDocument{}, err
	}
	if err := verifyPinnedPolicy(client.state.PolicyPublicKey, signed); err != nil {
		return controller.PolicyDocument{}, err
	}
	if _, err := persistVerifiedPolicy(client.statePath, signed); err != nil {
		return controller.PolicyDocument{}, err
	}
	return signed.Document, nil
}

func (client *Client) SubmitReport(
	ctx context.Context,
	report controller.ReportSync,
	now time.Time,
) error {
	if ctx == nil {
		return errors.New("managed report context is required")
	}
	if err := report.Validate(now.UTC()); err != nil {
		return errors.New("redacted report is invalid")
	}
	var response struct {
		Accepted int `json:"accepted"`
	}
	if err := performJSON(
		ctx,
		client.http,
		http.MethodPost,
		client.state.ControllerURL+"/v1/agent/reports",
		client.state.DeviceID,
		client.state.DeviceCredential,
		report,
		maxReportRequestBytes,
		http.StatusAccepted,
		&response,
		maxReportResponseBytes,
		"submit report",
	); err != nil {
		return err
	}
	if response.Accepted != len(report.Findings) {
		return errors.New("controller acknowledged an unexpected report count")
	}
	return nil
}

func (client *Client) RotateCredential(ctx context.Context) error {
	if ctx == nil {
		return errors.New("managed credential rotation context is required")
	}
	var grant controller.EnrollmentGrant
	if err := performJSON(
		ctx,
		client.http,
		http.MethodPost,
		client.state.ControllerURL+"/v1/agent/credentials/rotate",
		client.state.DeviceID,
		client.state.DeviceCredential,
		nil,
		0,
		http.StatusOK,
		&grant,
		maxRotationResponseBytes,
		"rotate credential",
	); err != nil {
		return err
	}
	if grant.DeviceID != client.state.DeviceID || !safeCredential(grant.DeviceCredential) {
		return errors.New("controller returned an invalid rotated credential")
	}
	updated := client.state
	updated.DeviceCredential = grant.DeviceCredential
	if err := replaceState(client.statePath, updated); err != nil {
		return errors.New("persist rotated device credential")
	}
	client.state = updated
	return nil
}

func boundedHTTPClient(input *http.Client) *http.Client {
	var copied http.Client
	if input != nil {
		copied = *input
	}
	if copied.Timeout <= 0 || copied.Timeout > maxRequestTimeout {
		copied.Timeout = defaultRequestTimeout
	}
	copied.Jar = nil
	copied.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copied
}

func performJSON(
	ctx context.Context,
	httpClient *http.Client,
	method string,
	endpoint string,
	deviceID string,
	credential string,
	requestValue any,
	requestLimit int,
	expectedStatus int,
	responseValue any,
	responseLimit int,
	operation string,
) error {
	var body io.Reader
	if requestValue != nil {
		encoded, err := json.Marshal(requestValue)
		if err != nil || len(encoded) > requestLimit {
			return errors.New("managed request payload is invalid or too large")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("create managed controller request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "oh-my-safety-agent")
	if requestValue != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("X-Device-ID", deviceID)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("managed controller request canceled: %w", ctx.Err())
		}
		return &RemoteError{Operation: operation}
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		_, _ = io.CopyN(io.Discard, response.Body, 4<<10)
		return &RemoteError{Operation: operation, StatusCode: response.StatusCode}
	}
	if responseValue == nil {
		var single [1]byte
		count, readErr := response.Body.Read(single[:])
		if count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return errors.New("controller returned an unexpected response body")
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("controller returned a non-JSON response")
	}
	limited := io.LimitReader(response.Body, int64(responseLimit)+1)
	encoded, err := io.ReadAll(limited)
	if err != nil {
		return errors.New("read controller response")
	}
	if len(encoded) > responseLimit {
		return errors.New("controller response exceeds its size limit")
	}
	if err := decodeStrict(bytes.NewReader(encoded), responseValue); err != nil {
		return errors.New("controller returned invalid JSON")
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') ||
			character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}
