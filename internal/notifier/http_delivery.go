package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultDeliveryTimeout = 10 * time.Second
	maxDeliveryTimeout     = time.Minute
	maxRequestBodyBytes    = 1 << 20
	maxResponseBodyBytes   = 64 << 10
)

type ProviderDelivery struct {
	Channel    string `json:"channel"`
	ID         string `json:"id,omitempty"`
	StatusCode int    `json:"status_code"`
}

type DetailedChannel interface {
	Channel
	Deliver(context.Context, Notification) (ProviderDelivery, error)
}

type DeliveryError struct {
	Channel    string
	StatusCode int
	Retryable  bool
	RetryAfter time.Duration
	DeliveryID string

	kind  string
	cause error
}

func (deliveryError *DeliveryError) Error() string {
	switch {
	case deliveryError.kind == "canceled":
		return deliveryError.Channel + " notification delivery canceled"
	case deliveryError.kind == "timeout":
		return deliveryError.Channel + " notification delivery timed out"
	case deliveryError.kind == "response-too-large":
		return deliveryError.Channel + " notification response exceeded the size limit"
	case deliveryError.kind == "provider-rejected":
		return deliveryError.Channel + " notification was rejected by the provider"
	case deliveryError.StatusCode > 0:
		return fmt.Sprintf(
			"%s notification delivery failed with HTTP status %d",
			deliveryError.Channel,
			deliveryError.StatusCode,
		)
	default:
		return deliveryError.Channel + " notification delivery failed"
	}
}

func (deliveryError *DeliveryError) Unwrap() error {
	return deliveryError.cause
}

type httpSender struct {
	client  *http.Client
	timeout time.Duration
}

type httpResponse struct {
	statusCode int
	header     http.Header
	body       []byte
}

func newHTTPSender(client *http.Client, timeout time.Duration) (httpSender, error) {
	if timeout == 0 {
		timeout = defaultDeliveryTimeout
	}
	if timeout < 0 || timeout > maxDeliveryTimeout {
		return httpSender{}, fmt.Errorf(
			"notification timeout must be between 1ns and %s",
			maxDeliveryTimeout,
		)
	}
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return httpSender{client: &clientCopy, timeout: timeout}, nil
}

func (sender httpSender) postJSON(
	ctx context.Context,
	channel string,
	endpoint string,
	headers http.Header,
	payload any,
	secrets ...string,
) (httpResponse, error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return httpResponse{}, safeDeliveryError(channel, "request", false, err)
	}
	if len(requestBody) > maxRequestBodyBytes {
		return httpResponse{}, safeDeliveryError(channel, "request-too-large", false, nil)
	}

	requestContext, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		endpoint,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return httpResponse{}, safeDeliveryError(channel, "request", false, nil)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "oh-my-safety-notifier/1")
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}

	response, err := sender.client.Do(request)
	if err != nil {
		return httpResponse{}, transportDeliveryError(channel, requestContext, err)
	}
	defer response.Body.Close()

	bounded := io.LimitReader(response.Body, maxResponseBodyBytes+1)
	body, readErr := io.ReadAll(bounded)
	if readErr != nil {
		return httpResponse{}, safeDeliveryError(channel, "response", isRetryableStatus(response.StatusCode), nil)
	}
	if len(body) > maxResponseBodyBytes {
		return httpResponse{}, &DeliveryError{
			Channel:    channel,
			StatusCode: response.StatusCode,
			Retryable:  isRetryableStatus(response.StatusCode),
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			DeliveryID: safeProviderID(firstDeliveryHeader(response.Header), secrets...),
			kind:       "response-too-large",
		}
	}
	return httpResponse{
		statusCode: response.StatusCode,
		header:     response.Header.Clone(),
		body:       body,
	}, nil
}

func providerStatusError(
	channel string,
	response httpResponse,
	deliveryID string,
	retryAfter time.Duration,
) error {
	if retryAfter == 0 {
		retryAfter = parseRetryAfter(response.header.Get("Retry-After"), time.Now())
	}
	return &DeliveryError{
		Channel:    channel,
		StatusCode: response.statusCode,
		Retryable:  isRetryableStatus(response.statusCode),
		RetryAfter: retryAfter,
		DeliveryID: deliveryID,
		kind:       "http-status",
	}
}

func safeDeliveryError(channel, kind string, retryable bool, cause error) error {
	return &DeliveryError{
		Channel:   channel,
		Retryable: retryable,
		kind:      kind,
		cause:     safeContextCause(cause),
	}
}

func transportDeliveryError(channel string, ctx context.Context, requestErr error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return &DeliveryError{
			Channel: channel,
			kind:    "canceled",
			cause:   context.Canceled,
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &DeliveryError{
			Channel:   channel,
			Retryable: true,
			kind:      "timeout",
			cause:     context.DeadlineExceeded,
		}
	}
	var networkError net.Error
	return &DeliveryError{
		Channel:   channel,
		Retryable: errors.As(requestErr, &networkError),
		kind:      "transport",
	}
}

func safeContextCause(cause error) error {
	switch {
	case errors.Is(cause, context.Canceled):
		return context.Canceled
	case errors.Is(cause, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func isSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

func isRetryableStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusTooEarly ||
		statusCode == http.StatusTooManyRequests ||
		statusCode >= http.StatusInternalServerError
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		if seconds <= 0 {
			return 0
		}
		duration := time.Duration(seconds) * time.Second
		if duration > 24*time.Hour {
			return 24 * time.Hour
		}
		return duration
	}
	retryAt, err := http.ParseTime(value)
	if err != nil || !retryAt.After(now) {
		return 0
	}
	duration := retryAt.Sub(now)
	if duration > 24*time.Hour {
		return 24 * time.Hour
	}
	return duration
}

func firstDeliveryHeader(header http.Header) string {
	for _, name := range []string{"X-Message-Id", "X-Request-Id", "X-Correlation-Id"} {
		if value := header.Get(name); value != "" {
			return value
		}
	}
	return ""
}

func safeProviderID(value string, secrets ...string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\t") {
		return ""
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			return ""
		}
	}
	if !utf8.ValidString(value) {
		return ""
	}
	return value
}

func validateEndpoint(raw string, allowQuery bool) (*url.URL, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return nil, errors.New("notification endpoint is required and must not contain control characters")
	}
	parsed, err := url.Parse(raw)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Opaque != "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return nil, errors.New("notification endpoint must be an absolute URL without user info or a fragment")
	}
	if !allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return nil, errors.New("notification base URL must not contain a query")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("notification endpoint must use HTTPS unless it targets loopback")
		}
	default:
		return nil, errors.New("notification endpoint must use HTTP or HTTPS")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func appendURLPath(base *url.URL, suffix string) string {
	copy := *base
	copy.Path = strings.TrimRight(copy.Path, "/") + suffix
	copy.RawPath = ""
	return copy.String()
}

func truncateRunes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}

func validSecret(value string) bool {
	return value != "" &&
		value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, "\r\n\t ")
}

func validChannelName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("._-", character):
		default:
			return false
		}
	}
	return true
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", character):
		default:
			return false
		}
	}
	return true
}
