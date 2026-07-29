package exposure

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRequestTimeout    = 10 * time.Second
	maxRequestTimeout        = time.Minute
	defaultMaxResponseBytes  = int64(2 << 20)
	absoluteMaxResponseBytes = int64(16 << 20)
	maxRetryAfter            = 24 * time.Hour
)

type HTTPOptions struct {
	Client           *http.Client
	BaseURL          string
	Timeout          time.Duration
	MaxResponseBytes int64
}

type httpRuntime struct {
	adapter          string
	client           *http.Client
	baseURL          *url.URL
	timeout          time.Duration
	maxResponseBytes int64
}

func newHTTPRuntime(adapter, defaultBaseURL string, options HTTPOptions) (httpRuntime, error) {
	rawBaseURL := strings.TrimSpace(options.BaseURL)
	if rawBaseURL == "" {
		rawBaseURL = defaultBaseURL
	}
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil ||
		baseURL.Host == "" ||
		(baseURL.Scheme != "https" && baseURL.Scheme != "http") ||
		baseURL.User != nil ||
		baseURL.RawQuery != "" ||
		baseURL.Fragment != "" {
		return httpRuntime{}, configurationError(adapter)
	}
	if baseURL.Scheme == "http" && !loopbackHost(baseURL.Hostname()) {
		return httpRuntime{}, configurationError(adapter)
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	baseURL.RawPath = ""

	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout < 0 || timeout > maxRequestTimeout {
		return httpRuntime{}, configurationError(adapter)
	}

	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}
	if maxResponseBytes < 1 || maxResponseBytes > absoluteMaxResponseBytes {
		return httpRuntime{}, configurationError(adapter)
	}

	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	clientCopy.Jar = nil
	// Refuse redirects so a provider cannot move credential or account-bearing
	// requests to another origin.
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return httpRuntime{
		adapter:          adapter,
		client:           &clientCopy,
		baseURL:          baseURL,
		timeout:          timeout,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (runtime httpRuntime) endpoint() string {
	return runtime.baseURL.String()
}

func (runtime httpRuntime) requestContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, inputError(runtime.adapter)
	}
	requestContext, cancel := context.WithTimeout(ctx, runtime.timeout)
	return requestContext, cancel, nil
}

func (runtime httpRuntime) newGETRequest(ctx context.Context, segment string) (*http.Request, context.CancelFunc, error) {
	requestContext, cancel, err := runtime.requestContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	endpoint := *runtime.baseURL
	escapedPath := strings.TrimRight(endpoint.EscapedPath(), "/") + "/" + url.QueryEscape(segment)
	endpoint.Path, err = url.PathUnescape(escapedPath)
	if err != nil {
		cancel()
		return nil, nil, inputError(runtime.adapter)
	}
	endpoint.RawPath = escapedPath
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		cancel()
		return nil, nil, inputError(runtime.adapter)
	}
	return request, cancel, nil
}

func (runtime httpRuntime) do(request *http.Request) (*http.Response, error) {
	response, err := runtime.client.Do(request)
	if err == nil {
		return response, nil
	}
	switch {
	case errors.Is(request.Context().Err(), context.Canceled):
		return nil, &AdapterError{
			Adapter: runtime.adapter,
			Kind:    ErrorCanceled,
			cause:   context.Canceled,
		}
	case errors.Is(request.Context().Err(), context.DeadlineExceeded):
		return nil, &AdapterError{
			Adapter:   runtime.adapter,
			Kind:      ErrorCanceled,
			Retryable: true,
			cause:     context.DeadlineExceeded,
		}
	default:
		return nil, &AdapterError{
			Adapter:   runtime.adapter,
			Kind:      ErrorRequest,
			Retryable: true,
		}
	}
}

func (runtime httpRuntime) readResponse(response *http.Response) ([]byte, error) {
	limited := io.LimitReader(response.Body, runtime.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		if response.Request != nil {
			switch {
			case errors.Is(response.Request.Context().Err(), context.Canceled):
				return nil, &AdapterError{
					Adapter: runtime.adapter,
					Kind:    ErrorCanceled,
					cause:   context.Canceled,
				}
			case errors.Is(response.Request.Context().Err(), context.DeadlineExceeded):
				return nil, &AdapterError{
					Adapter:   runtime.adapter,
					Kind:      ErrorCanceled,
					Retryable: true,
					cause:     context.DeadlineExceeded,
				}
			}
		}
		return nil, &AdapterError{
			Adapter:   runtime.adapter,
			Kind:      ErrorResponse,
			Retryable: true,
		}
	}
	if int64(len(body)) > runtime.maxResponseBytes {
		return nil, &AdapterError{
			Adapter: runtime.adapter,
			Kind:    ErrorResponse,
		}
	}
	return body, nil
}

func statusError(adapter string, response *http.Response) error {
	adapterError := &AdapterError{
		Adapter:    adapter,
		Kind:       ErrorStatus,
		StatusCode: response.StatusCode,
		Retryable:  retryableStatus(response.StatusCode),
	}
	if adapterError.Retryable {
		adapterError.RetryAfter = parseRetryAfter(response.Header.Get("Retry-After"), time.Now())
	}
	return adapterError
}

func retryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay <= maxRetryAfter {
			return delay
		}
		return 0
	}
	retryAt, err := http.ParseTime(value)
	if err != nil || !retryAt.After(now) {
		return 0
	}
	delay := retryAt.Sub(now)
	if delay > maxRetryAfter {
		return 0
	}
	return delay
}
