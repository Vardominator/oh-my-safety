package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebhookConfig struct {
	Name        string
	URL         string
	BearerToken string
	Headers     map[string]string
	Timeout     time.Duration
}

type WebhookChannel struct {
	name     string
	endpoint string
	headers  http.Header
	secrets  []string
	sender   httpSender
}

func NewWebhookChannel(config WebhookConfig, client *http.Client) (*WebhookChannel, error) {
	name := config.Name
	if name == "" {
		name = "webhook"
	}
	if !validChannelName(name) {
		return nil, errors.New("webhook channel name contains unsupported characters")
	}
	endpoint, err := validateEndpoint(config.URL, true)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook configuration: %w", err)
	}
	if config.BearerToken != "" && !validSecret(config.BearerToken) {
		return nil, errors.New("webhook bearer token contains whitespace or control characters")
	}
	headers, headerSecrets, err := validateWebhookHeaders(config.Headers)
	if err != nil {
		return nil, err
	}
	if config.BearerToken != "" {
		headers.Set("Authorization", "Bearer "+config.BearerToken)
		headerSecrets = append(headerSecrets, config.BearerToken)
	}
	headerSecrets = append(headerSecrets, endpointSecretFragments(endpoint)...)

	sender, err := newHTTPSender(client, config.Timeout)
	if err != nil {
		return nil, err
	}
	return &WebhookChannel{
		name:     name,
		endpoint: endpoint.String(),
		headers:  headers,
		secrets:  headerSecrets,
		sender:   sender,
	}, nil
}

func (channel *WebhookChannel) Name() string {
	return channel.name
}

func (channel *WebhookChannel) String() string {
	return channel.Name()
}

func (*WebhookChannel) GoString() string {
	return "notifier.WebhookChannel{credentials:redacted}"
}

func (channel *WebhookChannel) Notify(ctx context.Context, notification Notification) error {
	_, err := channel.Deliver(ctx, notification)
	return err
}

func (channel *WebhookChannel) Deliver(
	ctx context.Context,
	notification Notification,
) (ProviderDelivery, error) {
	if err := notification.Validate(); err != nil {
		return ProviderDelivery{}, err
	}
	response, err := channel.sender.postJSON(
		ctx,
		"webhook",
		channel.endpoint,
		channel.headers,
		notification,
		channel.secrets...,
	)
	if err != nil {
		return ProviderDelivery{}, err
	}
	deliveryID := safeProviderID(firstDeliveryHeader(response.header), channel.secrets...)
	if !isSuccess(response.statusCode) {
		return ProviderDelivery{}, providerStatusError("webhook", response, deliveryID, 0)
	}
	return ProviderDelivery{
		Channel:    channel.name,
		ID:         deliveryID,
		StatusCode: response.statusCode,
	}, nil
}

func validateWebhookHeaders(values map[string]string) (http.Header, []string, error) {
	if len(values) > 32 {
		return nil, nil, errors.New("webhook supports at most 32 custom headers")
	}
	headers := make(http.Header, len(values))
	secrets := make([]string, 0, len(values))
	totalBytes := 0
	for name, value := range values {
		if !validHeaderName(name) {
			return nil, nil, errors.New("webhook custom header name is invalid")
		}
		canonicalName := http.CanonicalHeaderKey(name)
		if !strings.HasPrefix(canonicalName, "X-") {
			return nil, nil, errors.New("webhook custom headers must use an X- prefix")
		}
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return nil, nil, errors.New("webhook custom header value is empty or contains control characters")
		}
		totalBytes += len(canonicalName) + len(value)
		if len(value) > 8<<10 || totalBytes > 16<<10 {
			return nil, nil, errors.New("webhook custom headers exceed the size limit")
		}
		headers.Set(canonicalName, value)
		secrets = append(secrets, value)
	}
	return headers, secrets, nil
}

func endpointSecretFragments(endpoint *url.URL) []string {
	secrets := make([]string, 0)
	for _, values := range endpoint.Query() {
		for _, value := range values {
			if len(value) >= 6 {
				secrets = append(secrets, value)
			}
		}
	}
	segments := strings.Split(strings.Trim(endpoint.Path, "/"), "/")
	if len(segments) > 0 {
		last := segments[len(segments)-1]
		if len(last) >= 12 {
			secrets = append(secrets, last)
		}
	}
	return secrets
}
