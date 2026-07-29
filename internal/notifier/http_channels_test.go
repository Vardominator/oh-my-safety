package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTelegramToken = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcd"
	testSendGridKey   = "SG.abcdefghijklmno.pqrstuvwxyzABCDEFGHIJ"
)

func TestWebhookSuccessUsesNotificationContract(t *testing.T) {
	bearerToken := "bearer-secret-123456"
	headerSecret := "header-secret-123456"
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		if request.Header.Get("Authorization") != "Bearer "+bearerToken {
			t.Errorf("authorization header missing")
		}
		if request.Header.Get("X-Webhook-Secret") != headerSecret {
			t.Errorf("custom header missing")
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		var received Notification
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode notification: %v", err)
			return
		}
		if !reflect.DeepEqual(received, testNotification()) {
			t.Errorf("webhook payload changed\nwant: %#v\n got: %#v", testNotification(), received)
		}
		writer.Header().Set("X-Request-ID", "request-123")
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	channel, err := NewWebhookChannel(WebhookConfig{
		Name:        "security-webhook",
		URL:         server.URL + "/notify?signature=query-secret-123456",
		BearerToken: bearerToken,
		Headers:     map[string]string{"X-Webhook-Secret": headerSecret},
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := channel.Deliver(context.Background(), testNotification())
	if err != nil {
		t.Fatal(err)
	}
	if result.Channel != "security-webhook" ||
		result.ID != "request-123" ||
		result.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected delivery result: %#v", result)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("request count = %d, want 1", requestCount.Load())
	}
}

func TestDiscordSuccessUsesSafeEmbedAndReturnsMessageID(t *testing.T) {
	webhookToken := "discord-webhook-token-123456"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("wait") != "true" {
			t.Errorf("Discord wait query missing: %s", request.URL.RawQuery)
		}
		if !strings.HasSuffix(request.URL.Path, "/"+webhookToken) {
			t.Errorf("unexpected Discord path")
		}
		var payload discordPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode Discord payload: %v", err)
			return
		}
		if len(payload.Embeds) != 1 {
			t.Errorf("embed count = %d, want 1", len(payload.Embeds))
			return
		}
		embed := payload.Embeds[0]
		if embed.Title != testNotification().Title ||
			embed.Description != testNotification().Body ||
			embed.Color != 0xe74c3c {
			t.Errorf("unexpected Discord embed: %#v", embed)
		}
		if payload.AllowedMentions.Parse == nil || len(payload.AllowedMentions.Parse) != 0 {
			t.Errorf("Discord mentions are not disabled: %#v", payload.AllowedMentions)
		}
		if strings.Contains(embed.Description, webhookToken) {
			t.Error("Discord token leaked into payload")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"discord-message-1"}`)
	}))
	defer server.Close()

	channel, err := NewDiscordChannel(DiscordConfig{
		WebhookURL: server.URL + "/api/webhooks/123/" + webhookToken,
		Username:   "oh-my-safety",
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := channel.Deliver(context.Background(), testNotification())
	if err != nil {
		t.Fatal(err)
	}
	if result.Channel != "discord" ||
		result.ID != "discord-message-1" ||
		result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected Discord result: %#v", result)
	}
}

func TestTelegramSuccessUsesProtectedPlainTextAndReturnsMessageID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		wantPath := "/bot" + testTelegramToken + "/sendMessage"
		if request.URL.Path != wantPath {
			t.Errorf("Telegram path = %q, want %q", request.URL.Path, wantPath)
		}
		var payload telegramPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode Telegram payload: %v", err)
			return
		}
		if payload.ChatID != "-1001234567890" ||
			!payload.ProtectContent ||
			!payload.LinkPreviewOptions.IsDisabled {
			t.Errorf("unexpected Telegram payload: %#v", payload)
		}
		if payload.Text != testNotification().Title+"\n\n"+testNotification().Body {
			t.Errorf("unexpected Telegram text: %q", payload.Text)
		}
		if strings.Contains(payload.Text, testTelegramToken) {
			t.Error("Telegram token leaked into payload")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true,"result":{"message_id":98765}}`)
	}))
	defer server.Close()

	channel, err := NewTelegramChannel(TelegramConfig{
		BotToken: testTelegramToken,
		ChatID:   "-1001234567890",
		BaseURL:  server.URL,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := channel.Deliver(context.Background(), testNotification())
	if err != nil {
		t.Fatal(err)
	}
	if result.Channel != "telegram" ||
		result.ID != "98765" ||
		result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected Telegram result: %#v", result)
	}
}

func TestSendGridSuccessUsesPlainTextAndReturnsMessageID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v3/mail/send" {
			t.Errorf("SendGrid path = %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testSendGridKey {
			t.Error("SendGrid authorization header missing")
		}
		var payload sendGridPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode SendGrid payload: %v", err)
			return
		}
		if payload.Subject != testNotification().Title ||
			len(payload.Content) != 1 ||
			payload.Content[0].Type != "text/plain" ||
			payload.Content[0].Value != testNotification().Body {
			t.Errorf("unexpected SendGrid content: %#v", payload)
		}
		if payload.From.Email != "security@example.com" ||
			len(payload.Personalizations) != 1 ||
			len(payload.Personalizations[0].To) != 1 ||
			payload.Personalizations[0].To[0].Email != "owner@example.com" {
			t.Errorf("unexpected SendGrid addressing: %#v", payload)
		}
		serialized, _ := json.Marshal(payload)
		if bytes.Contains(serialized, []byte(testSendGridKey)) {
			t.Error("SendGrid API key leaked into payload")
		}
		writer.Header().Set("X-Message-ID", "sendgrid-message-1")
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	channel, err := NewSendGridChannel(validSendGridConfig(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := channel.Deliver(context.Background(), testNotification())
	if err != nil {
		t.Fatal(err)
	}
	if result.Channel != "sendgrid" ||
		result.ID != "sendgrid-message-1" ||
		result.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected SendGrid result: %#v", result)
	}
}

func TestWebhookConfigurationValidation(t *testing.T) {
	tooLongName := strings.Repeat("x", 65)
	cases := []WebhookConfig{
		{},
		{URL: "http://example.com/hook"},
		{URL: "https://user:password@example.com/hook"},
		{URL: "https://example.com/hook#fragment"},
		{Name: tooLongName, URL: "https://example.com/hook"},
		{URL: "https://example.com/hook", BearerToken: "contains space"},
		{URL: "https://example.com/hook", Headers: map[string]string{"Authorization": "secret"}},
		{URL: "https://example.com/hook", Headers: map[string]string{"X-Test": "line\r\nbreak"}},
		{URL: "https://example.com/hook", Timeout: maxDeliveryTimeout + time.Second},
	}
	for index, config := range cases {
		if _, err := NewWebhookChannel(config, nil); err == nil {
			t.Fatalf("invalid webhook config %d accepted: %#v", index, config)
		}
	}
}

func TestDiscordConfigurationValidation(t *testing.T) {
	cases := []DiscordConfig{
		{},
		{WebhookURL: "http://example.com/api/webhooks/1/token"},
		{WebhookURL: "https://user:password@example.com/api/webhooks/1/token"},
		{WebhookURL: "https://example.com/hook", Username: strings.Repeat("x", 81)},
		{WebhookURL: "https://example.com/hook", Username: "line\nbreak"},
		{WebhookURL: "https://example.com/hook", Timeout: -time.Second},
	}
	for index, config := range cases {
		if _, err := NewDiscordChannel(config, nil); err == nil {
			t.Fatalf("invalid Discord config %d accepted: %#v", index, config)
		}
	}
}

func TestTelegramConfigurationValidation(t *testing.T) {
	cases := []TelegramConfig{
		{},
		{BotToken: "not-a-token", ChatID: "-1001234567890"},
		{BotToken: testTelegramToken, ChatID: "bad chat id"},
		{BotToken: testTelegramToken, ChatID: "@abc"},
		{BotToken: testTelegramToken, ChatID: "-1001234567890", BaseURL: "http://example.com"},
		{BotToken: testTelegramToken, ChatID: "-1001234567890", BaseURL: "https://example.com?token=secret"},
		{BotToken: testTelegramToken, ChatID: "-1001234567890", Timeout: maxDeliveryTimeout + 1},
	}
	for index, config := range cases {
		if _, err := NewTelegramChannel(config, nil); err == nil {
			t.Fatalf("invalid Telegram config %d accepted", index)
		}
	}
}

func TestSendGridConfigurationValidation(t *testing.T) {
	base := validSendGridConfig("https://example.com")
	cases := []SendGridConfig{
		{},
		func() SendGridConfig {
			value := base
			value.APIKey = "invalid"
			return value
		}(),
		func() SendGridConfig {
			value := base
			value.From.Email = "Display <security@example.com>"
			return value
		}(),
		func() SendGridConfig {
			value := base
			value.To = nil
			return value
		}(),
		func() SendGridConfig {
			value := base
			value.To = []EmailAddress{{Email: "owner@example.com"}, {Email: "OWNER@example.com"}}
			return value
		}(),
		func() SendGridConfig {
			value := base
			value.BaseURL = "http://example.com"
			return value
		}(),
		func() SendGridConfig {
			value := base
			value.Timeout = -1
			return value
		}(),
	}
	for index, config := range cases {
		if _, err := NewSendGridChannel(config, nil); err == nil {
			t.Fatalf("invalid SendGrid config %d accepted", index)
		}
	}
}

func TestWebhookNon2xxIsRetryableWithoutSecretExposure(t *testing.T) {
	bearerToken := "bearer-secret-non2xx"
	headerSecret := "header-secret-non2xx"
	querySecret := "query-secret-non2xx"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Retry-After", "7")
		writer.Header().Set("X-Request-ID", bearerToken)
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(
			writer,
			bearerToken+" "+headerSecret+" "+querySecret,
		)
	}))
	defer server.Close()

	channel, err := NewWebhookChannel(WebhookConfig{
		URL:         server.URL + "/hook/token-path-123456?sig=" + querySecret,
		BearerToken: bearerToken,
		Headers:     map[string]string{"X-Webhook-Secret": headerSecret},
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if deliveryError.StatusCode != http.StatusTooManyRequests ||
		!deliveryError.Retryable ||
		deliveryError.RetryAfter != 7*time.Second ||
		deliveryError.DeliveryID != "" {
		t.Fatalf("unexpected webhook failure metadata: %#v", deliveryError)
	}
	assertErrorExcludes(t, err, bearerToken, headerSecret, querySecret)
}

func TestDiscordNon2xxDoesNotReturnWebhookToken(t *testing.T) {
	webhookToken := "discord-secret-token-123456"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Request-ID", webhookToken)
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"message":"`+webhookToken+`"}`)
	}))
	defer server.Close()

	channel, err := NewDiscordChannel(DiscordConfig{
		WebhookURL: server.URL + "/api/webhooks/1/" + webhookToken,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if !deliveryError.Retryable || deliveryError.DeliveryID != "" {
		t.Fatalf("unexpected Discord failure metadata: %#v", deliveryError)
	}
	assertErrorExcludes(t, err, webhookToken)
}

func TestTelegramNon2xxReturnsSafeRetryMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(
			writer,
			`{"ok":false,"error_code":429,"description":"`+
				testTelegramToken+
				`","parameters":{"retry_after":11}}`,
		)
	}))
	defer server.Close()

	channel, err := NewTelegramChannel(TelegramConfig{
		BotToken: testTelegramToken,
		ChatID:   "-1001234567890",
		BaseURL:  server.URL,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if deliveryError.StatusCode != http.StatusTooManyRequests ||
		!deliveryError.Retryable ||
		deliveryError.RetryAfter != 11*time.Second {
		t.Fatalf("unexpected Telegram failure metadata: %#v", deliveryError)
	}
	assertErrorExcludes(t, err, testTelegramToken)
}

func TestTelegramHTTP200ProviderRejectionIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(
			writer,
			`{"ok":false,"error_code":400,"description":"invalid request"}`,
		)
	}))
	defer server.Close()

	channel, err := NewTelegramChannel(TelegramConfig{
		BotToken: testTelegramToken,
		ChatID:   "-1001234567890",
		BaseURL:  server.URL,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if deliveryError.StatusCode != http.StatusOK || deliveryError.Retryable {
		t.Fatalf("unexpected Telegram rejection metadata: %#v", deliveryError)
	}
	if !strings.Contains(err.Error(), "rejected by the provider") {
		t.Fatalf("unexpected rejection error: %v", err)
	}
}

func TestSendGridNon2xxDoesNotReturnAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Message-ID", testSendGridKey)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, `{"errors":[{"message":"`+testSendGridKey+`"}]}`)
	}))
	defer server.Close()

	channel, err := NewSendGridChannel(validSendGridConfig(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if !deliveryError.Retryable || deliveryError.DeliveryID != "" {
		t.Fatalf("unexpected SendGrid failure metadata: %#v", deliveryError)
	}
	assertErrorExcludes(t, err, testSendGridKey)
}

func TestChannelFormattingRedactsCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	webhookToken := "webhook-format-secret-123456"
	webhook, err := NewWebhookChannel(WebhookConfig{
		URL:         server.URL + "/hook/path-secret-123456",
		BearerToken: webhookToken,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	discordToken := "discord-format-secret-123456"
	discord, err := NewDiscordChannel(DiscordConfig{
		WebhookURL: server.URL + "/api/webhooks/1/" + discordToken,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	telegram, err := NewTelegramChannel(TelegramConfig{
		BotToken: testTelegramToken,
		ChatID:   "-1001234567890",
		BaseURL:  server.URL,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sendGrid, err := NewSendGridChannel(validSendGridConfig(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		channel any
		secrets []string
	}{
		{channel: webhook, secrets: []string{webhookToken, "path-secret-123456"}},
		{channel: discord, secrets: []string{discordToken}},
		{channel: telegram, secrets: []string{testTelegramToken}},
		{channel: sendGrid, secrets: []string{testSendGridKey}},
	}
	for _, test := range tests {
		renderings := []string{
			fmt.Sprintf("%v", test.channel),
			fmt.Sprintf("%+v", test.channel),
			fmt.Sprintf("%#v", test.channel),
		}
		for _, secret := range test.secrets {
			for _, rendering := range renderings {
				if strings.Contains(rendering, secret) {
					t.Fatalf("formatted channel exposes secret %q: %s", secret, rendering)
				}
			}
		}
	}
}

func TestAllHTTPChannelsHonorCanceledCallerContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	webhook, err := NewWebhookChannel(WebhookConfig{URL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	discord, err := NewDiscordChannel(DiscordConfig{
		WebhookURL: server.URL + "/api/webhooks/1/discord-token-123456",
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	telegram, err := NewTelegramChannel(TelegramConfig{
		BotToken: testTelegramToken,
		ChatID:   "-1001234567890",
		BaseURL:  server.URL,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sendGrid, err := NewSendGridChannel(validSendGridConfig(server.URL), server.Client())
	if err != nil {
		t.Fatal(err)
	}

	channels := []DetailedChannel{webhook, discord, telegram, sendGrid}
	for _, channel := range channels {
		t.Run(channel.Name(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := channel.Deliver(ctx, testNotification())
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestWebhookInheritsCallerDeadlineAndEnforcesOwnBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(200 * time.Millisecond):
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	t.Run("caller deadline", func(t *testing.T) {
		channel, err := NewWebhookChannel(WebhookConfig{
			URL:     server.URL,
			Timeout: time.Second,
		}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err = channel.Deliver(ctx, testNotification())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error = %v", err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("caller deadline was not inherited")
		}
	})

	t.Run("channel bound", func(t *testing.T) {
		channel, err := NewWebhookChannel(WebhookConfig{
			URL:     server.URL,
			Timeout: 20 * time.Millisecond,
		}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, err = channel.Deliver(context.Background(), testNotification())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout error = %v", err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("channel timeout did not bound the request")
		}
	})
}

func TestResponseBodyIsBoundedAndClosed(t *testing.T) {
	body := &trackingReadCloser{
		reader: bytes.NewReader(bytes.Repeat([]byte("x"), maxResponseBodyBytes+1024)),
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
			Request:    request,
		}, nil
	})}
	channel, err := NewWebhookChannel(WebhookConfig{
		URL: "https://example.invalid/hook/secret-path-123456",
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if deliveryError.kind != "response-too-large" {
		t.Fatalf("unexpected bounded-body error: %#v", deliveryError)
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed")
	}
	if got := body.read.Load(); got > maxResponseBodyBytes+1 {
		t.Fatalf("read %d response bytes, maximum is %d", got, maxResponseBodyBytes+1)
	}
}

func TestHTTPChannelsRefuseRedirects(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	secret := "redirect-secret-123456"
	channel, err := NewWebhookChannel(WebhookConfig{
		URL:         source.URL + "/hook",
		BearerToken: secret,
	}, source.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.Deliver(context.Background(), testNotification())
	deliveryError := requireDeliveryError(t, err)
	if deliveryError.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect status = %d", deliveryError.StatusCode)
	}
	if redirected.Load() {
		t.Fatal("redirect was followed")
	}
	assertErrorExcludes(t, err, secret, target.URL)
}

func requireDeliveryError(t *testing.T, err error) *DeliveryError {
	t.Helper()
	if err == nil {
		t.Fatal("expected delivery error")
	}
	var deliveryError *DeliveryError
	if !errors.As(err, &deliveryError) {
		t.Fatalf("error type = %T, want *DeliveryError: %v", err, err)
	}
	return deliveryError
}

func assertErrorExcludes(t *testing.T, err error, secrets ...string) {
	t.Helper()
	renderings := []string{
		err.Error(),
		fmt.Sprintf("%v", err),
		fmt.Sprintf("%+v", err),
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		for _, rendering := range renderings {
			if strings.Contains(rendering, secret) {
				t.Fatalf("error exposes secret %q: %s", secret, rendering)
			}
		}
	}
}

func validSendGridConfig(baseURL string) SendGridConfig {
	return SendGridConfig{
		APIKey: testSendGridKey,
		From: EmailAddress{
			Email: "security@example.com",
			Name:  "Security",
		},
		To: []EmailAddress{{
			Email: "owner@example.com",
			Name:  "Owner",
		}},
		BaseURL: baseURL,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type trackingReadCloser struct {
	reader *bytes.Reader
	read   atomic.Int64
	closed atomic.Bool
}

func (body *trackingReadCloser) Read(destination []byte) (int, error) {
	count, err := body.reader.Read(destination)
	body.read.Add(int64(count))
	return count, err
}

func (body *trackingReadCloser) Close() error {
	body.closed.Store(true)
	return nil
}
