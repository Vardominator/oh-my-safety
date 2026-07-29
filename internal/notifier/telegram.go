package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const defaultTelegramBaseURL = "https://api.telegram.org"

var (
	telegramBotTokenPattern = regexp.MustCompile(`^[0-9]{5,}:[A-Za-z0-9_-]{20,}$`)
	telegramChatIDPattern   = regexp.MustCompile(`^(?:-?[0-9]{1,32}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

type TelegramConfig struct {
	BotToken string
	ChatID   string
	BaseURL  string
	Timeout  time.Duration
}

type TelegramChannel struct {
	endpoint string
	chatID   string
	token    string
	sender   httpSender
}

type telegramPayload struct {
	ChatID             string                     `json:"chat_id"`
	Text               string                     `json:"text"`
	ProtectContent     bool                       `json:"protect_content"`
	LinkPreviewOptions telegramLinkPreviewOptions `json:"link_preview_options"`
}

type telegramLinkPreviewOptions struct {
	IsDisabled bool `json:"is_disabled"`
}

type telegramResponse struct {
	OK        bool `json:"ok"`
	ErrorCode int  `json:"error_code,omitempty"`
	Result    *struct {
		MessageID int64 `json:"message_id"`
	} `json:"result,omitempty"`
	Parameters *struct {
		RetryAfter int64 `json:"retry_after,omitempty"`
	} `json:"parameters,omitempty"`
}

func NewTelegramChannel(config TelegramConfig, client *http.Client) (*TelegramChannel, error) {
	if !telegramBotTokenPattern.MatchString(config.BotToken) {
		return nil, errors.New("Telegram bot token has an invalid format")
	}
	if !telegramChatIDPattern.MatchString(config.ChatID) {
		return nil, errors.New("Telegram chat ID has an invalid format")
	}
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultTelegramBaseURL
	}
	base, err := validateEndpoint(baseURL, false)
	if err != nil {
		return nil, errors.New("invalid Telegram base URL")
	}
	sender, err := newHTTPSender(client, config.Timeout)
	if err != nil {
		return nil, err
	}
	return &TelegramChannel{
		endpoint: appendURLPath(base, "/bot"+config.BotToken+"/sendMessage"),
		chatID:   config.ChatID,
		token:    config.BotToken,
		sender:   sender,
	}, nil
}

func (channel *TelegramChannel) Name() string {
	return "telegram"
}

func (channel *TelegramChannel) String() string {
	return channel.Name()
}

func (*TelegramChannel) GoString() string {
	return "notifier.TelegramChannel{credentials:redacted}"
}

func (channel *TelegramChannel) Notify(ctx context.Context, notification Notification) error {
	_, err := channel.Deliver(ctx, notification)
	return err
}

func (channel *TelegramChannel) Deliver(
	ctx context.Context,
	notification Notification,
) (ProviderDelivery, error) {
	if err := notification.Validate(); err != nil {
		return ProviderDelivery{}, err
	}
	text := notification.Title + "\n\n" + notification.Body
	response, err := channel.sender.postJSON(
		ctx,
		channel.Name(),
		channel.endpoint,
		nil,
		telegramPayload{
			ChatID:         channel.chatID,
			Text:           truncateRunes(text, 4096),
			ProtectContent: true,
			LinkPreviewOptions: telegramLinkPreviewOptions{
				IsDisabled: true,
			},
		},
		channel.token,
	)
	if err != nil {
		return ProviderDelivery{}, err
	}

	var providerResponse telegramResponse
	parsed := len(response.body) > 0 && json.Unmarshal(response.body, &providerResponse) == nil
	retryAfter := time.Duration(0)
	if parsed &&
		providerResponse.Parameters != nil &&
		providerResponse.Parameters.RetryAfter > 0 {
		retryAfter = time.Duration(providerResponse.Parameters.RetryAfter) * time.Second
		if retryAfter > 24*time.Hour {
			retryAfter = 24 * time.Hour
		}
	}
	if !isSuccess(response.statusCode) {
		return ProviderDelivery{}, providerStatusError(
			channel.Name(),
			response,
			"",
			retryAfter,
		)
	}
	if !parsed || !providerResponse.OK {
		retryable := parsed && isRetryableStatus(providerResponse.ErrorCode)
		return ProviderDelivery{}, &DeliveryError{
			Channel:    channel.Name(),
			StatusCode: response.statusCode,
			Retryable:  retryable,
			RetryAfter: retryAfter,
			kind:       "provider-rejected",
		}
	}

	deliveryID := ""
	if providerResponse.Result != nil && providerResponse.Result.MessageID > 0 {
		deliveryID = strconv.FormatInt(providerResponse.Result.MessageID, 10)
	}
	return ProviderDelivery{
		Channel:    channel.Name(),
		ID:         deliveryID,
		StatusCode: response.statusCode,
	}, nil
}
