package notifier

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

const defaultSendGridBaseURL = "https://api.sendgrid.com"

var sendGridAPIKeyPattern = regexp.MustCompile(
	`^SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$`,
)

type EmailAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type SendGridConfig struct {
	APIKey  string
	From    EmailAddress
	To      []EmailAddress
	BaseURL string
	Timeout time.Duration
}

type SendGridChannel struct {
	apiKey   string
	endpoint string
	from     EmailAddress
	to       []EmailAddress
	sender   httpSender
}

type sendGridPayload struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             EmailAddress              `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
}

type sendGridPersonalization struct {
	To []EmailAddress `json:"to"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func NewSendGridChannel(config SendGridConfig, client *http.Client) (*SendGridChannel, error) {
	if !sendGridAPIKeyPattern.MatchString(config.APIKey) {
		return nil, errors.New("SendGrid API key has an invalid format")
	}
	if err := validateEmailAddress(config.From); err != nil {
		return nil, errors.New("SendGrid sender address is invalid")
	}
	if len(config.To) == 0 || len(config.To) > 100 {
		return nil, errors.New("SendGrid requires between 1 and 100 recipients")
	}
	recipients := make([]EmailAddress, len(config.To))
	seen := make(map[string]struct{}, len(config.To))
	for index, recipient := range config.To {
		if err := validateEmailAddress(recipient); err != nil {
			return nil, errors.New("SendGrid recipient address is invalid")
		}
		normalized := strings.ToLower(recipient.Email)
		if _, duplicate := seen[normalized]; duplicate {
			return nil, errors.New("SendGrid recipient addresses must be unique")
		}
		seen[normalized] = struct{}{}
		recipients[index] = recipient
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultSendGridBaseURL
	}
	base, err := validateEndpoint(baseURL, false)
	if err != nil {
		return nil, errors.New("invalid SendGrid base URL")
	}
	sender, err := newHTTPSender(client, config.Timeout)
	if err != nil {
		return nil, err
	}
	return &SendGridChannel{
		apiKey:   config.APIKey,
		endpoint: appendURLPath(base, "/v3/mail/send"),
		from:     config.From,
		to:       recipients,
		sender:   sender,
	}, nil
}

func (channel *SendGridChannel) Name() string {
	return "sendgrid"
}

func (channel *SendGridChannel) String() string {
	return channel.Name()
}

func (*SendGridChannel) GoString() string {
	return "notifier.SendGridChannel{credentials:redacted}"
}

func (channel *SendGridChannel) Notify(ctx context.Context, notification Notification) error {
	_, err := channel.Deliver(ctx, notification)
	return err
}

func (channel *SendGridChannel) Deliver(
	ctx context.Context,
	notification Notification,
) (ProviderDelivery, error) {
	if err := notification.Validate(); err != nil {
		return ProviderDelivery{}, err
	}
	response, err := channel.sender.postJSON(
		ctx,
		channel.Name(),
		channel.endpoint,
		http.Header{
			"Authorization": []string{"Bearer " + channel.apiKey},
		},
		sendGridPayload{
			Personalizations: []sendGridPersonalization{{To: channel.to}},
			From:             channel.from,
			Subject:          truncateRunes(notification.Title, 998),
			Content: []sendGridContent{{
				Type:  "text/plain",
				Value: notification.Body,
			}},
		},
		channel.apiKey,
	)
	if err != nil {
		return ProviderDelivery{}, err
	}
	deliveryID := safeProviderID(firstDeliveryHeader(response.header), channel.apiKey)
	if !isSuccess(response.statusCode) {
		return ProviderDelivery{}, providerStatusError(
			channel.Name(),
			response,
			deliveryID,
			0,
		)
	}
	return ProviderDelivery{
		Channel:    channel.Name(),
		ID:         deliveryID,
		StatusCode: response.statusCode,
	}, nil
}

func validateEmailAddress(address EmailAddress) error {
	if address.Email == "" ||
		len(address.Email) > 254 ||
		address.Email != strings.TrimSpace(address.Email) ||
		strings.ContainsAny(address.Email, "\r\n\t") {
		return errors.New("invalid email address")
	}
	parsed, err := mail.ParseAddress(address.Email)
	if err != nil || parsed.Name != "" || parsed.Address != address.Email {
		return errors.New("invalid email address")
	}
	if len([]rune(address.Name)) > 256 || strings.ContainsAny(address.Name, "\r\n") {
		return errors.New("invalid email display name")
	}
	return nil
}
