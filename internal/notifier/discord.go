package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

type DiscordConfig struct {
	WebhookURL string
	Username   string
	Timeout    time.Duration
}

type DiscordChannel struct {
	endpoint string
	username string
	secrets  []string
	sender   httpSender
}

type discordPayload struct {
	Username        string                 `json:"username,omitempty"`
	Embeds          []discordEmbed         `json:"embeds"`
	AllowedMentions discordAllowedMentions `json:"allowed_mentions"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Footer      *discordFooter `json:"footer,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

type discordAllowedMentions struct {
	Parse []string `json:"parse"`
}

func NewDiscordChannel(config DiscordConfig, client *http.Client) (*DiscordChannel, error) {
	endpoint, err := validateEndpoint(config.WebhookURL, true)
	if err != nil {
		return nil, errors.New("invalid Discord webhook configuration")
	}
	if len([]rune(config.Username)) > 80 || strings.ContainsAny(config.Username, "\r\n") {
		return nil, errors.New("Discord username exceeds 80 characters or contains control characters")
	}
	query := endpoint.Query()
	query.Set("wait", "true")
	endpoint.RawQuery = query.Encode()

	sender, err := newHTTPSender(client, config.Timeout)
	if err != nil {
		return nil, err
	}
	return &DiscordChannel{
		endpoint: endpoint.String(),
		username: config.Username,
		secrets:  endpointSecretFragments(endpoint),
		sender:   sender,
	}, nil
}

func (channel *DiscordChannel) Name() string {
	return "discord"
}

func (channel *DiscordChannel) String() string {
	return channel.Name()
}

func (*DiscordChannel) GoString() string {
	return "notifier.DiscordChannel{credentials:redacted}"
}

func (channel *DiscordChannel) Notify(ctx context.Context, notification Notification) error {
	_, err := channel.Deliver(ctx, notification)
	return err
}

func (channel *DiscordChannel) Deliver(
	ctx context.Context,
	notification Notification,
) (ProviderDelivery, error) {
	if err := notification.Validate(); err != nil {
		return ProviderDelivery{}, err
	}
	embed := discordEmbed{
		Title:       truncateRunes(notification.Title, 256),
		Description: truncateRunes(notification.Body, 4096),
		Color:       discordSeverityColor(notification.Severity),
	}
	if notification.FindingID != "" {
		embed.Footer = &discordFooter{
			Text: "Finding: " + truncateRunes(notification.FindingID, 1900),
		}
	}
	payload := discordPayload{
		Username: channel.username,
		Embeds:   []discordEmbed{embed},
		AllowedMentions: discordAllowedMentions{
			Parse: []string{},
		},
	}
	response, err := channel.sender.postJSON(
		ctx,
		"discord",
		channel.endpoint,
		nil,
		payload,
		channel.secrets...,
	)
	if err != nil {
		return ProviderDelivery{}, err
	}
	deliveryID := safeProviderID(firstDeliveryHeader(response.header), channel.secrets...)
	if !isSuccess(response.statusCode) {
		return ProviderDelivery{}, providerStatusError("discord", response, deliveryID, 0)
	}
	if len(response.body) > 0 {
		var message struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(response.body, &message) == nil {
			if parsedID := safeProviderID(message.ID, channel.secrets...); parsedID != "" {
				deliveryID = parsedID
			}
		}
	}
	return ProviderDelivery{
		Channel:    channel.Name(),
		ID:         deliveryID,
		StatusCode: response.statusCode,
	}, nil
}

func discordSeverityColor(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 0xe74c3c
	case model.SeverityWarn:
		return 0xf39c12
	default:
		return 0x3498db
	}
}
