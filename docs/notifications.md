# Notifications

Native desktop notifications remain the default on macOS. Linux uses
`notify-send` when available and otherwise keeps the finding in local status and
history. Optional network channels are available for Discord, Telegram,
SendGrid email, WhatsApp Cloud API, and a generic HTTPS webhook.

The multi-channel notification configuration is available in v0.3.0. The
v0.2.3 compatibility line retains native macOS notifications but does not
contain these external channel adapters.

External delivery has three independent gates:

1. `notifications.enabled` must be true.
2. `notifications.external.enabled` and the specific channel must both be true.
3. The active profile connectivity must be `connected`.

This means an `offline` or `airgapped` profile cannot send externally even if a
stale channel setting remains enabled.

Inspect the effective configuration without printing credential values:

```bash
oh-my-safety notifications show
oh-my-safety notifications test
```

## Safe defaults

- Every external channel is disabled.
- Credentials are read from environment variables or the separate strict
  credential file, never from `config.yaml` or `overrides.conf`.
- External messages omit finding detail by default. They tell the recipient to
  inspect `oh-my-safety status` locally.
- Provider responses, tokens, webhook URLs, and authorization headers are not
  written to logs. Local history records only accepted/failed delivery metadata.
- Notification HTTP requests do not follow redirects. The portable Go
  transports also reject redirects so a provider cannot forward a credential
  to another host.
- A provider failure never changes a check result or turns a failed delivery
  into an all-clear.

To include the local finding summary in external messages:

```bash
oh-my-safety set notifications.external.include_details true
```

Paths, usernames, host details, and check summaries may still be sensitive.
Keep this false unless the destination and its retention policy are trusted.

## Discord

Create a channel webhook, place the URL in the process environment, then enable
both gates:

```bash
export OMS_DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'
oh-my-safety set notifications.external.enabled true
oh-my-safety set notifications.channels.discord.enabled true
oh-my-safety notifications test
```

Put the export in the environment used by the service, not in a shell history or
world-readable file.

## Telegram

Create a bot, obtain its destination chat ID, and configure:

```bash
export OMS_TELEGRAM_BOT_TOKEN='...'
oh-my-safety set notifications.channels.telegram.chat_id '123456789'
oh-my-safety set notifications.external.enabled true
oh-my-safety set notifications.channels.telegram.enabled true
```

The bot token is part of the Telegram request URL, but the implementation keeps
the URL in a mode-`600` temporary curl configuration and removes it immediately.

## SendGrid email

Use a narrowly scoped SendGrid API key and a verified sender:

```bash
export SENDGRID_API_KEY='...'
oh-my-safety set notifications.channels.sendgrid.from 'safety@example.com'
oh-my-safety set notifications.channels.sendgrid.to 'owner@example.com'
oh-my-safety set notifications.external.enabled true
oh-my-safety set notifications.channels.sendgrid.enabled true
```

Email destinations commonly retain and forward messages. The generic local
review prompt is therefore especially important.

## WhatsApp Cloud API

WhatsApp requires a Cloud API access token, phone-number ID, recipient, and an
explicit supported Graph API version:

```bash
export OMS_WHATSAPP_ACCESS_TOKEN='...'
oh-my-safety set notifications.channels.whatsapp.phone_number_id '...'
oh-my-safety set notifications.channels.whatsapp.to '15551234567'
oh-my-safety set notifications.channels.whatsapp.graph_version 'vNN.0'
oh-my-safety set notifications.external.enabled true
oh-my-safety set notifications.channels.whatsapp.enabled true
```

Meta retires Graph API versions on a schedule, so the project intentionally
does not silently change this value on a running installation. Confirm the
currently supported version in Meta's official documentation.

## Generic webhook

The generic webhook sends a small versioned JSON envelope:

```bash
export OMS_WEBHOOK_URL='https://alerts.example.net/oh-my-safety'
export OMS_WEBHOOK_BEARER='...'
oh-my-safety set notifications.channels.webhook.bearer_token_env OMS_WEBHOOK_BEARER
oh-my-safety set notifications.external.enabled true
oh-my-safety set notifications.channels.webhook.enabled true
```

The receiver should authenticate requests, enforce TLS, rate-limit input, and
discard unexpected fields. A `2xx` response means only that delivery was
accepted; it does not resolve the finding.

## Running under a service manager

Interactive shell exports are not automatically inherited by launchd,
Homebrew services, or a systemd user service. For continuous delivery, create
the dedicated local credential file:

```bash
install -d -m 700 "${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety"
umask 077
printf '%s\n' \
  'OMS_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/REPLACE_ME' \
  'SENDGRID_API_KEY=REPLACE_ME' \
  > "${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety/notifications.env"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety/notifications.env"
```

Edit that example to retain only the variables you use. The parser accepts
literal `NAME=value` rows, blank lines, and full-line comments. It does not
source the file, expand `$variables`, run substitutions, or accept duplicate
names. The file must be at most 64 KiB and must be a regular non-symlink owned
by the running user with mode `600` or `400` and no extended ACL; otherwise it
is rejected. A process environment variable takes precedence over a same-named
file value.

By default the path follows
`$XDG_CONFIG_HOME/oh-my-safety/notifications.env`, falling back to
`~/.config/oh-my-safety/notifications.env`. This lets launchd, Homebrew
services, and systemd user services use the same per-user configuration
location as the CLI.

This file is notification-specific. It may hold the Discord, Telegram,
SendGrid, WhatsApp, and webhook variables named by `notifications.channels`,
but it is not used for HIBP monitored-account credentials or organization
enrollment.

Change the path if necessary:

```bash
oh-my-safety set notifications.external.credentials_file \
  ~/.config/oh-my-safety/notifications.env
```

Never add credentials to the packaged unit, repository, ordinary YAML
configuration, organization policy, or a world-readable file.

After changing service credentials, restart the service and run:

```bash
# Homebrew:
brew services restart oh-my-safety
# Linux package or manual systemd install:
systemctl --user restart oh-my-safety.service

oh-my-safety notifications show
oh-my-safety notifications test
oh-my-safety history --limit 20
```
