# Configuration

This page describes the v0.3.0 configuration. The v0.2.3 compatibility line
accepts the same basic default/user/override layers but does not implement
every profile, notification, portable-core, or organization key shown below.

Core privacy and security checks are enabled by default. The deeper
`secrets-content` and `yara-scan` checks are opt-in because they require external
tools or trusted local rules. A standalone endpoint resolves three layers, in
increasing precedence:

1. The default config shipped with the tool (`config/default.yaml`).
2. Your user config: `~/.config/oh-my-safety/config.yaml`.
3. CLI overrides (`enable`/`disable`/`set`/`profile set`), stored in `~/.config/oh-my-safety/overrides.conf`.

## The easy way: the CLI

```bash
oh-my-safety checks                       # see every check and its on/off state
oh-my-safety disable privacy              # turn off a whole category
oh-my-safety enable  wallet-guard         # turn a single check back on
oh-my-safety set notifications.min_severity critical
oh-my-safety profile set personal-strict
```

`enable`/`disable` accept a **check name** (e.g. `dns-leak`, `persistence-scan`)
or a **category** (`privacy`, `security`). `set` writes any dotted config path.
These write to `overrides.conf`; no YAML editing is required. A profile writes
all of its controlled values as one atomic bundle and preserves unrelated
overrides. New commands read the change immediately. The monitor reloads
configuration between scheduler
ticks; a running check finishes with the snapshot it started with. Invalid
monitoring intervals are rejected and the previous known-good configuration
remains active.

## The config file

Copy the shipped default and edit it:

```bash
mkdir -p ~/.config/oh-my-safety
cp "$(brew --prefix)/opt/oh-my-safety/libexec/config/default.yaml" ~/.config/oh-my-safety/config.yaml
```

That source path is for Homebrew. Native Linux packages use
`/usr/lib/oh-my-safety/config/default.yaml`; a default source install uses
`~/.local/lib/oh-my-safety/config/default.yaml`.

Key sections:

```yaml
profile:
  name: personal-balanced
  workload: workstation
  protection: balanced
  management: standalone
  connectivity: connected

monitoring:
  interval: 300         # seconds between full scans (agent)
  fast_interval: 15     # seconds between quick VPN route-flip checks
  deep: false

notifications:
  enabled: true
  min_severity: warn
  renotify_interval_hours: 4
  external:
    enabled: false
    include_details: false
    # Empty follows XDG_CONFIG_HOME, then ~/.config.
    credentials_file: ""
  channels:
    discord:
      enabled: false
      webhook_url_env: OMS_DISCORD_WEBHOOK_URL

tools:
  gitleaks:
    enabled: false

categories:
  privacy:
    enabled: true
  security:
    enabled: true

checks:
  privacy:
    ip_address:
      enabled: true
      services:
        - ifconfig.me
        - api.ipify.org
        - icanhazip.com
  security:
    hardening_posture:
      enabled: true
      xprotect_max_age_days: 45
      allow_remote_login: false
    local_secret_scan:
      enabled: false
      scan_roots:
        - ~/Projects
    breach_exposure:
      enabled: false
      api_key_env: HIBP_API_KEY
      account_envs:
        - OMS_MONITORED_EMAIL

organization:
  enabled: false
  sync_interval_seconds: 300
  enrollment_token_env: OMS_ENROLLMENT_TOKEN
```

See [profiles.md](profiles.md) for connectivity enforcement and
[notifications.md](notifications.md) for every channel, credential variable,
the strict service credential-file format, and disclosed field.

Enrollment tokens and monitored accounts are passed through named environment
variables. Notification credentials may come from the process environment or
the separate user-owned mode-`600` credential file. YAML and CLI overrides
contain only variable names and the credential-file path—never secret values.
An empty credential-file path uses
`$XDG_CONFIG_HOME/oh-my-safety/notifications.env`, falling back to
`~/.config/oh-my-safety/notifications.env`.
The notification credential file is intentionally read only by notification
channels; it is not a general environment file and cannot supply HIBP account
values, HIBP API keys, or organization enrollment tokens.

When an endpoint is explicitly enrolled, the last cached controller policy is
accepted only after signature/pin verification. Its explicitly controlled
profile, cadence, remediation intent, reporting cadence, and per-check
enable/disable rows form the highest-precedence config layer. Unmentioned
checks keep their local setting. `oh-my-safety organization policy` shows the
bounded effective policy rows.

Each check's own knobs are documented on its page in the
[checks catalog](checks/README.md).

### Supported YAML subset
The parser is pure bash (no dependencies), so it accepts a deliberate subset:
2-space indentation, `key: value`, block lists (`- item`), quoted or unquoted
scalars, and comments. It does **not** support flow collections (`{}`/`[]`),
multi-line strings, anchors, maps nested inside list items, or tabs. Use the
block-style example above rather than inline maps or arrays.

Check the effective configuration and setup after editing:

```bash
oh-my-safety checks
oh-my-safety doctor
```

## Responding to findings

When a check reports something, you have three moves:

- **Fix and confirm.** Address the issue (e.g. `chmod 600 ~/.netrc`), then:
  ```bash
  oh-my-safety recheck secrets-exposure
  ```
- **Ignore a specific item you accept.** Every finding prints a stable
  `[id: …]`. Suppress just that one:
  ```bash
  oh-my-safety ignore secrets-exposure 'sec:/Users/me/.netrc:perms'
  ```
  Ignored items live in `~/.local/state/oh-my-safety/allowlist/<check>.list`
  (entries may be exact IDs or globs). List them with `oh-my-safety ignored <check>`.
- **Accept a new baseline.** For drift checks, if a flagged change is expected
  (you installed an app, opened a port):
  ```bash
  oh-my-safety accept persistence-scan
  ```

## Custom checks

Drop your own check into `~/.config/oh-my-safety/checks/*.sh` and it's
auto-discovered — see [extending.md](extending.md). Add more discovery
directories with `custom_check_paths` in config.
