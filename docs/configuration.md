# Configuration

Everything is **enabled by default**. You can change behavior three ways, in
increasing precedence:

1. The default config shipped with the tool (`config/default.yaml`).
2. Your user config: `~/.config/oh-my-safety/config.yaml`.
3. CLI overrides (`enable`/`disable`/`set`), stored in `~/.config/oh-my-safety/overrides.conf`.

## The easy way: the CLI

```bash
oh-my-safety checks                       # see every check and its on/off state
oh-my-safety disable privacy              # turn off a whole category
oh-my-safety enable  wallet-guard         # turn a single check back on
oh-my-safety set notifications.min_severity critical
```

`enable`/`disable` accept a **check name** (e.g. `dns-leak`, `persistence-scan`)
or a **category** (`privacy`, `security`). `set` writes any dotted config path.
These write to `overrides.conf` and take effect immediately — no file editing.

## The config file

Copy the shipped default and edit it:
```bash
mkdir -p ~/.config/oh-my-safety
cp "$(brew --prefix)/opt/oh-my-safety/libexec/config/default.yaml" ~/.config/oh-my-safety/config.yaml
```

Key sections:

```yaml
monitoring:
  interval: 300         # seconds between full scans (agent)
  fast_interval: 15     # seconds between quick VPN route-flip checks

notifications:
  enabled: true
  min_severity: warn              # info | warn | critical
  renotify_interval_hours: 4      # how often to re-alert an unresolved critical

tools:                            # opt-in; used only if enabled AND installed
  gitleaks: { enabled: false }

categories:
  privacy:  { enabled: true }
  security: { enabled: true }

checks:
  privacy:
    ip_address:
      enabled: true
      services: [ifconfig.me, api.ipify.org, icanhazip.com]
  security:
    hardening_posture:
      enabled: true
      xprotect_max_age_days: 45
      allow_remote_login: false
```

Each check's own knobs are documented on its page in the
[checks catalog](checks/README.md).

### Supported YAML subset
The parser is pure bash (no dependencies), so it accepts a deliberate subset:
2-space indentation, `key: value`, block lists (`- item`), and `#` comments
(whole-line or inline). It does **not** support flow collections (`{}`/`[]`),
multi-line strings, anchors, or tabs. `oh-my-safety doctor` warns if your file
fails to parse.

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
