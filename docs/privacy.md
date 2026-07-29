# Privacy promise

oh-my-safety has no telemetry, analytics, crash reporting, usage statistics,
update pings, hosted account, or vendor collection endpoint. Core endpoint
scanning and evidence storage are local.

Network access exists only in three explicit capability classes:

1. Connected privacy checks that measure the endpoint's public network identity.
2. Optional exposure and notification adapters that are disabled by default,
   individually configured, and blocked by offline/air-gapped profiles.
3. Explicitly enrolled managed endpoints that initiate TLS connections to a
   self-hosted organization controller and send only the closed redacted-report
   contract.

Installation and update tools are outside those runtime capability classes.
Homebrew, `apt`, Snap, `curl`, Git, and the operating system's package manager
contact their configured repositories (GitHub, GitHub Pages, the Snap Store,
and/or distribution mirrors) and disclose ordinary request metadata and source
IP as part of software installation. That package-manager traffic is not
oh-my-safety telemetry and does not contain scan findings, baselines, or local
evidence. Air-gapped operators should import reviewed packages and signed
metadata through their normal offline software-supply process instead.

The security check directory is CI-enforced to contain no direct network
client calls. The one network-capable security check, `breach-exposure`, is
disabled by default, declares `CHECK_REQUIRES_NETWORK=true`, and delegates to
the bounded exposure adapter whose contract is shown before use.

## Privacy-check endpoints

| HTTPS/DNS endpoint | Field sent | Why | Disable with |
|--------------------|------------|-----|--------------|
| `ifconfig.me`, `api.ipify.org`, `icanhazip.com` | ordinary request metadata and source IP | Look up the endpoint's public IP | `oh-my-safety disable ip-address` |
| `api64.ipify.org` (`v6.ident.me` fallback on Linux) | ordinary request metadata and source IPv6 | Detect IPv6 escaping the tunnel | `oh-my-safety disable ipv6-leak` |
| `ns1.google.com` (TXT `o-o.myaddr.l.google.com`) | DNS query and resolver/source metadata | Identify DNS resolver egress | `oh-my-safety disable dns-leak` |

You can change the IP-lookup services in config (`checks.privacy.ip_address.services`),
or disable the whole category with `oh-my-safety disable privacy`.

Service hostnames without a scheme are normalized to HTTPS. A user may replace
the public-IP service list, in which case that endpoint becomes part of their
configuration.

## Optional notification endpoints

External delivery requires the global gate, a channel gate, and a `connected`
profile. Finding details are omitted by default.

| Provider | Default endpoint | Fields sent |
|----------|------------------|-------------|
| Discord | URL held in `OMS_DISCORD_WEBHOOK_URL` | title/check name and generic local-review prompt; local finding summary only if explicitly enabled |
| Telegram | `api.telegram.org` | configured chat ID and the same message; bot token authenticates the request |
| SendGrid | `api.sendgrid.com/v3/mail/send` | configured sender/recipient, title, and the same message |
| WhatsApp Cloud API | configured `graph.facebook.com/<version>/<phone-id>/messages` | configured recipient, title, and the same message |
| Generic webhook | URL held in `OMS_WEBHOOK_URL` | versioned notification JSON; optional bearer authentication |

Provider delivery metadata in local history contains only the channel name,
success/failure, and safe HTTP status. Tokens, webhook URLs, provider response
bodies, and authorization headers are suppressed.

## Optional internet-exposure endpoints

The portable core contains explicit adapters for
[Have I Been Pwned](https://haveibeenpwned.com/API/V3):

- Pwned Passwords hashes the complete password locally and sends only the first
  five SHA-1 characters to `api.pwnedpasswords.com`, with response padding
  requested. The raw password and full hash are never stored or returned.
- Breached-account lookup sends the monitored email address to
  `haveibeenpwned.com/api/v3` and requires a narrowly scoped HIBP API key. This
  disclosure is unavoidable and must be explicitly accepted per monitored
  identity.

Inspect these contracts or run an explicit lookup with:

```bash
oh-my-safety exposure contracts
oh-my-safety exposure password --allow-network
oh-my-safety exposure account --allow-network --email-env OMS_MONITORED_EMAIL
```

Air-gapped installations can instead import reviewed signed offline
intelligence bundles from local media. They never silently fall back online.

## Optional organization controller

Enrollment discloses the configured device display name, platform, OS version,
and agent version to the organization-owned controller URL. Subsequent sync
sends a device ID, heartbeat, and only detector ID, category, severity,
lifecycle state, timestamps, and occurrence count for each finding.
The device display name defaults to the local hostname unless enrollment
supplies `--device-name`; use an inventory ID or pseudonymous label if that
hostname is sensitive.

The report contract cannot contain titles, summaries, paths, usernames,
hostnames, labels, evidence, remediation text, secret fingerprints, command
lines, or arbitrary payloads. Enrollment is explicit, controller credentials
remain in a mode-`600` local state file, endpoints initiate every request, and
local protection continues while disconnected. See
[Organization controller](organization.md).

## Verify it yourself

The no-direct-network-client guarantee for Bash security checks is falsifiable
— this returns nothing:

```bash
grep -rE 'curl|wget|/dev/tcp|nc ' lib/checks/security/
```

CI enforces the same grep on every commit, so a Bash security check cannot
quietly add its own client. Network-capable adapters are centralized, versioned,
and explicitly gated. You can also run a full scan with `--offline`: local
security checks behave identically, while privacy and exposure checks are
visibly skipped.

Notably, the **opt-in** external deep scanners are configured to stay offline:
`trufflehog` is always invoked with `--no-verification` (its default behavior
would send discovered credentials to their issuing services to test them), and
oh-my-safety never downloads YARA rules for you.

## Where your data lives (all local)

- **Config:** `~/.config/oh-my-safety/` (and `overrides.conf` for CLI toggles)
- **State, baselines, TSV history, SQLite journal:** `~/.local/state/oh-my-safety/` (directory mode `700`; sensitive files mode `600`)
- **Agent logs:** Homebrew's `var/log/oh-my-safety.log`, or `~/Library/Logs/oh-my-safety/` for a manual agent
- **Snap config/state:** `~/snap/oh-my-safety/common/` when using the
  experimental Snap instead of a native installation

Raw files, baseline snapshots, scanner evidence, and the SQLite journal are
never uploaded. An enabled external notification may transmit its documented
message fields, and an explicitly enrolled organization sync transmits only its
separately versioned redacted report contract. Uninstalling leaves local state
in place so you can review it; delete it manually if you want a clean wipe.

## A note on Full Disk Access

Some checks read protected data (the TCC database, `~/Documents`) and therefore
need Full Disk Access. Granting it increases what a compromised copy of the tool
could read — which is why the state directory is locked to your user and the
no-network invariant is enforced in code and CI. See
[monitoring.md](monitoring.md#full-disk-access) for the trade-offs.
