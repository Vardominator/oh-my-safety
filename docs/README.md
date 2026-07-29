# oh-my-safety documentation

oh-my-safety is a local-first macOS and Linux safety agent. It runs **privacy**
and **security** checks locally, retains a durable finding history, and can use
explicitly enabled internet-exposure or notification adapters. Core security
checks have a CI-enforced no-direct-network-client boundary and the product has
no telemetry.

The current release is v0.3.0. It includes the Linux packaging, portable core,
profiles, history, notification channels, and optional self-hosted controller
documented here. Use Homebrew `--HEAD` or a source checkout only when
intentionally evaluating newer development code. The [roadmap](roadmap.md)
separates the released surface from future research.

## Start here

1. **[Getting started](getting-started.md)** — install, first run, and turning on background monitoring.
2. **[Linux installation](linux.md)** — apt/deb/rpm/tar choices and the systemd user service.
3. **[Configuration](configuration.md)** — enable/disable checks, tune behavior, and the config file.
4. **[Operating profiles](profiles.md)** — personal, developer, managed, server, and air-gapped modes.
5. **[Continuous monitoring](monitoring.md)** — launchd, systemd, scheduling, and permissions.

## Understand it

- **[Threat model](threat-model.md)** — exactly what oh-my-safety protects you from, and what it *cannot* do (read this).
- **[Privacy promise](privacy.md)** — every network endpoint the tool ever contacts, and how to disable each.
- **[Architecture](architecture.md)** — how the framework fits together (dispatch → runner → checks → state).
- **[Baselines & state](baselines-and-state.md)** — how "new since I last approved it" detection works, and where state lives.
- **[Local history](history.md)** — scan events, finding lifecycle, and notification delivery records.

## Use it

- **[Checks catalog](checks/README.md)** — every check, with a dedicated page explaining how it keeps you safe.
- **[Menu bar](menu-bar.md)** — the optional SwiftBar status icon.
- **[Notifications](notifications.md)** — desktop, SendGrid, Telegram, WhatsApp, Discord, and generic webhooks.
- **[Organization controller](organization.md)** — self-hosted enrollment, signed policy, redacted fleet findings, and administration.
- **[Signed offline intelligence](offline-intelligence.md)** — key generation, bundle signing, verification, and air-gapped import.
- **[Troubleshooting](troubleshooting.md)** — permission prompts, missing notifications, common issues.
- **[Signed APT repository](apt-repository.md)** — fingerprint-verified install and protected publisher setup.
- **[Experimental Snap package](../packaging/snap/README.md)** — local sideloading, service lifecycle, and Store constraints.

## Extend & contribute

- **[Extending oh-my-safety](extending.md)** — write your own check as a drop-in file (the framework is built to grow).
- **[Roadmap](roadmap.md)** — what's shipped, what's next, and the deprecation policy.
- **[Security policy](security-policy.md)** — how to report a vulnerability in the tool itself.
- **[Release maintenance](releasing.md)** — CI, tag, GitHub App, and Homebrew release process.

## Command reference

| Command | Purpose |
|---------|---------|
| `oh-my-safety scan [--check N] [--category C] [--offline] [--deep]` | Run checks once |
| `oh-my-safety status [--format human\|json\|tsv\|swiftbar]` | Show the last scan's findings |
| `oh-my-safety history [--json\|--format tsv] [--limit N]` | Show durable local events |
| `oh-my-safety monitor [--quiet]` | Continuous loop (used by the agent) |
| `oh-my-safety checks` | List every check and whether it's on/off |
| `oh-my-safety profile [show\|list\|set NAME]` | Inspect or select an operating profile |
| `oh-my-safety notifications [show\|test]` | Inspect or test delivery channels |
| `oh-my-safety organization {status\|enroll\|sync\|policy\|rotate-credential\|disable}` | Manage explicit self-hosted controller enrollment |
| `oh-my-safety secret-scan [PATH ...]` | Run the bounded built-in redacted credential scanner |
| `oh-my-safety triage-executable PATH [PATH ...]` | Hash and explain executable risk signals |
| `oh-my-safety exposure {contracts\|password\|account}` | Inspect or run an explicit exposure adapter |
| `oh-my-safety doctor` | Diagnose setup, permissions, notifications |
| `oh-my-safety enable\|disable <check\|category>` | Toggle checks |
| `oh-my-safety set <path> <value>` | Set any config value |
| `oh-my-safety recheck <check>` | Re-run one check to confirm a fix |
| `oh-my-safety ignore <check> <finding-id>` | Permanently accept a specific finding |
| `oh-my-safety accept <check>` | Accept current state as the new baseline |
| `oh-my-safety baseline {list\|show\|approve\|reset} <check>` | Manage baselines |
| `oh-my-safety install-agent \| uninstall-agent` | launchd/systemd agent for manual installs |
| `oh-my-safety menubar install` | Install the SwiftBar plugin |
