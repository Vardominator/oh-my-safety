# oh-my-safety documentation

oh-my-safety is a macOS safety & privacy monitor. It runs a set of **checks**
across two categories — **privacy** (VPN/DNS/IP leaks) and **security**
(malware persistence, suspicious processes, exposed secrets and wallets, system
hardening) — locally, with a strict no-network guarantee for the security
checks and no telemetry anywhere.

## Start here

1. **[Getting started](getting-started.md)** — install, first run, and turning on background monitoring.
2. **[Configuration](configuration.md)** — enable/disable checks, tune behavior, the config file.
3. **[Continuous monitoring](monitoring.md)** — the launchd agent, `brew services`, and Full Disk Access.

## Understand it

- **[Threat model](threat-model.md)** — exactly what oh-my-safety protects you from, and what it *cannot* do (read this).
- **[Privacy promise](privacy.md)** — every network endpoint the tool ever contacts, and how to disable each.
- **[Architecture](architecture.md)** — how the framework fits together (dispatch → runner → checks → state).
- **[Baselines & state](baselines-and-state.md)** — how "new since I last approved it" detection works, and where state lives.

## Use it

- **[Checks catalog](checks/README.md)** — every check, with a dedicated page explaining how it keeps you safe.
- **[Menu bar](menu-bar.md)** — the optional SwiftBar status icon.
- **[Troubleshooting](troubleshooting.md)** — permission prompts, missing notifications, common issues.

## Extend & contribute

- **[Extending oh-my-safety](extending.md)** — write your own check as a drop-in file (the framework is built to grow).
- **[Roadmap](roadmap.md)** — what's shipped, what's next, and the deprecation policy.
- **[Security policy](security-policy.md)** — how to report a vulnerability in the tool itself.

## Command reference

| Command | Purpose |
|---------|---------|
| `oh-my-safety scan [--check N] [--category C] [--offline] [--deep]` | Run checks once |
| `oh-my-safety status [--format human\|json\|tsv\|swiftbar]` | Show the last scan's findings |
| `oh-my-safety monitor [--quiet]` | Continuous loop (used by the agent) |
| `oh-my-safety checks` | List every check and whether it's on/off |
| `oh-my-safety doctor` | Diagnose setup, permissions, notifications |
| `oh-my-safety enable\|disable <check\|category>` | Toggle checks |
| `oh-my-safety set <path> <value>` | Set any config value |
| `oh-my-safety recheck <check>` | Re-run one check to confirm a fix |
| `oh-my-safety ignore <check> <finding-id>` | Permanently accept a specific finding |
| `oh-my-safety accept <check>` | Accept current state as the new baseline |
| `oh-my-safety baseline {list\|show\|approve\|reset} <check>` | Manage baselines |
| `oh-my-safety install-agent \| uninstall-agent` | launchd agent (non-Homebrew) |
| `oh-my-safety menubar install` | Install the SwiftBar plugin |
