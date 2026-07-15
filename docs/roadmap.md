# Roadmap

oh-my-safety is built to grow: new detections are drop-in check files following a
[versioned contract](extending.md), so the catalog can expand across releases
without breaking existing installs. This page tracks where it's headed.

## Shipped (v0.2 — the oh-my-safety framework)
- Renamed from oh-my-privacy; subcommand CLI; path-aware config with
  enable/disable/set; local state, baselines, and allowlists.
- Privacy checks: ip-address, dns-leak, ipv6-leak, vpn-tunnel, routing.
- Security checks: hardening-posture, process-audit, persistence-scan,
  network-exposure, wallet-guard, secrets-exposure, tcc-audit.
- Opt-in: secrets-content (gitleaks/trufflehog), yara-scan.
- launchd agent via `brew services`; SwiftBar plugin; doctor; generated docs.

## Next (v0.3)
- Wallet "modified while the wallet app is closed" tripwire (content-hash based,
  desktop wallets only) — currently deferred as too noisy to enable by default.
- BackgroundTaskManagement (BTM) diffing in persistence-scan for SMAppService
  registrations that never touch the LaunchAgents directories.
- Per-item baseline approval UI (accept one drifted item instead of the whole set).
- A `bats` test suite in `test/` wired into CI.

## Later (v1.0 and beyond)
- A native Swift menu-bar app (distributed as a cask) consuming the existing
  `status --json` contract — only once the project has traction to justify the
  signing/notarization overhead.
- More wallet artifacts and browser-extension IDs.
- Optional, clearly-marked integrations that stay within the no-network promise.

## Deprecation & compatibility policy
- The `oh-my-privacy` binary/alias and legacy flags (`--once`, `--list-checks`)
  are supported as deprecated shims and may be removed in a future major release.
- Checks declare `CHECK_CONTRACT`; the runner skips (with a warning) any check
  targeting a newer contract than it understands, so upgrading the catalog never
  silently misbehaves. This build supports contract **2**.

## Contribute
Have a detection idea? The fastest path is a [custom check](extending.md) — and
good ones are welcome upstream. See [CONTRIBUTING.md](../CONTRIBUTING.md).
