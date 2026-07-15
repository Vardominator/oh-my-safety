# Claude Code Instructions for oh-my-safety

This file provides context for Claude Code when working on this project.

## Project Overview

oh-my-safety is a macOS-first safety & privacy monitor written in pure Bash. It
runs modular **checks** in two categories — **privacy** (VPN/DNS/IP leaks,
cross-platform) and **security** (malware persistence, suspicious processes,
exposed secrets & crypto wallets, system hardening; macOS-only) — with a strict
no-network guarantee for security checks and no telemetry anywhere.

It was renamed from **oh-my-privacy**; a deprecation shim (`bin/oh-my-privacy`)
and config migration keep old installs working.

## Architecture

```
bin/oh-my-safety            # entry point: resolve root, source libs, dispatch subcommand
bin/oh-my-privacy           # deprecation shim -> exec oh-my-safety
lib/core.sh                 # version (OMS_VERSION), logging, notify/notify_finding, print helpers
lib/yaml.sh                 # path-aware config parser (flatten-once) + override layer
lib/state.sh                # baselines, notification de-dupe, log rotation (all local)
lib/allowlist.sh            # per-check finding allowlists
lib/runner.sh               # discovery, manifest reading, scan orchestration, result model
lib/cmd/*.sh                # one file per subcommand (scan, monitor, status, checks, doctor, ...)
lib/platform/{detect,macos,linux,windows}.sh   # detect_platform + accessors + oms_* helpers
lib/checks/{privacy,security}/*.sh             # the checks
lib/data/*.tsv              # wallet inventories
scripts/gen-docs.sh         # regenerate docs/checks/ catalog from manifests
docs/                       # documentation tree (see docs/README.md)
```

Read `docs/architecture.md` for the full picture and `docs/extending.md` for the
check contract (the canonical guide for adding checks).

## Key Design Principles

1. **bash 3.2 compatible.** macOS ships bash 3.2 and the launchd agent runs
   `/bin/bash`. NO `declare -A`, `mapfile`/`readarray`, `${x^^}`/`${x,,}`, `|&`.
   CI enforces this and `bin/oh-my-safety` uses `set -uo pipefail` (NOT `-e`).
2. **Zero dependencies.** Pure bash + tools that ship with macOS. External tools
   (gitleaks/trufflehog/YARA) are opt-in via `optional_tool` and never installed.
3. **No phone-home from security checks.** Enforced by a CI grep gate over
   `lib/checks/security/`. Only privacy checks make network calls.
4. **Manifest is the single source of truth.** Each check declares `CHECK_*`
   header vars, read by both the runner (via `sed`, not sourcing) and the docs
   generator. Adding a check never requires editing the runner/CLI/docs by hand.
5. **Everything is enabled by default; toggle via `enable`/`disable`/`set`** which
   write to `~/.config/oh-my-safety/overrides.conf` (highest precedence).

## Adding a check

See `docs/extending.md`. In short: create `lib/checks/<category>/<name>.sh` with
the manifest header + `check_<name_with_underscores>()` returning 0/1/77, set
`CHECK_FINDING_SUMMARY`/`CHECK_RESULT_SEVERITY`, print via `print_check_result`,
filter with `allowlist_match`, and use the baseline API for drift. Then
`make docs`. Users can drop checks into `~/.config/oh-my-safety/checks/`.

## Testing

```bash
./bin/oh-my-safety scan            # full scan
./bin/oh-my-safety scan --offline  # skip network checks (deterministic; used by CI)
./bin/oh-my-safety scan --check dns-leak
make lint                          # shellcheck
make docs                          # regenerate the checks catalog
./scripts/gen-docs.sh --check      # verify the catalog is current (CI gate)
```

## Common Tasks

- **Version bump**: update `OMS_VERSION` in `lib/core.sh` only — it's the single
  source of truth (Makefile, formula check, and CI read from it).
- **Notification from a check**: don't — the runner notifies based on your return
  value + severity (deduped). Just `print_check_result` and return.
- **Debug**: run with `-v` / `--verbose`; use `oh-my-safety doctor`.
