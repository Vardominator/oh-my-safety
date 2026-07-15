# Architecture

oh-my-safety is pure bash (3.2-compatible), zero-dependency, and organized so
that adding capability means adding a file — not editing the core.

```
bin/oh-my-safety            Entry point: resolve root, source libs, dispatch subcommand
lib/core.sh                 Version, logging, notifications, print helpers; sources the libs below
lib/platform/detect.sh      detect_platform (canonical)
lib/platform/macos.sh       Platform accessors + macOS security helpers (oms_*)
lib/yaml.sh                 Config: flatten-once parser + override layer
lib/state.sh                Baselines, notification de-dupe, log rotation (all local)
lib/allowlist.sh            Per-check finding allowlists
lib/runner.sh               Discovery, manifest reading, scan orchestration, result model
lib/cmd/*.sh                One file per subcommand
lib/checks/<category>/*.sh  The checks (privacy, security, and user "custom")
lib/data/*.tsv              Reference data (wallet inventories)
```

## Request flow

```
oh-my-safety scan
  └─ bin: resolve OMS_ROOT, source core.sh (+ yaml/state/allowlist), runner.sh, cmd/*
  └─ load_config: default.yaml + user config.yaml + overrides.conf (flattened once)
  └─ cmd_scan → run_scan
       └─ checks_discover: glob lib/checks/*/*.sh + ~/.config/oh-my-safety/checks/*.sh
       └─ for each check (ordered privacy → security → custom):
            run_one_check: read manifest (sed, no sourcing) →
              gate by platform / category / config / offline / contract →
              source file, call check_<name>(), capture exit + summary + severity →
              record a result row → notify_finding (deduped) on warn/critical
       └─ write last-scan.tsv (atomic) + append scan.log (rotated) → exit 0/1/2/3
```

## Key design choices

- **Manifest as single source of truth.** Each check declares `CHECK_*` header
  variables. The runner reads them by `sed` (not by sourcing, which would clobber
  globals), and the docs generator reads the same fields via `checks --json`. Code
  and docs can't drift.
- **Config precedence: override → user → default.** The parser flattens YAML once
  into `dotted.path=value` lines held in memory; lookups are in-memory greps. The
  override layer (`overrides.conf`) is how `enable`/`disable`/`set` persist changes
  without rewriting nested YAML.
- **Result model.** A check returns `0` (ok) / `1` (finding) / `77` (skip). The
  runner maps that plus severity to a status (`ok|warn|critical|skip|error`),
  computes an exit code (0/1/2/3), and writes a machine-readable `last-scan.tsv`.
  `status` renders it (human/json/tsv/swiftbar) with **no** re-scanning.
- **Notifications are centralized and deduped.** Checks never notify directly; the
  runner calls `notify_finding`, which alerts once per finding and re-alerts
  criticals only on an interval — no per-scan spam from the background agent.
- **State is local and safe.** Everything persistent lives under
  `~/.local/state/oh-my-safety` (mode 700), written atomically (temp + `mv`).
  See [baselines-and-state.md](baselines-and-state.md).
- **Platform split.** Checks call platform accessors (`get_*`, `oms_*`) rather
  than OS commands directly, so privacy checks stay cross-platform while security
  checks target macOS via `CHECK_PLATFORMS="macos"`.

## Extending it

The whole point of the above is that a new check is a drop-in file — see
[extending.md](extending.md). The same `status --json` contract that the SwiftBar
plugin consumes is also the API a future native menu-bar app would use.
