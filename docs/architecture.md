# Architecture

This page describes the v0.3.0 implementation. The v0.2.3 compatibility line
provides the first Bash layer; v0.3.0 preserves its Homebrew, launchd, and
SwiftBar contracts while adding the portable and fleet layers.

oh-my-safety has two cooperating endpoint layers and one optional self-hosted
fleet layer:

1. a Bash 3.2-compatible runtime preserves the CLI, checks, Homebrew service,
   SwiftBar, config, baselines, and upgrade contracts;
2. a pure-Go portable core provides the append-only journal, bounded built-in
   scanners, exposure adapters, notification transports, signed content, and
   organization client contracts;
3. an optional pure-Go organization controller receives redacted reports and
   serves signed, declarative policies. It is not required for standalone use.

The transition is deliberately additive. A missing Go binary reduces portable
features and records a coverage gap; it does not make the established Bash
scanner or its state unreadable.

## Repository map

```text
bin/oh-my-safety                 compatibility CLI and subcommand dispatch
lib/core.sh                      version, logging, output helpers
lib/platform/                    macOS and Linux accessors
lib/yaml.sh                      dependency-free config and atomic overrides
lib/state.sh                     baselines, schedules, alert lifecycle, locks
lib/events.sh                    local append-only compatibility event log
lib/runner.sh                    discovery, execution, result persistence, bridge
lib/notifications.sh             desktop and opt-in external delivery
lib/cmd/                         one file per compatibility CLI command
lib/checks/<category>/           versioned endpoint checks

cmd/oh-my-safety-agent/          portable endpoint-core CLI
cmd/oh-my-safety-intel/          signed offline-intelligence CLI
internal/journal/                SQLite events and finding projections
internal/bridge/                 bounded TSV ingestion and journal queries
internal/scanner/                local secret and executable scanners
internal/exposure/               explicit internet-exposure adapters
internal/notifier/               bounded notification transports
internal/profile/                composable workload/protection policy
internal/intel/                  signed offline intelligence bundles

cmd/oh-my-safety-controller/     self-hosted fleet-controller service
internal/controller/             enrollment, policy, reporting, RBAC, audit

packaging/                       systemd and nFPM package definitions
scripts/build-linux-packages.sh  deb, rpm, and portable endpoint archives
```

## Continuous endpoint loop

```text
launchd / systemd --user
        |
        v
  Bash monitor supervisor
        |
        +-- fast route transition probe
        |
        `-- non-overlapping scheduled scan worker
              |
              +-- discover due checks and enforce profile/network gates
              +-- collect bounded local observations
              +-- reconcile per-item finding lifecycle
              +-- atomically persist current posture and compatibility events
              +-- ingest the versioned snapshot into the SQLite journal
              `-- deliver deduplicated local/opt-in external notifications
```

The supervisor reloads configuration only between ticks. Per-check intervals
let inexpensive checks run frequently while deep scanners run less often.
Manual and scheduled scans share a stale-recoverable global lock, so they
cannot race each other. A partial recheck merges only the checks it evaluated
and never erases unrelated posture.

## Check execution contract

Each check declares `CHECK_*` manifest fields. Discovery reads those fields
without sourcing the file, then applies category, check, platform, profile,
offline, contract-version, and schedule gates. Only then is the check sourced
and its `check_<name>` function called.

A check returns:

- `0`: healthy;
- `1`: finding;
- `77`: explicit skip or missing coverage;
- any other value: collector error.

The runner writes versioned `result`, `detail`, and metadata rows to
`last-scan.tsv`. Non-OK details and remediation stay local. Contract-v2 checks
can emit stable per-item IDs so one item can resolve while another remains
open.

## State and journal

Endpoint state defaults to:

```text
${XDG_STATE_HOME:-~/.local/state}/oh-my-safety/
```

The directory is mode `700`; sensitive files are mode `600`. Compatibility
state uses atomic temp-file replacement. The SQLite journal additionally uses
database triggers to make event rows append-only and rebuilds the current
finding projection by replay. Scan ingestion is deterministic, idempotent, and
bounded; human detail rows are deliberately excluded.

The journal complements rather than silently replaces the compatibility
contracts. `oh-my-safety status` continues to read the current TSV snapshot,
while `oh-my-safety history` and the agent journal expose versioned timelines.

## Trust and network boundaries

Core checks, scanning, correlation, evidence, scheduling, policy evaluation,
and journal storage are local. There is no product telemetry or required hosted
service.

Every network path is a named adapter with an explicit gate:

- privacy probes disclose the documented IP/DNS request;
- external notifications are globally off until enabled and read credentials
  from named environment variables;
- HIBP exposure checks are opt-in and publish what they disclose before use;
- managed endpoints initiate controller connections; the controller never
  opens a connection back to an endpoint.

Offline and air-gapped profiles block all adapters. Signed intelligence is
installed from a local file, contains declarative records only, enforces size
and record limits, pins Ed25519 keys, rejects rollback/expiry, and never
executes content.

## Organization control plane

The controller stores its own SQLite data and exposes bounded JSON APIs for:

- one-use, expiring enrollment;
- device heartbeat and credential rotation;
- signed command-free policies assigned through device groups;
- redacted finding synchronization;
- viewer, operator, and administrator roles;
- append-only administrative audit history.

Non-loopback listeners require TLS. Administrator and signing-key files must be
regular mode-`600` files. Device and administrator bearer values are stored as
hashes. Endpoint reports exclude titles, summaries, evidence, labels, paths,
usernames, and hostnames.

The controller is intentionally not remote shell, MDM, or EDR. Declarative
policy selects known local checks, cadence, profile, reporting, and constrained
remediation mode; it cannot carry commands, scripts, paths, arguments, or
arbitrary payloads.

## Distribution compatibility

- Stable macOS releases remain installable with the repository Homebrew tap.
- `brew services` continues to supervise the same `oh-my-safety monitor`
  contract.
- SwiftBar remains a read-only renderer of `status --format swiftbar`.
- Debian/Ubuntu and Fedora/RHEL-compatible packages install the same CLI, the
  pure-Go agent core, and a systemd user service.
- Release CI validates Bash on Ubuntu and macOS, Go tests/race/vet/pure builds,
  generated docs, Homebrew stable and HEAD, SwiftBar, deb/rpm installs, and
  release checksums.

See [Extending](extending.md) for the check contract and
[Baselines and state](baselines-and-state.md) for persistent file details.
