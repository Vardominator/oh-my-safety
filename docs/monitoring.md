# Continuous monitoring

A one-off `oh-my-safety scan` is useful, but the real value is running it
continuously so you're alerted the moment something changes.

v0.3.0 preserves the Homebrew launchd and SwiftBar service contracts from
v0.2.3 and adds the Linux service, per-check scheduler, external notification
lifecycle, and managed-sync behavior described on this page.

## Start it (Homebrew)

```bash
brew services start oh-my-safety
```

This generates and loads a launchd agent (`homebrew.mxcl.oh-my-safety`) that:
- runs at login and stays resident,
- runs `oh-my-safety monitor --quiet`, which does a quick VPN route-flip check
  every `monitoring.fast_interval` seconds and schedules each check using its
  own `CHECK_INTERVAL` (falling back to `monitoring.interval`),
- sends a native notification when a **new** finding at or above
  `notifications.min_severity` appears (deduped — you won't be re-nagged every scan),
- logs to `$(brew --prefix)/var/log/oh-my-safety.log`.

Stop or restart with `brew services stop|restart oh-my-safety`.

## Start it (manual macOS install)

```bash
oh-my-safety install-agent      # writes ~/Library/LaunchAgents/com.vardominator.oh-my-safety.plist and loads it
oh-my-safety uninstall-agent    # remove it
```

The agent uses `KeepAlive`, `ProcessType Background` (battery-friendly QoS), and
logs to `~/Library/Logs/oh-my-safety/agent.log`. `oh-my-safety status` reports
whether an agent is running and which manager owns it; the tool refuses to
install a manual agent if the Homebrew one is already loaded (and vice versa) so
you never get double notifications.

## Start it (Linux)

Release packages install a systemd user unit:

```bash
systemctl --user daemon-reload
systemctl --user enable --now oh-my-safety.service
systemctl --user status oh-my-safety.service
journalctl --user -u oh-my-safety.service -f
```

Manual installs can create the same user service with
`oh-my-safety install-agent`. See [linux.md](linux.md) for lingering after
logout and the reason the current service deliberately does not run as root.

## Checking status

```bash
oh-my-safety status              # human-readable last-scan summary
oh-my-safety status --format json
oh-my-safety history --limit 25
```
`status` reads the last scan from local state and makes no network calls, so
it's instant and safe to poll (the [menu bar plugin](menu-bar.md) uses it).

## Full Disk Access

A few checks read data macOS protects behind Full Disk Access (FDA): **tcc-audit**
(the TCC database) and the protected-folder parts of **secrets-exposure**. Without
FDA they **degrade gracefully** — tcc-audit self-skips with a clear message rather
than failing.

How FDA attaches to a bash script:
- **Interactive scans** are attributed to your terminal app. If your terminal has
  FDA, `oh-my-safety scan --deep` gets full coverage with no extra grants. This is
  the recommended path.
- **The background agent** runs as `/bin/bash`. To give it FDA you must grant FDA
  to `/bin/bash` itself — which extends to *all* bash scripts on your Mac. That's a
  real trade-off; the agent works fine without it (the FDA-gated checks just skip).

`oh-my-safety doctor` detects your FDA status in both contexts and prints the exact
steps (including the `open "x-apple.systempreferences:…Privacy_AllFiles"` deep link)
if you want to grant it.

## Notifications

Notifications use `osascript` (attributed to "Script Editor" in
System Settings › Notifications) or `terminal-notifier` if you have it installed
(a cleaner, dedicated identity). If you don't see the test notification from
`oh-my-safety doctor`, allow notifications for that identity, or install
`terminal-notifier`. Findings are always also written to `status` and the scan
log, so a missed notification never means a missed finding.

Linux uses `notify-send`, `zenity`, or `kdialog` when available and falls back
to the service log. Discord, Telegram, SendGrid, WhatsApp, and generic webhook
delivery are opt-in and documented in [notifications.md](notifications.md).

## Scheduling, overlap, and reload behavior

Manual scans and the monitoring worker share one process-wide scan lock. If a
scan is already active, another manual request reports busy and a scheduler tick
waits for the next opportunity; checks never overlap and corrupt baselines.
Stale locks are reclaimed only after their recorded process no longer exists.

The fast route probe stays responsive while due checks run in a background
worker. Configuration reloads only between ticks. Invalid cadence values retain
the last known-good configuration rather than partially changing a live
monitor.

An enrolled endpoint also performs a managed sync after the scan worker exits.
The sync is locally throttled using the last verified reporting interval (or
the bootstrap interval while reporting is disabled). It reports only the
closed device metadata and redacted finding projection described in
[organization.md](organization.md); it never sends finding summaries or
evidence. Disabled reporting still allows heartbeat and signed-policy polling.
If the controller is unavailable, monitoring continues with the cached,
signature-verified policy and records a local operational event; offline mode
disables managed network access entirely.

Filtered rechecks write `last-partial-scan.tsv` and merge only the rechecked
rows into current posture. They do not falsely refresh the timestamp of a full
device scan. Scheduled composites do advance freshness because every retained
row remains inside its declared cadence.

Offline and air-gapped profiles disable the route probe, force scan offline
gating, and block every external notification adapter.
