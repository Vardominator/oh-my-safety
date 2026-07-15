# Continuous monitoring

A one-off `oh-my-safety scan` is useful, but the real value is running it
continuously so you're alerted the moment something changes.

## Start it (Homebrew)

```bash
brew services start oh-my-safety
```

This generates and loads a launchd agent (`homebrew.mxcl.oh-my-safety`) that:
- runs at login and stays resident,
- runs `oh-my-safety monitor --quiet`, which does a quick VPN route-flip check
  every `monitoring.fast_interval` seconds and a full scan every
  `monitoring.interval` seconds,
- sends a native notification when a **new** finding at or above
  `notifications.min_severity` appears (deduped — you won't be re-nagged every scan),
- logs to `$(brew --prefix)/var/log/oh-my-safety.log`.

Stop or restart with `brew services stop|restart oh-my-safety`.

## Start it (non-Homebrew)

```bash
oh-my-safety install-agent      # writes ~/Library/LaunchAgents/com.vardominator.oh-my-safety.plist and loads it
oh-my-safety uninstall-agent    # remove it
```

The agent uses `KeepAlive`, `ProcessType Background` (battery-friendly QoS), and
logs to `~/Library/Logs/oh-my-safety/agent.log`. `oh-my-safety status` reports
whether an agent is running and which manager owns it; the tool refuses to
install a manual agent if the Homebrew one is already loaded (and vice versa) so
you never get double notifications.

## Checking status

```bash
oh-my-safety status              # human-readable last-scan summary
oh-my-safety status --format json
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
