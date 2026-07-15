# Troubleshooting

Start with `oh-my-safety doctor` — it checks most of the below and prints
targeted guidance.

## "macOS is asking me to allow oh-my-safety / bash to control System Events"
That's the **persistence-scan** check reading your Login Items via AppleScript
(Automation permission). Allow it, or disable just that part with
`oh-my-safety set checks.security.persistence_scan.login_items false`. If denied,
the check skips login items and keeps going.

> Note: oh-my-safety never runs `sfltool dumpbtm` — that command hangs without
> root and can trigger permission prompts. If you saw an `sfltool` prompt, it
> was not from this tool.

## "tcc-audit is skipped: needs Full Disk Access"
Reading the TCC database requires Full Disk Access. Either run deep scans from an
FDA-granted terminal (`oh-my-safety scan --deep`), or grant FDA to `/bin/bash`
for the background agent (this extends to all bash scripts — a real trade-off).
See [monitoring.md](monitoring.md#full-disk-access). `doctor` prints the exact
steps and the settings deep link.

## "I'm not getting notifications"
- Run `oh-my-safety doctor` — it fires a test notification.
- Allow notifications for "Script Editor" in System Settings › Notifications, or
  `brew install terminal-notifier` for a dedicated identity.
- Findings are always in `oh-my-safety status` and the scan log regardless.

## "A legitimate app is being flagged"
That's expected for drift/heuristic checks. Accept it:
- one item: `oh-my-safety ignore <check> '<finding-id>'` (the id is in the scan output)
- the whole new state: `oh-my-safety accept <check>`

## "A check I don't want keeps running"
```bash
oh-my-safety disable <check-or-category>
oh-my-safety checks        # confirm on/off state
```

## "My config isn't taking effect"
- CLI overrides (`enable`/`disable`/`set`) win over your `config.yaml`; check
  `~/.config/oh-my-safety/overrides.conf`.
- The YAML parser needs **2-space indentation** and doesn't accept tabs or flow
  collections; `doctor` warns if your file fails to parse.

## "Scans feel slow"
The first scan runs code-signature checks on many binaries; results are cached by
path+inode+mtime, so later scans are much faster. The background agent's fast
route check is separate and cheap. Tune cadence with `monitoring.interval`.

## "Both a Homebrew and a manual agent are installed"
That causes double notifications. `oh-my-safety status` warns about it; remove
one with `oh-my-safety uninstall-agent` or `brew services stop oh-my-safety`.

## Reset everything
```bash
oh-my-safety baseline reset <check>       # re-snapshot one check next scan
rm -rf ~/.local/state/oh-my-safety        # wipe all baselines/allowlists/logs
```
