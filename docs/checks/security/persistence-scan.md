# persistence-scan

Watches every place macOS can auto-start a program and flags any new one that appears after your first run.

**Category:** security · **Default severity:** critical · **Platforms:** macos · **Runs every:** 600s (in the background agent)

## What it protects you from

The single most important thing malware wants after it lands on your Mac is *persistence*: a way to relaunch itself automatically every time you log in or reboot, so a restart doesn't clean it out. macOS gives it several doors to do that: a LaunchAgent or LaunchDaemon plist, a Login Item, a `cron` job, a periodic script, an ancient StartupItem, or a configuration profile.

Real infostealers abuse exactly these. After stealing your Keychain, browser passwords, and crypto wallets, families like Atomic Stealer (AMOS) and the many "cracked app" trojans commonly drop a LaunchAgent pointing at a script in your home folder or `/tmp` so they survive a reboot and keep exfiltrating. A rogue configuration profile can silently reroute your traffic or force-install software.

This check doesn't try to recognize specific malware. Instead it learns what auto-start entries are *normal for your machine*, then tells you the moment a new one shows up — which is precisely when you'd want to know something planted itself.

## How it works

It makes **no network calls**. Everything it reads is local system state. On each run it collects one line per persistence entry from:

- **LaunchAgents / LaunchDaemons** — every `*.plist` in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and `/Library/LaunchDaemons`. For each it reads the `Label` (via `plutil`) and the target program (the plist's `Program`, else the first item of `ProgramArguments`).
- **Login Items** — asks System Events via `osascript` for the name of every login item (see Permissions).
- **cron** — `crontab -l` for your user, ignoring comments and blank lines.
- **periodic scripts** — anything under `/etc/periodic/{daily,weekly,monthly}` (often absent on modern macOS).
- **legacy vectors** — anything in `/Library/StartupItems/` or `/etc/emond.d/rules/*.plist`; these are obsolete, so their mere presence is treated as anomalous.
- **configuration profiles** — the `profileIdentifier` of each profile listed by `profiles list`.

The collected list is sorted, de-duplicated, and compared against the saved baseline. For any LaunchAgent/Daemon that points at a real program, it also runs a **code-signature check** (`oms_codesign_verdict`, cached by path + inode + mtime) to see whether the program is Apple-signed, Developer-ID-signed, ad-hoc signed, or unsigned.

## What it flags (and how serious)

- **pass** — the current set of persistence entries exactly matches the baseline: "No new persistence mechanisms since baseline."
- **info** — an entry that was in the baseline is now gone ("no longer present: ..."). Purely informational; it never fails the check.
- **warn** — one or more *new* entries appeared since the baseline. Each is listed with a human-readable description and its finding id, e.g. `NEW persistence: cron job: ...` or `NEW persistence: Login item: ...`.
- **critical** — a new LaunchAgent/Daemon whose target program is **unsigned or ad-hoc signed AND lives in a user-writable location** (your home folder, `/tmp`, `/private/var/tmp`, `/private/var/folders`, etc.). This is the classic malware signature — an untrusted binary in a place any process can write, wired to auto-start. The overall result becomes critical and the summary reads "N new persistence item(s) — at least one is unsigned and user-writable."

A new signed or Apple binary, or anything in a system-protected path, is reported as a warning rather than critical.

## What's baselined

Yes — this is a baseline-drift check. **The first run is silent about content:** it records the complete current set of persistence entries as your baseline and reports `pass` ("Baseline recorded (N persistence item(s)). Future changes will be flagged."). Nothing is treated as suspicious on that first pass, because it has nothing to compare against.

From then on, only *differences* from the baseline are surfaced: newly added entries are evaluated and flagged; removed entries are noted as info. When new items are found, the current snapshot is staged as "pending" so you can promote it to the new baseline once you've reviewed it.

## Permissions

No Full Disk Access required. The only permission it touches is **Automation access to System Events**, used solely to read Login Items. If your terminal (or the background agent) hasn't been granted it, the `osascript` call fails and the check **self-degrades gracefully**: it drops Login Items from that run and prints an `info` line telling you to grant Automation > System Events, or to turn Login Item scanning off in config. Every other persistence source still gets scanned. Importantly, the Login Item lookup happens *outside* the snapshot capture, so a permission-denial notice can never accidentally get folded into your baseline.

## Configuration

Reads these config keys (in `~/.config/oh-my-privacy/config.yaml`):

- `checks.security.persistence_scan.enabled` — whether the check runs at all (default: enabled).
- `checks.security.persistence_scan.login_items` — whether to scan Login Items (default: `true`). Set to `false` to skip the System Events / Automation call entirely.

Enable or disable the whole check:

    oh-my-safety disable persistence-scan
    oh-my-safety enable  persistence-scan

## Handling findings

When a new persistence item appears, decide whether it's something you (or software you trust) installed:

- **It's legitimate** — for example you just installed an app that adds a LaunchAgent. Either accept the whole current state as the new normal:

      oh-my-safety accept persistence-scan

  (this promotes the staged pending snapshot to the baseline), or permanently accept just that one item:

      oh-my-safety ignore persistence-scan '<finding-id>'

  Finding ids are stable and path-based — each collected entry *is* its own id. The schemes are:

      launchd|<plist-path>|<program-path>
      login|<login-item-name>
      cron|<crontab-line>
      periodic|<script-path>
      legacy|<path>
      profile|<profile-identifier>

  Allowlist entries may be exact ids or shell globs, so you can accept a family of entries with a pattern (e.g. `launchd|/Library/LaunchDaemons/com.trustedvendor.*`).

- **It's suspicious or unknown** — do not accept it. Remove the offending item (delete the plist / login item / cron line, or remove the configuration profile), then confirm it's gone:

      oh-my-safety recheck persistence-scan

## Limitations

- **First-run blindness.** Anything already persisting when you first run oh-my-safety is baked into the baseline and will never be flagged. Run the initial baseline on a machine you believe is clean.
- **It detects change, not badness.** A new entry from software you trust looks the same as malware until you inspect it; a warn/critical is a prompt to review, not proof of compromise. Conversely, malware that reuses an *existing* baselined entry (e.g. hijacks a legitimate LaunchAgent's target in place, or replaces the program without changing the plist path) won't register as a new id — the id is based on the plist and program *paths*, not on file contents beyond the code-signature verdict of the launchd target.
- **Signature check is limited to launchd targets.** The unsigned/user-writable escalation to critical only applies to LaunchAgents/Daemons. A malicious cron job, login item, or profile is reported as a warning regardless of what it runs.
- **Coverage gaps.** It reads per-user `crontab` only (not system crontabs), and profile enumeration via `profiles list` is best-effort. Root-level LaunchDaemons whose plists it can read are covered, but a full inventory of system daemons is not guaranteed.
- **Userspace tool.** oh-my-safety runs as your user with ordinary privileges. Root-level or kernel-level malware can hide entries from these commands, tamper with the baseline files, or disable the agent outright. Treat a clean result as reassuring, not as a guarantee.
