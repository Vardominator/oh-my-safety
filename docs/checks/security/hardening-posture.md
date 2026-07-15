# hardening-posture

Audits the core macOS security settings — SIP, Gatekeeper, FileVault, the firewall, remote-access sharing services, automatic updates, and XProtect freshness — and flags anything that leaves your Mac more exposed than Apple's safe defaults.

**Category:** security · **Default severity:** warn (SIP and Gatekeeper findings escalate to critical) · **Platforms:** macOS · **Runs every:** 3600s (in the background agent)

## What it protects you from

Your Mac ships with several protections turned on that quietly stop most malware and casual snooping. Over time those can get switched off — sometimes by you following a "disable this to run my app" tutorial, sometimes by an installer, sometimes by malware that deliberately weakens the machine before it does damage. This check is your safety net: it notices when a protection you rely on has gone missing.

Concretely, it watches for:

- **System Integrity Protection (SIP) disabled.** SIP is the wall that stops even administrator-level processes from modifying protected system files and injecting into Apple's own apps. Turning it off is a common step in malware and "cracked app" installers because it removes a major roadblock. If SIP is off, a lot of other macOS protection can be undermined — hence this is treated as critical.
- **Gatekeeper disabled.** Gatekeeper checks that apps you open are signed and notarized by Apple before letting them run. With it off, any downloaded binary runs with no vetting at all, which is exactly what droppers for infostealers (the family that steals browser passwords, crypto wallets, and Keychain data) want. Also critical.
- **FileVault off.** Without full-disk encryption, anyone who has your Mac in hand (lost, stolen, or seized) can pull files straight off the drive without your password.
- **Firewall off.** The application firewall limits which apps can accept incoming network connections. Off, any listening service on your machine is reachable.
- **Remote Login (SSH), Screen Sharing, or File Sharing (SMB) running.** These open your Mac up to remote access over the network. Handy when you set them up on purpose; a serious exposure when they were left on (or turned on quietly) and you forgot.
- **Automatic security updates disabled.** These are the fast, silent patches (including Rapid Security Responses and XProtect malware definitions) that close holes between full macOS updates. Off means you stay vulnerable longer.
- **Stale XProtect definitions.** XProtect is Apple's built-in malware blocklist. If its definitions haven't updated in a long time, your Mac is checking downloads against an out-of-date list of known threats.

## How it works

The check makes **no network calls**. Everything it reads comes from local system commands and files:

- **SIP:** `csrutil status` — flags if the output does not contain "enabled".
- **Gatekeeper:** `spctl --status` — flags if the output does not contain "assessments enabled".
- **FileVault:** `fdesetup status` — flags if the output does not contain "FileVault is On".
- **Firewall:** `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` — flags if the output contains "disabled" or "state = 0".
- **Remote Login (SSH):** `launchctl print system/com.openssh.sshd` — the SSH launchd service being present (i.e. not "Could not find service") is treated as SSH being on. (The code notes that `systemsetup -getremotelogin` is unreliable, so it uses the launchd service as the real signal.)
- **Screen Sharing:** `launchctl print system/com.apple.screensharing` — flags if "state = running".
- **File Sharing (SMB):** `launchctl print system/com.apple.smbd` — flags if "state = running".
- **Automatic updates:** `defaults read /Library/Preferences/com.apple.SoftwareUpdate` for the `ConfigDataInstall` and `CriticalUpdateInstall` keys — flags if either is explicitly `0`. If a key is absent, macOS defaults it to on, so that is treated as a pass.
- **XProtect:** reads `.../XProtect.bundle/Contents/Info.plist` (under `/Library/Apple/System/...` or falling back to `/System/Library/...`), reports the `CFBundleShortVersionString` as an info line, and compares the plist's modification time against the current date.

If a command produces no output (for example it isn't available on your macOS version), that individual sub-check is skipped rather than treated as a failure.

## What it flags (and how serious)

Each problem is reported as its own line, with a short description, a suggested fix, and a stable finding id in `[id: ...]`.

- **critical**
  - `hard:sip` — System Integrity Protection is disabled.
  - `hard:gatekeeper` — Gatekeeper assessments are disabled.
- **warn**
  - `hard:filevault` — FileVault disk encryption is off.
  - `hard:firewall` — Application firewall is disabled.
  - `hard:remote-login` — Remote Login (SSH) is enabled.
  - `hard:screen-sharing` — Screen Sharing is running.
  - `hard:file-sharing` — File Sharing (SMB) is running.
  - `hard:auto-security-updates` — Automatic security/system-data updates are disabled.
  - `hard:xprotect-stale` — XProtect definitions are older than the age threshold (the message includes the actual age in days and the threshold).
- **info**
  - The current XProtect version is always reported as an informational line when the plist is readable — this is not a problem, just context.

The overall check fails if there is one or more finding. Its reported severity is **critical** if any critical finding is present, otherwise **warn**. With no findings it passes with "System hardening posture looks good".

## What's baselined

**Nothing.** This is an absolute-policy check, not a drift check — it compares your Mac against a fixed notion of "safe defaults" every run, so there is no quiet first-run baseline to record and no `accept` state to manage. A setting that is unsafe today will be flagged whether or not it was unsafe yesterday.

## Permissions

**None required.** It does not need Full Disk Access or any TCC permission. All of its inputs are public system status commands and world-readable system files. Individual sub-checks self-skip if the underlying command isn't present or returns nothing on your macOS version.

## Configuration

Config keys live under `checks.security.hardening_posture`:

- `enabled` (default `true`) — turn the whole check on or off.
- `xprotect_max_age_days` (default `45`) — how old XProtect definitions may get before `hard:xprotect-stale` fires. A non-numeric value falls back to 45.
- `allow_remote_login` (default `false`) — set to `true` if you intentionally run SSH; this skips the `hard:remote-login` check entirely.
- `allow_screen_sharing` (default `false`) — set to `true` if you intentionally run Screen Sharing; skips the `hard:screen-sharing` check.
- `require_firewall` (default `true`) — set to `false` to skip the firewall check (not listed in `config/default.yaml`, but read by the check and defaulting to true).

This check uses no external tools, so it has no `tools.*` dependencies.

Enable or disable it:

    oh-my-safety disable hardening-posture
    oh-my-safety enable  hardening-posture

## Handling findings

When something is flagged, you generally have two paths:

1. **Fix it, then confirm.** Follow the "fix:" hint on the finding (e.g. turn FileVault back on in System Settings, re-enable SIP from Recovery, or run `softwareupdate --background-critical` for stale XProtect). Then re-run just this check to confirm it clears:

        oh-my-safety recheck hardening-posture

2. **Accept it, if it's intentional.** If a finding reflects a deliberate choice (a lab machine with SIP off, a Mac you SSH into on purpose), permanently stop flagging that specific item:

        oh-my-safety ignore hardening-posture 'hard:remote-login'

   The finding-id scheme here is a fixed set of `hard:<area>` strings — `hard:sip`, `hard:gatekeeper`, `hard:filevault`, `hard:firewall`, `hard:remote-login`, `hard:screen-sharing`, `hard:file-sharing`, `hard:auto-security-updates`, and `hard:xprotect-stale`. Ids are matched exactly (glob patterns are also supported), so ignoring one area does not silence the others. For SSH and Screen Sharing you can instead use the `allow_remote_login` / `allow_screen_sharing` config flags above.

Because this check has no baseline, `oh-my-safety accept hardening-posture` does not apply here — use `ignore` for the specific finding instead.

## Limitations

- **It only reports the on/off state of built-in protections.** It does not verify that they are effective — for example, it confirms Gatekeeper assessments are enabled but does not audit per-app quarantine overrides, and it confirms FileVault is on but does not evaluate your recovery-key hygiene.
- **The remote-access checks are presence/running signals, not deep audits.** They tell you SSH/Screen Sharing/SMB are active; they do not tell you who can connect, from where, or with what credentials.
- **XProtect freshness is inferred from a file's modification time**, which is a proxy for "recently updated," not a guarantee that the newest definitions are installed. A broken system clock disables this comparison (the check guards against it rather than reporting a bogus age).
- **Sub-checks silently skip when their command isn't available**, so on an unusual or heavily modified macOS build some items may simply not be evaluated.
- **This is a userspace check.** It runs with your privileges and trusts what the system commands report. Malware running as root could disable a protection and still make these commands report the safe answer, or tamper with the check itself. Treat a clean result as reassurance, not proof, on a machine you already suspect is compromised.
