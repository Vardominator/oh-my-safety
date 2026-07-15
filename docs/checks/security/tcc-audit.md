# tcc-audit

Learns which apps hold macOS's most powerful privacy permissions (Full Disk Access, Screen Recording, Accessibility, Input Monitoring, and Automation) and tells you the moment a new one is granted.

**Category:** security · **Default severity:** warn · **Platforms:** macos · **Runs every:** 600s (in the background agent)

## What it protects you from

macOS keeps a database called TCC (Transparency, Consent, and Control) that records which apps you've allowed to do sensitive things. A handful of those permissions are far more dangerous than the rest, because holding one lets a program spy on you or take over your machine:

- **Full Disk Access** — read every file, including your Mail, Messages, browser data, and other apps' private storage. This is exactly what infostealers like Atomic Stealer (AMOS) want, because it hands them your whole digital life in one grant.
- **Screen Recording** — silently capture everything on your screen, including passwords, one-time codes, and private messages.
- **Accessibility** and **Input Monitoring / PostEvent** — read your keystrokes (keylogging) and even inject synthetic clicks and typing to control your Mac as if they were you. This is how malware clicks through security prompts on your behalf.
- **Automation (Apple Events)** — drive other apps (Mail, Finder, browsers) programmatically to read or exfiltrate data.

The scary part is that these grants are *sticky*: once you approve one, it stays approved silently across reboots. Malware, a sketchy "cracked" app, or a mis-clicked permission prompt can quietly acquire one of these and keep it. This check doesn't try to recognize specific malware. It learns what's normal on your Mac, then alerts you the instant a new app gains one of these high-value permissions, which is precisely when you'd want to look.

## How it works

It makes **no network calls**. Everything it reads is local system state.

On each run it reads the TCC databases directly with `sqlite3` (opened read-only via `immutable=1` so it never fights macOS for a lock):

- your user database: `~/Library/Application Support/com.apple.TCC/TCC.db`
- the system database: `/Library/Application Support/com.apple.TCC/TCC.db`

From each it runs `SELECT service, client, client_type, auth_value FROM access WHERE auth_value IN (2,3)` — that is, only permissions that are actually **granted** (allowed / limited), not ones you denied.

It then keeps **only** these six high-value services and discards everything else (camera, microphone, contacts, calendar, photos, etc. are treated as noise and ignored):

| Raw TCC service code | What it means |
|---|---|
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access |
| `kTCCServiceScreenCapture` | Screen Recording |
| `kTCCServiceAccessibility` | Accessibility control |
| `kTCCServiceListenEvent` | Input Monitoring (keylogging-capable) |
| `kTCCServicePostEvent` | Keystroke/mouse injection (PostEvent) |
| `kTCCServiceAppleEvents` | Automation (Apple Events) |

Each surviving grant becomes one stable line of the form `tcc|<service>|<client>`, where `client` is either an absolute path to the app's binary or a bundle identifier. That list is sorted, de-duplicated, and compared against the saved baseline.

For any *new* grant whose client is an absolute path, it also runs a **code-signature check** (`oms_codesign_verdict`, cached by path + inode + mtime) to see whether that binary is Apple-signed, Developer-ID-signed, ad-hoc signed, unsigned, or missing.

## What it flags (and how serious)

- **skip** — Full Disk Access isn't available (see Permissions). The check does nothing that run.
- **pass** — the current set of grants exactly matches the baseline: "No new sensitive privacy grants since baseline."
- **info** — a grant that was in the baseline is now gone (the app lost a permission, or was removed). Reported as "Some grants were revoked since baseline" with a line per revoked grant. This is purely informational and never fails the check.
- **warn** — one or more *new* grants appeared since the baseline. Each is listed as `<client> was granted <permission>   [id: tcc|<service>|<client>]`. This is the default for any new grant, including all bundle-identifier clients (which can't be signature-verified).
- **critical** — a new grant whose client is an absolute path **and** the binary at that path is unsigned, ad-hoc signed, or missing, **or** lives in a user-writable location (your home folder, `/tmp`, `/private/var/tmp`, `/private/var/folders`, etc.). This is the classic malware signature — an untrusted binary in a place any process can write, holding a spy-grade permission. The line is prefixed `CRITICAL:` with the reason (e.g. `binary is unsigned; user-writable location`), and the whole check result becomes critical.

When there are new grants, the summary reads "N new sensitive privacy grant(s)" and the check returns a failure.

## What's baselined

Yes — this is a baseline-drift check. **The first run is silent about content:** it records the complete current set of high-value grants as your baseline and reports `pass` ("Baseline recorded (N sensitive privacy grants). New grants will be flagged."). Nothing is treated as suspicious on that first pass, because there's nothing to compare against.

From then on, only *differences* from the baseline are surfaced: newly added grants are evaluated and flagged, and revoked grants are noted as info. When new grants are found, the current snapshot is staged as a "pending" baseline so you can promote it once you've reviewed it.

## Permissions

This check **requires Full Disk Access** — reading the TCC database is itself a protected operation. If the process can't read `~/Library/Application Support/com.apple.TCC/TCC.db`, the check **self-skips** (returns a skip result, summary "needs Full Disk Access") rather than failing or guessing. It prints exactly how to fix it:

> grant FDA to your terminal for interactive scans, or to `/bin/bash` for the agent, or set `checks.security.tcc_audit.enabled false`; see: `oh-my-safety doctor`

In other words: for manual `oh-my-safety` runs, grant Full Disk Access to your terminal app; for the background agent, grant it to `/bin/bash`. Run `oh-my-safety doctor` to see the current status.

## Configuration

Reads these keys in `~/.config/oh-my-safety/config.yaml`:

- `checks.security.tcc_audit.enabled` — whether the check runs at all (default: `true`).

It has no `tools.*` dependency; it relies only on `sqlite3`, which ships with macOS.

Enable or disable the whole check:

    oh-my-safety disable tcc-audit
    oh-my-safety enable  tcc-audit

## Handling findings

When a new grant appears, decide whether it's something you (or software you trust) approved:

- **It's legitimate** — for example you just installed an app and deliberately gave it Screen Recording. Either accept the whole current state as the new normal:

      oh-my-safety accept tcc-audit

  (this promotes the staged pending snapshot to the baseline), or permanently accept just that one grant:

      oh-my-safety ignore tcc-audit '<finding-id>'

  The finding id is the entry itself: `tcc|<service>|<client>`, where `<service>` is the **raw** TCC service code (e.g. `kTCCServiceScreenCapture`, not the friendly label shown in the message) and `<client>` is the binary path or bundle id, for example:

      tcc|kTCCServiceScreenCapture|/Applications/Zoom.app/Contents/MacOS/zoom.us
      tcc|kTCCServiceAccessibility|com.example.someapp

  Allowlist entries may be exact ids or shell globs, so you can accept a family with a pattern (e.g. `tcc|*|/Applications/Zoom.app/*`).

- **It's suspicious or unknown** — do not accept it. Revoke the permission in **System Settings > Privacy & Security** (find the app under Full Disk Access, Screen Recording, Accessibility, Input Monitoring, or Automation and turn it off), remove the app if it's malware, then confirm it's gone:

      oh-my-safety recheck tcc-audit

## Limitations

- **First-run blindness.** Any grant that already exists when you first run oh-my-safety is baked into the baseline and will never be flagged. Establish the initial baseline on a Mac you believe is clean.
- **It detects change, not badness.** A new grant from software you trust looks identical to one from malware until you inspect it; a warn/critical is a prompt to review, not proof of compromise. A routine app update that legitimately needs a new permission will be flagged.
- **Only six services are tracked.** New grants for camera, microphone, contacts, calendar, photos, location, and other TCC categories are deliberately ignored, so this check will not tell you when an app gains those.
- **Signature escalation is path-only.** The critical escalation applies only to absolute-path clients. A bundle-identifier client (client type 0) can't be code-signature-verified here, so even a malicious one is reported as a plain warning.
- **In-place tampering isn't seen.** The id is based on the service and client *path/bundle id*. If an attacker replaces the binary behind an already-baselined grant without changing its path, the id is unchanged and no new finding appears (beyond what the code-signature cache happens to notice on a genuinely new grant).
- **Userspace tool.** oh-my-safety runs as your user with ordinary privileges. Modifying TCC itself requires elevated access, but root-level or kernel-level malware could tamper with the databases, the baseline files, or disable the agent outright. And because the check requires Full Disk Access to run at all, it goes quiet (skips) exactly on machines where that permission hasn't been granted. Treat a clean result as reassuring, not as a guarantee.
