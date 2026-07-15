# process-audit

Scans the processes currently running on your Mac and flags the ones that look like malware: unverified binaries launched from temp/download folders, apps run straight out of a quarantined download, binaries that deleted themselves off disk while still running, and password-phishing pop-ups driven by `osascript`.

**Category:** security · **Default severity:** warn · **Platforms:** macos · **Runs every:** 60s (in the background agent)

## What it protects you from

macOS infostealers like Atomic Stealer (AMOS) and its many clones are the most common real threat to everyday Mac users. They arrive as a "cracked app," a fake browser update, or a bogus meeting client, and once you run them they try to sweep up your browser passwords, crypto wallets, and Keychain, then send everything to an attacker.

This check watches for the tell-tale fingerprints of that behavior while it is happening:

- **A fresh download running from a temp or Downloads folder that isn't signed by a real developer.** Legitimate software is code-signed by Apple or a registered developer. A brand-new, unsigned binary running out of `/tmp` or `~/Downloads` is a classic stealer.
- **The infamous "enter your password" pop-up.** AMOS-family malware famously fakes a macOS password prompt using `osascript` so you type your login password straight into the malware. This check specifically hunts for that pop-up.
- **Self-cleaning malware.** Some malware deletes its own file from disk after launching so nothing is left for you (or an antivirus scan) to find later. This check catches a process whose binary has vanished while it is still running.
- **Apps launched straight from a quarantined download** (App Translocation), which is how many people unknowingly run something they just downloaded instead of installing it properly.

Catching these while the process is live gives you a chance to kill it and change your passwords before the damage spreads.

## How it works

Everything runs locally. **This check makes no network calls.**

1. It lists the full executable path of every running process with `ps -axo comm=`, keeps only real filesystem paths (lines starting with `/`), and de-duplicates them. Without root, it mainly sees your own processes' paths, which is exactly where user-level malware lives.
2. For each path it applies these tests:
   - **Deleted-while-running:** if the path no longer exists on disk (`[ ! -e "$path" ]`), the process is running from a binary that was removed.
   - **App Translocation:** if the path contains `/AppTranslocation/`, the app was launched from a quarantined/translocated location.
   - **Signature in a drop zone:** only for paths inside a "drop zone" (see below), it asks macOS for the code-signing verdict via `oms_codesign_verdict` (which runs `codesign -dvv` under the hood and caches the result). It flags a verdict of `unsigned` or `adhoc`.
3. Separately, it scans full process arguments with `ps -axo args=` for any `osascript` invocation whose script contains a `hidden answer` prompt, or both `display dialog` and `password`. That pattern is the phishing pop-up.

The "drop zone" is intentionally narrow so it doesn't nag you about normal developer tools. A path counts as a drop zone only if it is under: `/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`, `/private/var/folders`, `~/Downloads`, or `~/Library/Caches`. Unsigned tools elsewhere (`~/.pyenv`, `/opt/homebrew`, `/Applications`) are treated as normal and are not reported.

## What it flags (and how serious)

**Pass:** No suspicious processes detected.

**Warn:**
- A running process whose binary was **deleted while running** but is *not* in a drop zone. Example line:
  `- /some/path/tool (deleted while running -- possible self-cleaning malware)   [id: proc:deleted:/some/path/tool]`
- A process running from an **App Translocation** path:
  `- /path/.../AppTranslocation/... running from a quarantined/translocated location (app launched straight from a download)   [id: proc:translocated:/path...]`

**Critical:**
- A **deleted-while-running binary that was in a drop zone** (e.g. running out of `/tmp`) — same finding as above but escalated to critical.
- An **unsigned or ad-hoc-signed binary running from a drop zone**:
  `- /tmp/whatever (code signature: unsigned)   [id: proc:/tmp/whatever]`
- **osascript password phishing** detected:
  `- an osascript process is prompting for a password (classic macOS stealer behavior)   [id: proc:osascript-phishing]`

If several things are flagged, the overall result takes the highest severity seen, and the summary reads `N suspicious process finding(s)`.

## What's baselined

**This check does not use baseline drift.** It re-evaluates the live process list every run and reports whatever looks suspicious right now. There is no "first run records, later run flags" behavior and no `accept` snapshot to maintain — a process either matches a suspicious pattern or it doesn't.

(The code-signing verdict is cached to disk keyed by file inode and modification time, purely to avoid re-running `codesign` on unchanged binaries. That is a performance cache, not a security baseline.)

## Permissions

**No special permissions are required.** It does not need Full Disk Access or any TCC prompt.

It relies only on `ps` and `codesign`, which work without elevated privileges. Without root, `ps` shows the full paths of your own processes but hides most binary paths owned by other users; those unreadable entries are simply dropped. In practice this is fine, because user-level infostealers run as *you*, so their paths are visible. There is no self-skip — the check always runs, it just sees fewer processes without root.

## Configuration

Config lives under `checks.security.process_audit` in `config.yaml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Master on/off for this check. |
| `osascript_phishing_detect` | `true` | Scan running `osascript` args for fake password prompts. |
| `flag_deleted_binaries` | `true` | Flag processes whose binary was deleted while running. |

There are no `tools.*` dependencies; it uses only built-in macOS commands.

Enable or disable the whole check:

    oh-my-safety disable process-audit
    oh-my-safety enable  process-audit

## Handling findings

If a finding is real, treat it as urgent: quit the suspicious process, and if you saw the osascript password prompt, assume your password may be compromised and change it (and any Keychain-stored passwords). After you've dealt with it, confirm the process is gone:

    oh-my-safety recheck process-audit

If a finding is a false alarm — for example, a trusted dev tool you knowingly run unsigned out of `~/Library/Caches` — you can permanently accept that specific item by its finding id:

    oh-my-safety ignore process-audit '<finding-id>'

The finding ids this check emits are:

- `proc:deleted:<full-path>` — a deleted-while-running binary
- `proc:translocated:<full-path>` — an App Translocation launch
- `proc:<full-path>` — an unsigned/ad-hoc binary in a drop zone
- `proc:osascript-phishing` — the osascript password-prompt pattern

Allowlist entries support glob patterns, so you can ignore a family of paths at once, e.g. `oh-my-safety ignore process-audit 'proc:/private/var/folders/*'`. Note that `ignore` here means "never flag this again," so use it sparingly.

Because this check has no baseline, `oh-my-safety accept process-audit` does not apply.

## Limitations

- **Userspace only.** It uses `ps` and `codesign` as a normal user. Root-level malware (a kernel extension, a rootkit, or anything that can lie to `ps`) can hide from it entirely. Treat a clean result as "nothing obvious," not "guaranteed clean."
- **Narrow signature scope on purpose.** It only checks signatures for binaries in the drop-zone list. Malware that installs itself into `/Applications`, `/opt/homebrew`, or a hidden folder in your home directory outside `~/Downloads`/`~/Library/Caches` will not have its signature flagged here (persistence and other checks cover different ground).
- **osascript detection is pattern-based.** A legitimate app that genuinely asks for a password via `osascript display dialog` will be flagged as a false positive; conversely, malware that phishes for credentials some other way (a custom app, a browser page) won't match this pattern.
- **Point-in-time.** It only sees processes running at the moment it scans. Malware that runs briefly between the 60-second scans can be missed. A deleted binary is only caught while its process is still alive.
- **Signature results can be stale.** The `codesign` verdict is cached by inode and mtime; this is normally safe, but it means the signature is only re-evaluated when the file itself changes.
