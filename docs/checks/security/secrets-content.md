# secrets-content

An opt-in deep scan that runs an external secret scanner (gitleaks and/or trufflehog) over your source-code folders to find hard-coded passwords, API keys, and tokens sitting in files on disk.

**Category:** security · **Default severity:** warn · **Platforms:** macos · **Runs every:** 86400s (in the background agent)

## What it protects you from

Developers accidentally leave secrets in their code all the time: an AWS key pasted into a config file, a database password in a `.env`, a personal access token in an old script, a private key checked into a repo. Any of these is a live credential that can be stolen and abused.

The threat is concrete:

- **Malware and infostealers** (like the AMOS/Atomic Stealer family) specifically comb your home folder and dev directories for exactly these files, because a single leaked cloud key can let an attacker spin up servers on your bill or reach into your company's infrastructure.
- **Accidental publishing** — pushing a repo to GitHub, sharing a zip, or backing up a folder — can expose a secret to the whole internet in seconds, and automated bots scrape new public secrets within minutes.

This check surfaces those secrets *before* someone else finds them, so you can rotate the credential and clean up the file while it is still your problem and not an incident.

## How it works

This check **makes no network calls**, and it goes out of its way to keep it that way even though the tools it drives are capable of phoning home:

- It is **off by default** and only does anything when (a) the check itself is enabled *and* (b) at least one of `tools.gitleaks` / `tools.trufflehog` is enabled in config *and* the corresponding binary is already installed. oh-my-safety never installs or auto-updates these tools.
- It reads the list of folders to scan from `checks.security.secrets_content.scan_roots`. If that list is empty (the default), it falls back to `~/Projects`, `~/Developer`, `~/code`, and `~/src`. Any root that does not exist on disk is silently skipped.
- For each existing root:
  - **gitleaks** is run as `gitleaks dir "<root>" --redact --no-banner`. The `--redact` flag is mandatory so that if a secret is found, its actual value is never printed or logged — only the fact that something was flagged.
  - **trufflehog** is run as `trufflehog filesystem "<root>" --no-verification --no-update --json`. The `--no-verification` flag is non-negotiable: by default trufflehog *sends each candidate credential to its issuing service to check if it's live*, which would be an outbound network call. This check disables that entirely. `--no-update` stops trufflehog from auto-updating itself over the network.

A finding is registered whenever gitleaks exits non-zero (its signal that it found something) or whenever trufflehog produces any JSON output.

## What it flags (and how serious)

- **pass** — a tool is enabled and installed, all scan roots came back clean: "No secrets found by content scan".
- **skip** — no scanner is both enabled and installed. The check quietly self-skips with "content scan off — enable tools.gitleaks or tools.trufflehog and install the tool" and does nothing else.
- **warn** — one or more scan roots contain potential secrets. This is the only failing state, and it is a **warn** (not critical). Each flagged root produces a line naming the tool and the folder, plus the exact command to re-run so you can inspect the detail yourself, for example:

  ```
  gitleaks flagged potential secrets under /Users/you/Projects
    - inspect: gitleaks dir '/Users/you/Projects' --redact   [id: sec-content:gitleaks:/Users/you/Projects]
  ```

  The overall summary reports how many locations were flagged (e.g. "2 location(s) with potential secrets"). Note the finding tells you *that* a folder has secrets and how to look, but never prints the secret values themselves.

## What's baselined

This check does **not** use baseline drift. It has no concept of "quietly recording a first run" and no `accept` flow — every run is a fresh scan, and any flagged root shows up again on the next run until you either clean it up or explicitly ignore it (see below).

## Permissions

**None required.** It does not need Full Disk Access or any TCC permission. It reads only files it already has ordinary read access to, inside your own home-folder project directories. Its one "dependency" is a tool you have chosen to enable and install — if that tool isn't present, the check self-skips rather than erroring.

## Configuration

Config keys under `checks.security.secrets_content` in `~/.config/oh-my-safety/config.yaml` (defaults from `config/default.yaml`):

- `enabled` — `false` (this check is off by default)
- `scan_roots` — `[]` (empty; falls back to `~/Projects`, `~/Developer`, `~/code`, `~/src`)

It also depends on the opt-in tool switches under `tools.*`:

- `tools.gitleaks.enabled` — `false`
- `tools.trufflehog.enabled` — `false`

Enabling the check alone is not enough to make it do work — you must also enable at least one tool and have it installed. A typical setup:

```
oh-my-safety enable secrets-content
oh-my-safety set tools.gitleaks.enabled true
# (install gitleaks yourself, e.g. `brew install gitleaks`)
```

Enable or disable the check:

```
oh-my-safety disable secrets-content
oh-my-safety enable  secrets-content
```

## Handling findings

When a folder is flagged, run the `inspect:` command shown in the finding to see exactly which files and rules matched (values stay redacted). Then:

1. **If it's a real secret**: remove or rotate the credential — delete the hard-coded value, replace it with an environment variable or secret manager, invalidate the leaked key at its provider, and scrub it from git history if it was committed. Then confirm it's clean with:
   `oh-my-safety recheck secrets-content`
2. **If it's a false positive or a secret you deliberately keep there** (a test fixture, an example key): permanently accept that location using its finding id:
   `oh-my-safety ignore secrets-content 'sec-content:gitleaks:/Users/you/Projects'`

   The finding-id scheme is `sec-content:<tool>:<root>`, where `<tool>` is `gitleaks` or `trufflehog` and `<root>` is the scanned directory path. Copy the exact id from the `[id: ...]` field. Because allowlist entries accept shell globs, you can also ignore all gitleaks results with `'sec-content:gitleaks:*'`, or everything under one tree with `'sec-content:*:/Users/you/Projects*'`.

`oh-my-safety accept` does **not** apply to this check — there is no baseline to promote. Use `ignore` for anything you want to permanently accept.

## Limitations

- **You supply the engine.** This check is only as good as gitleaks/trufflehog and the versions you have installed. Because oh-my-safety never updates them (`--no-update` is forced), an old tool with stale rules will miss newer secret formats until you update it yourself.
- **Folder-level results only.** A finding tells you a whole root contains secrets; it does not, by itself, name the specific file — you re-run the `inspect:` command to drill in.
- **False positives are common.** High-entropy strings, example keys, and test fixtures routinely trip secret scanners. A warn here means "look," not "you are compromised."
- **Coverage is limited to configured roots.** Only the folders in `scan_roots` (or the four defaults) are scanned, and only if they exist. Secrets living outside those trees — on external drives, in other users' homes, in unusual project locations — are never seen.
- **Off by default and slow-cadence.** It runs at most once a day and only after you opt in, so it is a periodic hygiene sweep, not a real-time alarm.
- **Userspace check.** Like all of oh-my-safety's checks, it runs as your user and can be disabled or fed false data by anything already running with root privileges; it is not a defense against a fully compromised machine.
