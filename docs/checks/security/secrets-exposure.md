# secrets-exposure

Scans well-known locations for keys, credential files, shell histories, `.env` files, and credential-looking notes that are readable by other users or sitting unprotected — using file names and permissions only, never reading the contents.

**Category:** security · **Default severity:** warn · **Platforms:** macos · **Runs every:** 3600s (in the background agent)

## What it protects you from

Secrets don't leak only through fancy exploits. Far more often they leak because a file that should be private is readable by anyone, or a sensitive note is sitting in plain sight.

- **Over-permissive SSH and cloud keys.** If your SSH private key or `~/.aws/credentials` is readable by other accounts on the machine — or by another program running as a different user — those keys can be copied and reused. If such a file is *world-writable*, an attacker can replace it entirely (for example swapping in their own SSH key).
- **Backdoored SSH access.** An attacker who gains a foothold often appends their own key to `~/.ssh/authorized_keys` so they can log back in later, even after you change your password. This check notices when that file changes.
- **Secrets in shell history.** Passwords and API tokens you typed on the command line end up in `~/.zsh_history` and friends. If those files are readable by others, so are the secrets.
- **Leaked `.env` files.** Project `.env` files routinely hold database passwords and API keys. A group/other-readable `.env` exposes them to anything else running on your Mac.
- **Plaintext seed phrases and password notes.** A file literally named `seed phrase.txt` or `passwords.docx` on your Desktop or in Downloads is exactly what infostealer malware (and nosy apps) hunt for. Storing a crypto seed phrase in a plaintext file is one of the most common ways people get their wallets drained.

Why care: these are the mistakes that turn a minor compromise into a total one. Locking down file permissions and moving secrets out of plaintext costs nothing and closes the easiest doors.

## How it works

The check reads only **metadata** — file existence, octal permission modes, SHA-256 hashes, and file names. It never opens or reads the contents of any file, and it makes **no network calls**. It runs five passes:

1. **`~/.ssh`** — flags the directory if its mode isn't `700`, then checks every regular file in it *except* `*.pub`, `*known_hosts*`, `config`, `authorized_keys`, `environment`, and `.DS_Store`. Those remaining files (your private keys) are flagged if group or other can read them.
2. **Fixed credential files** — checks a fixed list: `~/.aws/credentials`, `~/.aws/config`, `~/.config/gcloud/legacy_credentials`, `~/.config/gcloud/application_default_credentials.json`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`, `~/.kube/config`. `~/.netrc` is held to a stricter `600` standard (any group *or* other access at all is a finding).
3. **Shell histories** — `~/.zsh_history`, `~/.bash_history`, `~/.python_history`, `~/.psql_history`, `~/.mysql_history`, `~/.node_repl_history`, flagged if group/other-readable.
4. **`.env` sweep** — runs `find` under `~/Projects`, `~/Developer`, `~/code`, `~/src`, and `~/dev` (down to a configurable depth, default 3), pruning `node_modules`, `.git`, and `vendor`, matching `.env*` files while skipping `*.example` and `*.sample`. Any match that is group/other-readable is counted.
5. **Filename scan** — uses macOS Spotlight (`mdfind`) to search `~/Desktop`, `~/Documents`, `~/Downloads`, and iCloud Drive for names containing `password`, `seed phrase`, `mnemonic`, `recovery phrase`, `private key`, or `2fa` (case- and accent-insensitive). Only plaintext-ish files are flagged — no extension, or `.txt`, `.md`, `.rtf`, `.csv`, `.doc`, `.docx`, `.pages`, `.numbers`, `.xlsx`. (A `.kdbx` password manager vault, for instance, is ignored because it's encrypted.)

Permission decisions use the file's octal mode: "readable by others" means the group or other read bit is set; "writable by others" means the world (other) write bit is set.

## What it flags (and how serious)

The check reports the single highest severity it finds; each item is listed with its own finding id.

**Warn** (the common case):
- SSH private key, credential file, or shell history that is group/other-readable.
- `~/.ssh` directory not mode `700` (but not world-writable).
- `~/.netrc` with any group/other permission bit set.
- One or more unprotected (`group/other-readable`) `.env` files — reported as a single count, e.g. `3 unprotected .env file(s)`, listing up to 10 paths then `... and N more`.
- A possible credential/seed/password note found by the filename scan.
- `~/.ssh/authorized_keys` changed since the last baseline (a new key may be a backdoor).

**Critical** (escalation for the most dangerous state):
- An SSH private key, one of the listed credential files, or `~/.netrc` that is **world-writable** — anyone can overwrite it.
- `~/.ssh` directory that is world-writable.

Shell histories and `.env` files are never escalated to critical (only ever warn), and the filename scan and `authorized_keys` drift are warn-only.

**Info:** if the filename scan couldn't fully run (Spotlight unavailable, or a folder isn't readable), it prints one informational line noting the scan was limited — this does not fail the check.

**Pass:** none of the above — `No exposed keys, credential files, or unprotected credential notes found`.

## What's baselined

Only `~/.ssh/authorized_keys` uses baseline drift. On the first run (if the file exists), the check quietly records a SHA-256 hash of the file and reports nothing. On a later run, if the hash differs, it warns once that the file changed, then immediately re-records the new hash as the baseline. That "report once, then re-baseline" design means each distinct change is surfaced a single time rather than nagging forever — so if a key really was added by an attacker, you get exactly one notification about it.

Everything else in this check (permissions, `.env` sweep, filename scan) is evaluated fresh each run with no baseline.

## Permissions

Most of this check needs **no special permission** — reading permission modes and hashes of files in your own home directory works out of the box.

The one exception is the Spotlight filename scan. It self-degrades: if `mdfind` isn't available, or a folder (notably iCloud Drive) can't be read without Full Disk Access, that folder is skipped, a single "Filename scan was limited" info line is printed, and the rest of the check runs normally. Granting the background agent Full Disk Access makes the filename scan more thorough but is not required.

## Configuration

Config keys live under `checks.security.secrets_exposure`:

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Whether the check runs at all. |
| `env_scan_depth` | `3` | `find` max depth for the `.env` sweep. Non-numeric values fall back to 3. |
| `filename_scan` | `true` | Set to `false` to skip the Spotlight/`mdfind` name scan entirely. |

No `tools.*` entries are required. The filename scan uses the system `mdfind` command directly.

Enable or disable the whole check:

    oh-my-safety disable secrets-exposure
    oh-my-safety enable  secrets-exposure

## Handling findings

**Fix, then confirm.** Most findings are a one-line fix:

- SSH key readable/writable: `chmod 600 ~/.ssh/id_ed25519` (and `chmod 700 ~/.ssh`).
- Credential file: `chmod 600 ~/.aws/credentials`.
- `.netrc`: `chmod 600 ~/.netrc`.
- Unprotected `.env`: `chmod 600 path/to/.env`.
- Plaintext seed/password note: move it into an encrypted password manager or vault, then delete the plaintext copy.

Then re-run just this check to confirm it's resolved:

    oh-my-safety recheck secrets-exposure

**Accept a specific item.** If a finding is expected and harmless, permanently ignore it by its finding id:

    oh-my-safety ignore secrets-exposure '<finding-id>'

The finding-id schemes used by this check are:

- `sec:<path>:perms` — a permission finding on a specific file (e.g. `sec:/Users/you/.ssh/id_rsa:perms`).
- `sec:ssh-dir:perms` — the `~/.ssh` directory mode finding.
- `sec:authorized_keys:changed` — the authorized_keys drift finding.
- `sec:env-files` — the entire `.env` sweep (ignoring this silences all `.env` findings at once).
- `sec:file:<path>` — a specific filename-scan hit (e.g. `sec:file:/Users/you/Desktop/passwords.txt`).

**Accept an `authorized_keys` change as the new normal.** Because drift on that file re-baselines automatically after reporting, an explicit accept is rarely needed, but you can force the current state to become the baseline with:

    oh-my-safety accept secrets-exposure

See what you've already ignored with `oh-my-safety ignored secrets-exposure`.

## Limitations

- **Metadata only.** By design the check never reads file contents, so it judges by name, location, and permissions. It cannot tell whether `passwords.txt` actually holds passwords, nor whether a file with an innocuous name contains a secret. Expect the occasional harmless-file false positive from the filename scan (use `ignore` for those), and don't rely on it to find secrets hidden in oddly-named files. The separate `secrets-content` check reads contents to find real secrets.
- **Fixed lists.** Permission checks cover a specific set of credential files; a credential file not on that list won't be examined. The `.env` sweep only looks under five fixed project roots (`~/Projects`, `~/Developer`, `~/code`, `~/src`, `~/dev`) to a limited depth — projects elsewhere, deeper than `env_scan_depth`, or inside `node_modules`/`.git`/`vendor` are not scanned.
- **Spotlight dependence.** The filename scan is only as good as the Spotlight index and only covers four folders and a short list of plaintext extensions. Unindexed files, encrypted vaults, and other locations are missed.
- **"Readable by others" on a single-user Mac.** If you're the only account, a group/other-readable file is lower risk than the wording suggests — but it's still surfaced, so some findings may feel like noise. `ignore` them if you accept the risk.
- **Userspace check.** Everything here runs as your user. Malware with root privileges can hide files from Spotlight, alter permissions back, or tamper with the baseline — this check cannot detect a compromise operating below its own privilege level.
