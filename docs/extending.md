# Extending oh-my-safety

oh-my-safety is built to grow. A check is just a bash file that follows a small,
versioned contract — the framework discovers it, gates it by config, runs it,
records its result, handles notifications and de-duplication, and lets users
`ignore`/`accept` its findings. You don't touch the runner, the CLI, the config
loader, or the docs index to add one.

## Add a check in three steps

1. Copy the template:
   ```bash
   mkdir -p ~/.config/oh-my-safety/checks
   cp "$(brew --prefix)/opt/oh-my-safety/libexec/lib/checks/_template.sh.example" \
      ~/.config/oh-my-safety/checks/my-check.sh
   ```
2. Set `CHECK_NAME="my-check"` (must match the filename) and rename the function
   to `check_my_check` (dashes → underscores).
3. Run it:
   ```bash
   oh-my-safety scan --check my-check
   oh-my-safety checks            # it now appears under "custom"
   ```

To ship a check in the repo instead, drop it in `lib/checks/<category>/<name>.sh`
and run `make docs` to scaffold its doc page and add it to the catalog.

## The manifest (single source of truth)

These header variables are read by **both** the runner and the docs generator,
so the catalog can never drift from the code:

```bash
CHECK_NAME="my-check"               # MUST equal the filename without .sh
CHECK_DESCRIPTION="One-line summary"
CHECK_CATEGORY="security"           # informational; the parent dir is canonical
CHECK_PLATFORMS="macos"             # space-separated, or "all"
CHECK_SEVERITY="warn"               # default severity of a finding: warn | critical
CHECK_CONTRACT="2"                  # contract version you target (see below)
CHECK_REQUIRES_NETWORK="false"      # true => skipped by `scan --offline`
CHECK_INTERVAL="600"                # daemon cadence hint (seconds)
CHECK_DOC="docs/checks/security/my-check.md"   # optional
```

## The function contract

Define `check_<name_with_underscores>()`. Its **exit code** is the result:

| Return | Meaning |
|--------|---------|
| `0`  | Passed — no findings |
| `1`  | Findings present |
| `77` | Self-skip (e.g. a permission is missing) |

Before returning, you may set:

- `CHECK_FINDING_SUMMARY` — a one-line summary (no tabs/newlines) shown in
  `status`, the menu bar, and notifications. On a skip, put the reason here.
- `CHECK_RESULT_SEVERITY` — `warn` or `critical`, overriding the manifest
  severity for this run (e.g. escalate when the offending binary is unsigned).

Print human detail with `print_check_result <pass|info|warn|critical|skip> "msg"`
and indented `echo "  ..."` lines. **Do not** send notifications yourself — the
runner does that, with de-duplication, based on your return + severity.

## Finding IDs, allowlists, and baselines

Give every actionable item a **stable finding-id** (path-based, never
pid/time-based) and print it so users can accept it:

```bash
echo "  - world-writable: $f   [id: mycheck:$f]"
allowlist_match "$CHECK_NAME" "mycheck:$f" && continue   # skip accepted items
```

For "new since I approved it" detection, use the baseline API (`baseline_exists`,
`baseline_save`, `baseline_diff`, `baseline_stage_pending`) — see
[baselines-and-state.md](baselines-and-state.md) and the drift idiom in the
template. The first run should snapshot quietly and return `0`.

## Helpers you can call

Framework: `print_check_result`, `log_debug`, `config_get`, `config_get_list`,
`config_enabled`, `config_expand_path`, `allowlist_match`, `optional_tool`.
macOS: `oms_codesign_verdict` (cached), `oms_proc_path`, `oms_plist_program`,
`oms_is_user_writable_path`, `oms_in_cloud_path`, `oms_has_fda`,
`oms_file_mode/mtime/size/uid`, `oms_sha256`.

## Rules

- **bash 3.2 compatible** — no `declare -A`, `mapfile`/`readarray`, `${x^^}`/`${x,,}`, `|&`.
- **Security checks make no network calls** — enforced by CI (`grep` gate).
- **No sudo, degrade gracefully** — if you lack a permission, return `77` with a
  clear reason rather than failing.
- **`CHECK_CONTRACT`** lets the runner skip a check written against a newer
  contract than it understands (instead of misbehaving), so the catalog can
  evolve across releases. This build supports contract **2**.

Run `make lint` (shellcheck) and `oh-my-safety scan --check my-check` before
submitting.
