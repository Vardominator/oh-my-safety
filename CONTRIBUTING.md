# Contributing to oh-my-safety

Thanks for contributing! oh-my-safety is designed to grow — most contributions
are new **checks**, which are drop-in files following a documented contract.

## Ways to contribute

- **Add a check** — a new detection (persistence vector, exposure heuristic,
  hardening item) or a privacy check. This is the most valuable contribution.
- **Improve a check** — reduce false positives, cover more artifacts (e.g. more
  wallet paths in `lib/data/`).
- **Docs** — clarify a check page, the threat model, or a guide.
- **Bugs & ideas** — open an issue.

## Development setup

```bash
git clone https://github.com/Vardominator/oh-my-safety.git
cd oh-my-safety
./bin/oh-my-safety scan            # run it without installing
./bin/oh-my-safety scan --offline  # deterministic (no network checks)
make lint                          # shellcheck
make docs                          # regenerate the checks catalog
```

## Project structure

See [docs/architecture.md](docs/architecture.md). The short version: `bin/` is
the dispatcher, `lib/core.sh` + `lib/{yaml,state,allowlist,runner}.sh` are the
framework, `lib/cmd/*` are subcommands, `lib/platform/*` are OS accessors, and
`lib/checks/{privacy,security}/*` are the checks.

## Adding a check

The canonical guide is **[docs/extending.md](docs/extending.md)**. In brief:

1. Create `lib/checks/<category>/<name>.sh` (or, for a personal check,
   `~/.config/oh-my-safety/checks/<name>.sh`).
2. Add the manifest header (`CHECK_NAME`, `CHECK_DESCRIPTION`, `CHECK_CATEGORY`,
   `CHECK_PLATFORMS`, `CHECK_SEVERITY`, `CHECK_CONTRACT`,
   `CHECK_REQUIRES_NETWORK`, `CHECK_INTERVAL`, `CHECK_DOC`).
3. Implement `check_<name_with_underscores>()` returning `0` (pass) / `1`
   (finding) / `77` (skip); set `CHECK_FINDING_SUMMARY` and
   `CHECK_RESULT_SEVERITY`; print with `print_check_result`; filter accepted
   items with `allowlist_match`; use the baseline API for drift detection.
4. Run `make docs` to scaffold its doc page and update the catalog, then fill in
   the page.

Copy `lib/checks/_template.sh.example` to start.

## Rules (enforced by CI)

- **bash 3.2 compatible** — no `declare -A`, `mapfile`/`readarray`,
  `${x^^}`/`${x,,}`, `|&`. Files must pass `/bin/bash -n`.
- **Security checks make no network calls** — `grep -rE 'curl|wget|/dev/tcp|nc '
  lib/checks/security/` must return nothing.
- **No sudo; degrade gracefully** — return `77` with a clear reason when a
  permission is missing rather than failing.
- **Version is single-sourced** in `lib/core.sh` (`OMS_VERSION`); don't hardcode
  it elsewhere.
- **`make docs` must be current** — commit the regenerated catalog.

## Pull requests

Keep PRs focused, run `make lint` and a scan of your new check, and include a
doc page for any new check. Be honest in docs about what a check can't detect —
see the tone in [docs/threat-model.md](docs/threat-model.md). By contributing you
agree your work is licensed under the project's MIT license.
