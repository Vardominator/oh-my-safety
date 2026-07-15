#!/bin/bash
# oh-my-safety - regenerate the checks catalog from check manifests.
#
#   scripts/gen-docs.sh           # write docs/checks/README.md + scaffold stubs
#   scripts/gen-docs.sh --check   # verify it's current (CI); nonzero if stale/missing
#
# The check manifest (CHECK_* header vars) is the single source of truth for
# both the runner and these docs, so the catalog can never silently drift.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin/oh-my-safety"
README="$ROOT/docs/checks/README.md"

mode="write"
[ "${1:-}" = "--check" ] && mode="check"

if ! command -v python3 >/dev/null 2>&1; then
    echo "gen-docs requires python3 (a build-time tool; not needed at runtime)" >&2
    exit 2
fi

json="$("$BIN" checks --json)" || { echo "failed to read check catalog" >&2; exit 2; }

# Generate catalog text (python also scaffolds/validates per-check pages).
gen_rc=0
generated="$(printf '%s' "$json" | python3 "$ROOT/scripts/_gen_catalog.py" "$ROOT" "$mode")" || gen_rc=$?

if [ "$mode" = "check" ]; then
    if [ "$gen_rc" -eq 3 ]; then
        echo "Some checks are missing doc pages (see MISSING above). Run: make docs" >&2
        exit 1
    fi
    if [ ! -f "$README" ] || ! diff <(printf '%s\n' "$generated") "$README" >/dev/null 2>&1; then
        echo "docs/checks/README.md is out of date. Run: make docs" >&2
        exit 1
    fi
    echo "Docs catalog is up to date."
else
    mkdir -p "$(dirname "$README")"
    printf '%s\n' "$generated" > "$README"
    echo "Wrote $README"
fi
