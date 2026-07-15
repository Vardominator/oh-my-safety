#!/bin/bash
# oh-my-safety - handling findings: ignore, re-check, accept.
#
# When a check reports something, the user can either:
#   - ignore it (allowlist a specific finding they accept), or
#   - address it and re-check for confirmation it's resolved, or
#   - accept the current system state as the new baseline (for drift checks).

cmd_ignore() {
    local check="$1" id="$2"
    if [[ -z "$check" || -z "$id" ]]; then
        echo "usage: oh-my-safety ignore <check> <finding-id>"
        echo "Finding IDs are shown when you run:  oh-my-safety scan --check <check>"
        return 1
    fi
    allowlist_add "$check" "$id" "ignored by user"
    echo "Confirm it no longer appears with:  oh-my-safety recheck $check"
}

cmd_ignored() {
    local check="$1"
    if [[ -z "$check" ]]; then
        echo "usage: oh-my-safety ignored <check>"
        return 1
    fi
    allowlist_show "$check"
}

# Re-run a single check to confirm a finding was addressed.
cmd_recheck() {
    local check="$1"
    if [[ -z "$check" ]]; then
        echo "usage: oh-my-safety recheck <check>"
        return 1
    fi
    load_platform
    run_scan --check "$check" --deep
}

# Accept the current system state as the new baseline for a drift-based check
# ("yes, I made that change / it's expected now").
cmd_accept() {
    local check="$1"
    if [[ -z "$check" ]]; then
        echo "usage: oh-my-safety accept <check>"
        echo "Accepts pending baseline changes so they stop being flagged."
        return 1
    fi
    baseline_approve "$check"
}
