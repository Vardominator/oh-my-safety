#!/bin/bash
# oh-my-safety - Per-check allowlists
#
# An allowlist is a user-approved set of "finding IDs" for a check. Entries may
# be exact IDs or shell globs (matched with bash `case`). Allowlisted findings
# are suppressed so a check stops flagging things the user has reviewed.
#
# Stored under the state dir at allowlist/<check>.list, one entry per line;
# "#" comment lines and blank lines are ignored.

[[ -n "${_OMS_ALLOWLIST_LOADED:-}" ]] && return 0
_OMS_ALLOWLIST_LOADED=1

_allowlist_file() { state_path "allowlist/$1.list"; }

# Return 0 if a finding ID matches any allowlist entry for the check.
allowlist_match() {
    local check="$1" id="$2"
    local f entry
    f="$(_allowlist_file "$check")"
    [[ -f "$f" ]] || return 1
    while IFS= read -r entry || [[ -n "$entry" ]]; do
        entry="${entry%$'\r'}"
        [[ -z "${entry//[[:space:]]/}" ]] && continue
        [[ "$entry" =~ ^[[:space:]]*# ]] && continue
        # Trim surrounding whitespace
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        # Strip a trailing "# comment"
        entry="${entry%%[[:space:]]#*}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        # shellcheck disable=SC2254  # glob match is intentional
        case "$id" in
            $entry) return 0 ;;
        esac
    done < "$f"
    return 1
}

# Append a finding ID (with optional comment) to a check's allowlist.
allowlist_add() {
    local check="$1" id="$2" comment="${3:-}"
    local f
    f="$(_allowlist_file "$check")"
    if [[ ! -f "$f" ]]; then
        {
            printf '# oh-my-safety allowlist for check: %s\n' "$check"
            printf '# One finding ID or glob per line. "#" starts a comment.\n'
        } > "$f"
        chmod 600 "$f" 2>/dev/null || true
    fi
    if [[ -n "$comment" ]]; then
        printf '%s  # %s (added %s)\n' "$id" "$comment" "$(date -u '+%Y-%m-%d')" >> "$f"
    else
        printf '%s  # added %s\n' "$id" "$(date -u '+%Y-%m-%d')" >> "$f"
    fi
    log_info "Allowlisted '$id' for $check"
}

# Print a check's allowlist entries (raw file, for inspection).
allowlist_show() {
    local f
    f="$(_allowlist_file "$1")"
    [[ -f "$f" ]] && cat "$f" || echo "No allowlist for: $1"
}
