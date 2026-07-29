#!/bin/bash
# oh-my-safety - user-facing wrappers for portable local scanner commands.

cmd_secret_scan() {
    local agent db roots root
    local -a arguments=()
    agent="$(_organization_agent)" || return 1
    db="$(state_path 'journal.db')"
    if [[ $# -gt 0 ]]; then
        for root in "$@"; do
            arguments+=(--scan-secrets "$(config_expand_path "$root")")
        done
    else
        roots="$(config_get_list 'checks.security.local_secret_scan.scan_roots')"
        [[ -n "$roots" ]] ||
            roots="$(printf '%s\n' "$HOME/Projects" "$HOME/Developer" "$HOME/code" "$HOME/src")"
        while IFS= read -r root; do
            [[ -z "$root" ]] && continue
            root="$(config_expand_path "$root")"
            [[ -d "$root" || -f "$root" ]] && arguments+=(--scan-secrets "$root")
        done <<EOF
$roots
EOF
    fi
    [[ "${#arguments[@]}" -gt 0 ]] || {
        log_error "No local secret scan roots exist; pass one or more paths"
        return 2
    }
    "$agent" --state-db "$db" "${arguments[@]}"
}

cmd_triage_executable() {
    local agent db path
    local -a arguments=()
    [[ $# -gt 0 ]] || {
        log_error "usage: oh-my-safety triage-executable PATH [PATH ...]"
        return 2
    }
    agent="$(_organization_agent)" || return 1
    db="$(state_path 'journal.db')"
    for path in "$@"; do
        arguments+=(--triage-executable "$(config_expand_path "$path")")
    done
    "$agent" --state-db "$db" "${arguments[@]}"
}
