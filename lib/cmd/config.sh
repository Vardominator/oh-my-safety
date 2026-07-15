#!/bin/bash
# oh-my-safety - `enable` / `disable` / `set` subcommands.
# Everything is enabled by default; these write to the override layer so a user
# can turn individual checks (or a whole category) on/off without editing YAML.

# Resolve a user-supplied target to "cat:<category>" or "check:<category>:<name>".
_resolve_target() {
    local target="$1" cat name file
    while IFS=$'\t' read -r cat name file; do
        [[ "$name" == "$target" ]] && { echo "check:$cat:$name"; return 0; }
    done < <(checks_discover)
    while IFS=$'\t' read -r cat name file; do
        [[ "$cat" == "$target" ]] && { echo "cat:$target"; return 0; }
    done < <(checks_discover)
    return 1
}

_toggle() {
    local target="$1" val="$2" word r cat rest name
    [[ "$val" == "true" ]] && word="enabled" || word="disabled"
    if [[ -z "$target" ]]; then
        echo "usage: oh-my-safety {enable|disable} <check-or-category>"
        echo "See available targets with: oh-my-safety checks"
        return 1
    fi
    if ! r="$(_resolve_target "$target")"; then
        log_error "Unknown check or category: $target"
        echo "See: oh-my-safety checks"
        return 1
    fi
    case "$r" in
        cat:*)
            cat="${r#cat:}"
            config_set "categories.${cat}.enabled" "$val"
            log_info "Category '$cat' $word (all its checks)" ;;
        check:*)
            rest="${r#check:}"; cat="${rest%%:*}"; name="${rest#*:}"
            config_set "checks.${cat}.${name//-/_}.enabled" "$val"
            log_info "Check '$name' $word" ;;
    esac
}

cmd_enable()  { _toggle "${1:-}" "true"; }
cmd_disable() { _toggle "${1:-}" "false"; }

cmd_set() {
    if [[ -z "${1:-}" || $# -lt 2 ]]; then
        echo "usage: oh-my-safety set <config.path> <value>"
        echo "example: oh-my-safety set notifications.min_severity critical"
        return 1
    fi
    config_set "$1" "$2"
    log_info "Set $1 = $2"
}
