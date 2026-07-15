#!/bin/bash
# oh-my-safety - `baseline` subcommand: inspect and manage check baselines.

cmd_baseline() {
    local sub="${1:-list}"
    shift || true
    case "$sub" in
        list)    baseline_list ;;
        show)
            [[ -z "${1:-}" ]] && { echo "usage: oh-my-safety baseline show <check>"; return 1; }
            baseline_load "$1" ;;
        approve|accept)
            [[ -z "${1:-}" ]] && { echo "usage: oh-my-safety baseline approve <check>"; return 1; }
            baseline_approve "$1" ;;
        reset)
            [[ -z "${1:-}" ]] && { echo "usage: oh-my-safety baseline reset <check>"; return 1; }
            baseline_reset "$1"
            log_info "Baseline reset for: $1 (next scan re-snapshots)" ;;
        *)
            echo "usage: oh-my-safety baseline {list | show <check> | approve <check> | reset <check>}"
            return 1 ;;
    esac
}

cmd_checks() { checks_list "$@"; }
