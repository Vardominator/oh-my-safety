#!/bin/bash
# oh-my-safety - `history` subcommand

_history_usage() {
    cat <<'EOF'
usage: oh-my-safety history [--limit N] [--json|--format tsv]

Shows the newest entries from the local event history. The history contains
scan completion, check results, finding resolution, and notification delivery
metadata. It never contains credential values.
EOF
}

cmd_history() {
    local format="human" limit=100 rows line first=1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) format="json"; shift ;;
            --format)
                [[ $# -ge 2 ]] || { _history_usage >&2; return 3; }
                format="$2"; shift 2 ;;
            --limit)
                [[ $# -ge 2 ]] || { _history_usage >&2; return 3; }
                limit="$2"; shift 2 ;;
            -h|--help) _history_usage; return 0 ;;
            *) log_error "Unknown history option: $1"; _history_usage >&2; return 3 ;;
        esac
    done
    case "$format" in human|json|tsv) : ;; *)
        log_error "Unknown history format: $format"; return 3 ;;
    esac
    case "$limit" in ''|*[!0-9]*) log_error "History limit must be a positive integer"; return 3 ;; esac
    [[ "${#limit}" -le 6 ]] || { log_error "History limit is too large"; return 3; }
    limit="$(( 10#$limit ))"
    [[ "$limit" -gt 0 && "$limit" -le 10000 ]] || {
        log_error "History limit must be between 1 and 10000"
        return 3
    }

    rows="$(event_read_recent "$limit")" || return 3
    if [[ "$format" == "tsv" ]]; then
        printf 'timestamp\ttype\tseverity\tsource\tsubject\tsummary\tcorrelation_id\n'
        [[ -n "$rows" ]] && printf '%s\n' "$rows"
        return 0
    fi
    if [[ "$format" == "json" ]]; then
        printf '{"schema":"io.oh-my-safety/history","schema_version":1,"events":['
        while IFS=$'\t' read -r timestamp type severity source subject summary correlation; do
            [[ -z "$timestamp" ]] && continue
            [[ "$first" -eq 1 ]] && first=0 || printf ','
            printf '{"timestamp":"%s","type":"%s","severity":"%s","source":"%s","subject":"%s","summary":"%s","correlation_id":"%s"}' \
                "$(json_escape "$timestamp")" "$(json_escape "$type")" \
                "$(json_escape "$severity")" "$(json_escape "$source")" \
                "$(json_escape "$subject")" "$(json_escape "$summary")" \
                "$(json_escape "$correlation")"
        done <<EOF
$rows
EOF
        printf ']}\n'
        return 0
    fi

    if [[ -z "$rows" ]]; then
        echo "No history recorded yet. Run: oh-my-safety scan"
        return 0
    fi
    printf '%-20s %-20s %-8s %-18s %s\n' "TIME (UTC)" "EVENT" "SEVERITY" "SUBJECT" "SUMMARY"
    while IFS=$'\t' read -r timestamp type severity source subject summary correlation; do
        [[ -z "$timestamp" ]] && continue
        printf '%-20s %-20s %-8s %-18s %s\n' \
            "${timestamp%:??Z}Z" "$type" "$severity" "$subject" "$summary"
    done <<EOF
$rows
EOF
}
