#!/bin/bash
# oh-my-safety - durable, local event history
#
# This compatibility journal is deliberately simple TSV so the existing Bash
# runtime can write and inspect it without a daemon or database dependency.
# The portable Go runtime keeps the richer append-only SQLite journal; this
# file gives every installation a useful history during that migration.

[[ -n "${_OMS_EVENTS_LOADED:-}" ]] && return 0
_OMS_EVENTS_LOADED=1

_event_field() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

_event_numeric_config() {
    local path="$1" fallback="$2" maximum="$3" value
    value="$(config_get "$path" "$fallback")"
    case "$value" in ''|*[!0-9]*) value="$fallback" ;; esac
    [[ "${#value}" -le 9 ]] || value="$fallback"
    value="$(( 10#$value ))"
    [[ "$value" -gt 0 && "$value" -le "$maximum" ]] || value="$fallback"
    printf '%s' "$value"
}

_event_log_path() {
    state_path "log/events.tsv"
}

_event_reverse_file() {
    local file="$1"
    if command -v tac >/dev/null 2>&1; then
        tac "$file"
    else
        tail -r "$file"
    fi
}

_event_log_rotate() {
    local log="$1" max_kb keep size i
    [[ -f "$log" ]] || return 0
    max_kb="$(_event_numeric_config 'logging.max_size_kb' 1024 1048576)"
    keep="$(_event_numeric_config 'logging.keep_rotations' 3 20)"
    size="$(wc -c < "$log" 2>/dev/null | tr -d ' ')"
    case "$size" in ''|*[!0-9]*) return 0 ;; esac
    [[ "$size" -le $(( max_kb * 1024 )) ]] && return 0

    i="$keep"
    while [[ "$i" -gt 1 ]]; do
        [[ -f "${log}.$(( i - 1 ))" ]] && mv -f "${log}.$(( i - 1 ))" "${log}.$i"
        i=$(( i - 1 ))
    done
    mv -f "$log" "${log}.1"
}

# Append one redacted event:
#   event_append TYPE SEVERITY SOURCE SUBJECT SUMMARY [CORRELATION_ID]
event_append() {
    local type="$1" severity="$2" source="$3" subject="$4" summary="$5"
    local correlation="${6:-}" log
    log="$(_event_log_path)" || return 1
    _event_log_rotate "$log"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(iso_now)" \
        "$(_event_field "$type")" \
        "$(_event_field "$severity")" \
        "$(_event_field "$source")" \
        "$(_event_field "$subject")" \
        "$(_event_field "$summary")" \
        "$(_event_field "$correlation")" >> "$log" || return 1
    chmod 600 "$log" 2>/dev/null || true
}

# Read the current log followed by older rotations, newest records first.
event_read_recent() {
    local limit="${1:-100}" log file
    case "$limit" in ''|*[!0-9]*) return 2 ;; esac
    [[ "${#limit}" -le 6 ]] || return 2
    limit="$(( 10#$limit ))"
    [[ "$limit" -gt 0 && "$limit" -le 10000 ]] || return 2

    log="$(_event_log_path)" || return 1
    {
        [[ -f "$log" ]] && _event_reverse_file "$log" 2>/dev/null
        for file in "$log".1 "$log".2 "$log".3 "$log".4 "$log".5 \
                    "$log".6 "$log".7 "$log".8 "$log".9 "$log".10 \
                    "$log".11 "$log".12 "$log".13 "$log".14 "$log".15 \
                    "$log".16 "$log".17 "$log".18 "$log".19 "$log".20; do
            [[ -f "$file" ]] && _event_reverse_file "$file" 2>/dev/null
        done
    } | awk -v n="$limit" 'NR <= n'
}
