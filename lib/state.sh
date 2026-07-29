#!/bin/bash
# oh-my-safety - State & baseline layer
#
# All persistent state lives locally under an XDG state dir (never remote).
# Baselines let checks diff current system state against an approved snapshot.
# Notification bookkeeping dedupes alerts so a monitoring daemon doesn't spam.
#
# File formats are line-oriented TSV for bash-friendliness. All writes are
# atomic (temp file + mv). The state dir is created mode 700; files 600.

[[ -n "${_OMS_STATE_LOADED:-}" ]] && return 0
_OMS_STATE_LOADED=1

# Resolve the state directory (creating it lazily, restricted to the user).
OMS_STATE_DIR="${OMS_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/oh-my-safety}"

state_dir() {
    if [[ ! -d "$OMS_STATE_DIR" ]]; then
        mkdir -p "$OMS_STATE_DIR" 2>/dev/null || return 1
        chmod 700 "$OMS_STATE_DIR" 2>/dev/null || true
    fi
    printf '%s' "$OMS_STATE_DIR"
}

# Echo an absolute path under the state dir, ensuring its parent exists.
state_path() {
    local rel="$1"
    local base
    base="$(state_dir)" || return 1
    local full="$base/$rel"
    local parent
    parent="$(dirname "$full")"
    [[ -d "$parent" ]] || { mkdir -p "$parent" 2>/dev/null && chmod 700 "$parent" 2>/dev/null; }
    printf '%s' "$full"
}

# Atomically write stdin to a state-relative path with restrictive perms.
_state_write_atomic() {
    local dest="$1"
    local tmp="${dest}.tmp.$$"
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$dest"
}

# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------

_baseline_file()  { state_path "baselines/$1.tsv"; }
_pending_file()   { state_path "pending/$1.tsv"; }

baseline_exists() { [[ -f "$(_baseline_file "$1")" ]]; }

# Save stdin as the baseline for a check (sorted, de-duplicated, with header).
baseline_save() {
    local check="$1"
    local dest content
    dest="$(_baseline_file "$check")"
    content="$(sort -u)"
    {
        printf '# oh-my-safety baseline v1\n'
        printf '# check: %s\n' "$check"
        printf '# created: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '%s\n' "$content"
    } | _state_write_atomic "$dest"
}

# Emit baseline entries (comment/header lines stripped) on stdout.
baseline_load() {
    local f
    f="$(_baseline_file "$1")"
    [[ -f "$f" ]] || return 0
    grep -v '^#' "$f" | grep -v '^[[:space:]]*$' || true
}

# Compare a current snapshot (stdin) against the baseline.
# Prints "+line" for additions and "-line" for removals.
# Returns 0 when there is no drift, 1 when there is.
baseline_diff() {
    local check="$1"
    local cur_sorted base_sorted added removed
    cur_sorted="$(sort -u)"
    base_sorted="$(baseline_load "$check" | sort -u)"

    added="$(comm -13 <(printf '%s\n' "$base_sorted") <(printf '%s\n' "$cur_sorted") | sed '/^[[:space:]]*$/d')"
    removed="$(comm -23 <(printf '%s\n' "$base_sorted") <(printf '%s\n' "$cur_sorted") | sed '/^[[:space:]]*$/d')"

    local drift=0
    if [[ -n "$added" ]]; then
        printf '%s\n' "$added" | sed 's/^/+/'
        drift=1
    fi
    if [[ -n "$removed" ]]; then
        printf '%s\n' "$removed" | sed 's/^/-/'
        drift=1
    fi
    return $drift
}

# Stage a current snapshot as "pending" (awaiting user approval).
baseline_stage_pending() {
    _state_write_atomic "$(_pending_file "$1")"
}

# Promote a pending snapshot to be the new baseline.
baseline_approve() {
    local check="$1"
    local pending baseline
    pending="$(_pending_file "$check")"
    baseline="$(_baseline_file "$check")"
    if [[ ! -f "$pending" ]]; then
        log_error "No pending changes to approve for: $check"
        return 1
    fi
    mv -f "$pending" "$baseline"
    log_info "Baseline updated for: $check"
}

baseline_reset() {
    local check="$1"
    rm -f "$(_baseline_file "$check")" "$(_pending_file "$check")"
}

# List all baselines with entry counts.
baseline_list() {
    local dir f name count pending
    dir="$OMS_STATE_DIR/baselines"
    [[ -d "$dir" ]] || { echo "No baselines recorded yet."; return 0; }
    for f in "$dir"/*.tsv; do
        [[ -f "$f" ]] || continue
        name="$(basename "$f" .tsv)"
        count="$(grep -vc '^#' "$f" 2>/dev/null || echo 0)"
        pending=""
        [[ -f "$(_pending_file "$name")" ]] && pending="  (pending changes)"
        printf '  %-24s %s entries%s\n' "$name" "$count" "$pending"
    done
}

# ---------------------------------------------------------------------------
# Notification dedupe
# ---------------------------------------------------------------------------
# Per-check TSV rows: finding_id \t severity \t last_epoch

_notified_file() { state_path "notified/$1.tsv"; }

# Echo the last-notified epoch for a finding, or empty.
_notify_last_epoch() {
    local check="$1" id="$2" f line
    f="$(_notified_file "$check")"
    [[ -f "$f" ]] || return 0
    line="$(grep -F "$(printf '%s\t' "$id")" "$f" 2>/dev/null | head -1 || true)"
    [[ -z "$line" ]] && return 0
    printf '%s' "$line" | awk -F'\t' '{print $3}'
}

# Echo the last-notified severity for a finding, or empty.
_notify_last_severity() {
    local check="$1" id="$2" f line
    f="$(_notified_file "$check")"
    [[ -f "$f" ]] || return 0
    line="$(grep -F "$(printf '%s\t' "$id")" "$f" 2>/dev/null | head -1 || true)"
    [[ -z "$line" ]] && return 0
    printf '%s' "$line" | awk -F'\t' '{print $2}'
}

# Record (or refresh) a notification for a finding at the current time.
_notify_record() {
    local check="$1" id="$2" sev="$3" now="$4"
    local f tmp
    f="$(_notified_file "$check")"
    tmp="${f}.tmp.$$"
    if [[ -f "$f" ]]; then
        grep -vF "$(printf '%s\t' "$id")" "$f" 2>/dev/null > "$tmp" || true
    else
        : > "$tmp"
    fi
    printf '%s\t%s\t%s\n' "$id" "$sev" "$now" >> "$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$f"
}

# Remove notification state for findings that are no longer active. Active IDs
# are read from stdin, one per line. Resolved IDs are printed so the caller can
# surface a single, useful recovery notification.
_notify_resolve_missing() {
    local check="$1" f tmp active resolved id sev epoch found candidate
    f="$(_notified_file "$check")"
    [[ -f "$f" ]] || { cat >/dev/null; return 0; }

    active="$(cat)"
    tmp="${f}.tmp.$$"
    resolved=""
    : > "$tmp"

    while IFS=$'\t' read -r id sev epoch; do
        [[ -z "$id" ]] && continue
        found=false
        while IFS= read -r candidate; do
            [[ "$candidate" == "$id" ]] && { found=true; break; }
        done <<EOF
$active
EOF
        if [[ "$found" == "true" ]]; then
            printf '%s\t%s\t%s\n' "$id" "$sev" "$epoch" >> "$tmp"
        else
            if [[ -z "$resolved" ]]; then resolved="$id"; else resolved="$resolved
$id"; fi
        fi
    done < "$f"

    if [[ -s "$tmp" ]]; then
        chmod 600 "$tmp" 2>/dev/null || true
        mv -f "$tmp" "$f"
    else
        rm -f "$tmp" "$f"
    fi
    [[ -n "$resolved" ]] && printf '%s\n' "$resolved"
}

# ---------------------------------------------------------------------------
# Scan scheduling and global non-overlap
# ---------------------------------------------------------------------------

_schedule_file() {
    local category="$1" check="$2"
    state_path "schedule/${category}--${check}.epoch"
}

schedule_last_epoch() {
    local f value
    f="$(_schedule_file "$1" "$2")"
    [[ -f "$f" ]] || return 0
    IFS= read -r value < "$f" || true
    case "$value" in ''|*[!0-9]*) return 0 ;; esac
    printf '%s' "$value"
}

schedule_record_epoch() {
    local category="$1" check="$2" epoch="$3"
    case "$epoch" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$epoch" | _state_write_atomic "$(_schedule_file "$category" "$check")"
}

_scan_lock_dir() { state_path "locks/scan.lock"; }

_scan_lock_mtime() {
    local path="$1" value
    value="$(stat -f '%m' "$path" 2>/dev/null)" || value=""
    if [[ -z "$value" ]]; then
        value="$(stat -c '%Y' "$path" 2>/dev/null)" || value=""
    fi
    case "$value" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s' "$value"
}

# Acquire one process-wide scan lock. mkdir is atomic on both macOS and Linux.
# A lock whose owner PID no longer exists is reclaimed once.
scan_lock_acquire() {
    local lock owner attempt=0 mtime now
    lock="$(_scan_lock_dir)"
    while [[ "$attempt" -lt 2 ]]; do
        if mkdir "$lock" 2>/dev/null; then
            printf '%s\n' "$$" | _state_write_atomic "$lock/pid" || {
                rmdir "$lock" 2>/dev/null || true
                return 1
            }
            OMS_SCAN_LOCK_DIR="$lock"
            export OMS_SCAN_LOCK_DIR
            return 0
        fi

        owner=""
        [[ -f "$lock/pid" ]] && IFS= read -r owner < "$lock/pid" || true
        case "$owner" in
            ''|*[!0-9]*)
                # Another process may be between mkdir and writing its owner.
                # Treat a young ownerless lock as busy, but recover an orphan
                # after a conservative grace period.
                mtime="$(_scan_lock_mtime "$lock")" || return 1
                now="$(date +%s)"
                [[ $(( now - mtime )) -lt 30 ]] && return 1
                rm -f "$lock/pid"
                rmdir "$lock" 2>/dev/null || return 1
                attempt=$(( attempt + 1 ))
                continue ;;
        esac
        if kill -0 "$owner" 2>/dev/null; then
            return 1
        fi

        # Reclaim only the two known lock artifacts and only after confirming
        # that the recorded process is gone.
        rm -f "$lock/pid"
        rmdir "$lock" 2>/dev/null || return 1
        attempt=$(( attempt + 1 ))
    done
    return 1
}

scan_lock_release() {
    local lock owner=""
    lock="${OMS_SCAN_LOCK_DIR:-$(_scan_lock_dir)}"
    [[ -d "$lock" ]] || return 0
    [[ -f "$lock/pid" ]] && IFS= read -r owner < "$lock/pid" || true
    [[ "$owner" == "$$" ]] || return 1
    rm -f "$lock/pid"
    rmdir "$lock" 2>/dev/null || return 1
    OMS_SCAN_LOCK_DIR=""
    export OMS_SCAN_LOCK_DIR
}
