#!/bin/bash
# oh-my-safety - Check discovery & scan runner
#
# Checks are drop-in files under lib/checks/<category>/<name>.sh (plus user
# drop-ins). Each declares a manifest via header variables and a
# check_<name_with_underscores>() function returning:
#   0  = passed (no findings)
#   1  = findings present (severity in CHECK_RESULT_SEVERITY, else manifest)
#   77 = self-skipped (reason in CHECK_FINDING_SUMMARY)
# The manifest is the single source of truth read by BOTH this runner and the
# docs generator.

[[ -n "${_OMS_RUNNER_LOADED:-}" ]] && return 0
_OMS_RUNNER_LOADED=1

# Highest check-contract version this runner understands
OMS_CONTRACT_VERSION=2

# Accumulator for the current scan's result records (newline-joined)
OMS_SCAN_RESULTS=""
# Exact human-readable output for non-OK checks. These rows are persisted next
# to the summaries so status renderers can explain what was found without
# re-running checks.
OMS_SCAN_DETAILS=""

# Read a manifest variable's value from a check file (without sourcing it).
check_meta() {
    local file="$1" var="$2"
    sed -n "s/^${var}=\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$file" | head -1
}

# Emit "category<TAB>name<TAB>file" for every discoverable check.
checks_discover() {
    local dir cat f name p custom_dir

    for dir in "$OMS_ROOT"/lib/checks/*/; do
        [[ -d "$dir" ]] || continue
        cat="$(basename "$dir")"
        for f in "$dir"*.sh; do
            [[ -f "$f" ]] || continue
            name="$(basename "$f" .sh)"
            case "$name" in _*) continue ;; esac
            printf '%s\t%s\t%s\n' "$cat" "$name" "$f"
        done
    done

    custom_dir="${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety/checks"
    if [[ -d "$custom_dir" ]]; then
        for f in "$custom_dir"/*.sh; do
            [[ -f "$f" ]] || continue
            name="$(basename "$f" .sh)"
            case "$name" in _*) continue ;; esac
            printf '%s\t%s\t%s\n' "custom" "$name" "$f"
        done
    fi

    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        p="$(config_expand_path "$p")"
        [[ -d "$p" ]] || continue
        for f in "$p"/*.sh; do
            [[ -f "$f" ]] || continue
            name="$(basename "$f" .sh)"
            case "$name" in _*) continue ;; esac
            printf '%s\t%s\t%s\n' "custom" "$name" "$f"
        done
    done < <(config_get_list 'custom_check_paths')
}

# Order rows: privacy, security, other categories, then custom.
_order_categories() {
    awk -F'\t' '{
        r=2;
        if ($1=="privacy") r=0;
        else if ($1=="security") r=1;
        else if ($1=="custom") r=4;
        else r=3;
        print r"\t"$0;
    }' | sort -t"$(printf '\t')" -k1,1n -k2,2 -k3,3 | cut -f2-
}

_sanitize_field() { printf '%s' "$1" | tr '\t\n' '  '; }

_run_emit() {
    local rec
    rec="$(printf 'result\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$1" "$2" "$3" "$4" \
        "$(_sanitize_field "$5")" "$(_sanitize_field "${6:-}")" "$(_sanitize_field "${7:-}")")"
    if [[ -z "$OMS_SCAN_RESULTS" ]]; then
        OMS_SCAN_RESULTS="$rec"
    else
        OMS_SCAN_RESULTS="$OMS_SCAN_RESULTS
$rec"
    fi
}

# Convert captured check output into detail rows. ANSI terminal color sequences,
# tabs, and carriage returns are removed so the state remains safe TSV.
_run_emit_details() {
    local cat="$1" name="$2" file="$3" line clean rec
    [[ -f "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        clean="$(printf '%s' "$line" | sed $'s/\033\\[[0-9;]*m//g' | tr '\t\r' '  ')"
        [[ -z "${clean//[[:space:]]/}" ]] && continue
        rec="$(printf 'detail\t%s\t%s\t%s' "$cat" "$name" "$clean")"
        if [[ -z "$OMS_SCAN_DETAILS" ]]; then
            OMS_SCAN_DETAILS="$rec"
        else
            OMS_SCAN_DETAILS="$OMS_SCAN_DETAILS
$rec"
        fi
    done < "$file"
}

# Extract stable per-item finding IDs from the contract-v2 human detail stream.
# Checks that do not yet emit IDs fall back to their check name.
_finding_ids_from_file() {
    local file="$1" line trimmed id ids=""
    [[ -f "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
        case "$trimmed" in
            "✅ "*|"ℹ️  "*|"ℹ️ "*|"⏭️  "*|"⏭️ "*) continue ;;
        esac
        id="$(printf '%s' "$line" | sed -n 's/.*\[id: \([^]]*\)\].*/\1/p')"
        [[ -z "$id" ]] && continue
        if [[ -z "$ids" ]]; then ids="$id"; else ids="$ids
$id"; fi
    done < "$file"
    [[ -n "$ids" ]] && printf '%s\n' "$ids" | sort -u
}

_count_status() {
    printf '%s\n' "$OMS_SCAN_RESULTS" | awk -F'\t' -v s="$1" '$1=="result" && $4==s{c++} END{print c+0}'
}

_probe_fda() {
    if type oms_has_fda >/dev/null 2>&1 && oms_has_fda; then echo true; else echo false; fi
}

# Run a single discovered check, emitting its result and firing notifications.
run_one_check() {
    local cat="$1" name="$2" file="$3"
    local underscored func platforms severity desc contract requires_net remediation doc
    local managed_check=""
    underscored="${name//-/_}"
    func="check_${underscored}"

    platforms="$(check_meta "$file" CHECK_PLATFORMS)"
    severity="$(check_meta "$file" CHECK_SEVERITY)"; severity="${severity:-warn}"
    desc="$(check_meta "$file" CHECK_DESCRIPTION)"; desc="${desc:-$name}"
    contract="$(check_meta "$file" CHECK_CONTRACT)"
    requires_net="$(check_meta "$file" CHECK_REQUIRES_NETWORK)"
    remediation="$(check_meta "$file" CHECK_REMEDIATION)"
    doc="$(check_meta "$file" CHECK_DOC)"

    managed_check="$(config_get "managed.check.${name}" '')"

    # Whole-category toggle (e.g. `disable privacy`) then per-check toggle. A
    # signed managed policy can explicitly require a known check even when a
    # local category toggle is off, or explicitly disable that check.
    if [[ "$managed_check" == "false" ]]; then
        log_debug "Check disabled by verified organization policy: $cat/$name"
        _run_emit "$cat" "$name" "skip" "info" "disabled by verified organization policy" \
            "Ask the organization security operator to review the assigned policy." "$doc"
        _notify_resolve_missing "$name" </dev/null >/dev/null
        return 0
    fi
    if [[ "$managed_check" != "true" ]] &&
       ! config_enabled "categories.${cat}.enabled" "true"; then
        log_debug "Category disabled: $cat"
        _run_emit "$cat" "$name" "skip" "info" "disabled by configuration" \
            "Enable the $cat category to restore coverage." "$doc"
        _notify_resolve_missing "$name" </dev/null >/dev/null
        return 0
    fi
    if [[ "$managed_check" != "true" ]] &&
       ! config_enabled "checks.${cat}.${underscored}.enabled" "true"; then
        log_debug "Check disabled: $cat/$name"
        _run_emit "$cat" "$name" "skip" "info" "disabled by configuration" \
            "Enable $cat/$name to restore coverage." "$doc"
        _notify_resolve_missing "$name" </dev/null >/dev/null
        return 0
    fi

    if [[ -n "$platforms" && "$platforms" != "all" ]]; then
        case " $platforms " in
            *" ${OMS_PLATFORM:-} "*) : ;;
            *) _run_emit "$cat" "$name" "skip" "info" "not supported on ${OMS_PLATFORM:-unknown}" \
                "Run this check on a supported platform: $platforms." "$doc"; return 0 ;;
        esac
    fi

    if [[ -n "$contract" && "$contract" -gt "$OMS_CONTRACT_VERSION" ]]; then
        log_warn "Skipping $name: requires check contract v$contract (this build supports v$OMS_CONTRACT_VERSION)"
        _run_emit "$cat" "$name" "skip" "info" "requires newer check contract v$contract" \
            "Upgrade oh-my-safety, then recheck." "$doc"
        return 0
    fi

    if [[ "${OMS_OFFLINE:-false}" == "true" && "$requires_net" == "true" ]]; then
        _run_emit "$cat" "$name" "skip" "info" "skipped (offline mode)" \
            "Run a normal or deep scan without --offline." "$doc"
        return 0
    fi

    # Initialize optional manifest fields so a custom check that omits them
    # cannot inherit values left behind by the previously sourced check.
    CHECK_REMEDIATION="$remediation"
    CHECK_DOC="$doc"
    # shellcheck source=/dev/null
    source "$file"
    if ! type "$func" >/dev/null 2>&1; then
        log_error "Check $name defines no function $func()"
        _run_emit "$cat" "$name" "error" "critical" "missing function $func" "$remediation" "$doc"
        notify_finding "$name" "critical" "coverage:$name" \
            "oh-my-safety: check failed" "$name could not run: missing function $func"
        return 3
    fi

    CHECK_FINDING_SUMMARY=""
    CHECK_RESULT_SEVERITY=""
    remediation="${CHECK_REMEDIATION:-$remediation}"
    doc="${CHECK_DOC:-$doc}"
    local rc=0 detail_tmp=""
    detail_tmp="$(mktemp "${TMPDIR:-/tmp}/oh-my-safety-check.XXXXXX" 2>/dev/null)" || detail_tmp=""
    if [[ -n "$detail_tmp" && "${OMS_QUIET:-false}" == "true" ]]; then
        "$func" >"$detail_tmp" 2>/dev/null; rc=$?
    elif [[ -n "$detail_tmp" ]]; then
        echo ""
        echo -e "${BOLD}▸ ${desc}${NC}"
        "$func" >"$detail_tmp"; rc=$?
        cat "$detail_tmp"
    elif [[ "${OMS_QUIET:-false}" == "true" ]]; then
        "$func" >/dev/null 2>&1; rc=$?
    else
        echo ""
        echo -e "${BOLD}▸ ${desc}${NC}"
        "$func"; rc=$?
    fi

    local status eff_sev summary
    case $rc in
        0)  status="ok";   eff_sev="info"; summary="${CHECK_FINDING_SUMMARY:-OK}" ;;
        77) status="skip"; eff_sev="info"; summary="${CHECK_FINDING_SUMMARY:-skipped}" ;;
        1)  eff_sev="${CHECK_RESULT_SEVERITY:-$severity}"
            summary="${CHECK_FINDING_SUMMARY:-$desc}"
            if [[ "$eff_sev" == "critical" ]]; then status="critical"; else status="warn"; fi ;;
        *)  status="error"; eff_sev="critical"; summary="${CHECK_FINDING_SUMMARY:-check errored (rc=$rc)}" ;;
    esac

    # Whole-check mute: `oh-my-safety ignore <check>` (no finding-id) allowlists
    # the check's own name, silencing it without disabling it entirely. This makes
    # `ignore` meaningful even for checks that report a single whole-check finding.
    if [[ "$status" == "warn" || "$status" == "critical" ]] && allowlist_match "$name" "$name"; then
        status="skip"; eff_sev="info"; summary="muted by user"
    fi

    # Checks may refine remediation after observing why they warned or skipped.
    remediation="${CHECK_REMEDIATION:-$remediation}"
    doc="${CHECK_DOC:-$doc}"
    _run_emit "$cat" "$name" "$status" "$eff_sev" "$summary" "$remediation" "$doc"
    case "$status" in
        warn|critical|error|skip)
            [[ -n "$detail_tmp" ]] && _run_emit_details "$cat" "$name" "$detail_tmp" ;;
    esac
    local active_ids="" resolved_ids="" finding_id resolved_count console=true deliver=true
    if [[ "$status" == "warn" || "$status" == "critical" ]]; then
        active_ids="$(_finding_ids_from_file "$detail_tmp")"
        [[ -z "$active_ids" ]] && active_ids="$name"
        while IFS= read -r finding_id; do
            [[ -z "$finding_id" ]] && continue
            notify_finding "$name" "$eff_sev" "$finding_id" \
                "oh-my-safety: $name" "$summary" "$console" "$deliver"
            console=false
            [[ "${OMS_NOTIFICATION_SENT:-false}" == "true" ]] && deliver=false
        done <<EOF
$active_ids
EOF
        resolved_ids="$(printf '%s\n' "$active_ids" | _notify_resolve_missing "$name")"
    elif [[ "$status" == "ok" || "$status" == "skip" ]]; then
        resolved_ids="$(_notify_resolve_missing "$name" </dev/null)"
    elif [[ "$status" == "error" ]]; then
        notify_finding "$name" "critical" "coverage:$name" \
            "oh-my-safety: check failed" "$name could not complete: $summary"
    fi
    if [[ -n "$resolved_ids" ]]; then
        resolved_count="$(printf '%s\n' "$resolved_ids" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
        notify "oh-my-safety: resolved" "$name resolved ${resolved_count:-1} finding(s)" ""
        while IFS= read -r finding_id; do
            [[ -z "$finding_id" ]] && continue
            event_append "finding.resolved" "info" "${OMS_SCAN_SOURCE:-scan}" \
                "$name/$finding_id" "finding no longer observed" || true
        done <<EOF
$resolved_ids
EOF
    fi
    [[ -n "$detail_tmp" ]] && rm -f "$detail_tmp"

    return $rc
}

_scan_meta() {
    local file="$1" key="$2"
    awk -F'\t' -v k="$key" '$1=="meta" && $2==k {print $3; exit}' "$file" 2>/dev/null
}

_agent_core_path() {
    if [[ -n "${OMS_AGENT_CORE_BIN:-}" && -x "$OMS_AGENT_CORE_BIN" ]]; then
        printf '%s' "$OMS_AGENT_CORE_BIN"
    elif command -v oh-my-safety-agent >/dev/null 2>&1; then
        command -v oh-my-safety-agent
    elif [[ -x "$OMS_ROOT/bin/oh-my-safety-agent" ]]; then
        printf '%s' "$OMS_ROOT/bin/oh-my-safety-agent"
    fi
}

_journal_ingest_scan() {
    local scan_file="$1" agent db profile output
    config_enabled "journal.enabled" "true" || return 0
    agent="$(_agent_core_path)"
    [[ -n "$agent" ]] || return 0
    db="$(state_path 'journal.db')" || return 1
    profile="$(config_get 'profile.name' 'personal-balanced')"
    output="$("$agent" --state-db "$db" --profile "$profile" \
        --ingest-scan "$scan_file" 2>/dev/null)" || {
        event_append "journal.ingest_failed" "warn" "bridge" \
            "$(basename "$scan_file")" "portable journal rejected scan snapshot" || true
        log_warn "Portable journal ingestion failed; TSV posture remains authoritative"
        return 1
    }
    log_debug "Journal bridge: $output"
}

_results_exit_code() {
    local warn crit err exit_code=0
    warn="$(_count_status warn)"
    crit="$(_count_status critical)"
    err="$(_count_status error)"
    [[ "$warn" -gt 0 ]] && exit_code=1
    [[ "$crit" -gt 0 ]] && exit_code=2
    [[ "$err" -gt 0 ]] && exit_code=3
    printf '%s' "$exit_code"
}

_write_scan_file() {
    local exit_code="$1" dest="$2" scope="$3" timestamp="$4"
    local source="$5" updated_at="$6" fda="$7" public_ip="${8:-}"
    {
        printf 'schema\t1\n'
        printf 'meta\ttimestamp\t%s\n' "$timestamp"
        printf 'meta\tupdated_at\t%s\n' "$updated_at"
        printf 'meta\tversion\t%s\n' "$OMS_VERSION"
        printf 'meta\tplatform\t%s\n' "${OMS_PLATFORM:-unknown}"
        printf 'meta\tsource\t%s\n' "$source"
        printf 'meta\tscope\t%s\n' "$scope"
        printf 'meta\texit\t%s\n' "$exit_code"
        printf 'meta\tfda\t%s\n' "$fda"
        [[ -n "$public_ip" ]] && printf 'meta\tpublic_ip\t%s\n' "$public_ip"
        [[ -n "$OMS_SCAN_RESULTS" ]] && printf '%s\n' "$OMS_SCAN_RESULTS"
        [[ -n "$OMS_SCAN_DETAILS" ]] && printf '%s\n' "$OMS_SCAN_DETAILS"
        # Keep the producer side successful under `set -o pipefail` when the
        # optional final details section is empty.
        true
    } | _state_write_atomic "$dest"
}

# Persist a filtered scan without throwing away the checks it did not run.
# `last-partial-scan.tsv` records exactly what the command just evaluated. When
# a complete snapshot already exists, matching rows are also merged into it.
# Manual filtered scans retain complete-scan freshness; scheduled composites
# advance freshness because every retained row is still within its cadence.
_persist_scan_results() {
    local exit_code="$1" partial_mode="$2" now source fda ip
    local full_dest partial_dest
    now="$(iso_now)"
    source="${OMS_SCAN_SOURCE:-scan}"
    fda="$(_probe_fda)"
    ip="${OMS_PUBLIC_IP:-}"
    full_dest="$(state_path 'last-scan.tsv')"

    if [[ "$partial_mode" == "false" ]]; then
        _write_scan_file "$exit_code" "$full_dest" "full" "$now" "$source" "$now" "$fda" "$ip" || return $?
        _journal_ingest_scan "$full_dest" || true
        return 0
    fi

    partial_dest="$(state_path 'last-partial-scan.tsv')"
    _write_scan_file "$exit_code" "$partial_dest" "partial" "$now" "$source" "$now" "$fda" "$ip" || return 1
    if [[ ! -f "$full_dest" ]]; then
        _journal_ingest_scan "$partial_dest" || true
        return 0
    fi

    local current_results current_details merged old_timestamp old_source old_fda old_ip merged_exit
    current_results="$OMS_SCAN_RESULTS"
    current_details="$OMS_SCAN_DETAILS"
    merged="$(awk -F'\t' '
        FNR==NR {
            if ($1=="result" || $1=="detail") {
                key=$2 SUBSEP $3
                replace[key]=1
                fresh[++fresh_count]=$0
            }
            next
        }
        ($1=="result" || $1=="detail") {
            key=$2 SUBSEP $3
            if (!replace[key]) print
        }
        END {
            for (i=1; i<=fresh_count; i++) print fresh[i]
        }
    ' "$partial_dest" "$full_dest")"
    if [[ "$partial_mode" == "scheduled" ]]; then
        # Reconciliation also removes results for checks that no longer exist
        # after an upgrade or custom-check removal. Otherwise a partial cadence
        # scheduler could preserve an obsolete warning forever.
        merged="$(awk -F'\t' '
            FNR==NR { known[$1 SUBSEP $2]=1; next }
            ($1=="result" || $1=="detail") && known[$2 SUBSEP $3] { print }
        ' <(checks_discover | _order_categories) <(printf '%s\n' "$merged"))"
    fi
    OMS_SCAN_RESULTS="$(printf '%s\n' "$merged" | awk -F'\t' '$1=="result"')"
    OMS_SCAN_DETAILS="$(printf '%s\n' "$merged" | awk -F'\t' '$1=="detail"')"
    merged_exit="$(_results_exit_code)"

    old_timestamp="$(_scan_meta "$full_dest" timestamp)"
    old_source="$(_scan_meta "$full_dest" source)"
    old_fda="$(_scan_meta "$full_dest" fda)"
    old_ip="$(_scan_meta "$full_dest" public_ip)"
    [[ -z "$old_timestamp" ]] && old_timestamp="$now"
    [[ -z "$old_source" ]] && old_source="$source"
    # A scheduled composite is the daemon's authoritative current posture:
    # retained rows are still within their declared cadence. A user-requested
    # filtered recheck is not equivalent to a whole-device refresh, so only
    # that mode preserves the complete-scan freshness timestamp.
    if [[ "$partial_mode" == "scheduled" ]]; then
        old_timestamp="$now"
        old_source="$source"
    fi
    [[ -z "$old_fda" ]] && old_fda="$fda"
    [[ -z "$old_ip" ]] && old_ip="$ip"

    _write_scan_file "$merged_exit" "$full_dest" "composite" \
        "$old_timestamp" "$old_source" "$now" "$old_fda" "$old_ip"
    local write_rc=$?
    OMS_SCAN_RESULTS="$current_results"
    OMS_SCAN_DETAILS="$current_details"
    [[ "$write_rc" -eq 0 ]] && _journal_ingest_scan "$partial_dest" || true
    return $write_rc
}

_log_rotate() {
    local log="$1" max keep size i
    max="$(config_get 'logging.max_size_kb' '1024')"
    keep="$(config_get 'logging.keep_rotations' '3')"
    case "$max" in ''|*[!0-9]*|0) max=1024 ;; esac
    case "$keep" in ''|*[!0-9]*|0) keep=3 ;; esac
    [[ "${#max}" -le 9 ]] || max=1024
    [[ "${#keep}" -le 2 ]] || keep=3
    max="$(( 10#$max ))"
    keep="$(( 10#$keep ))"
    [[ "$max" -le 1048576 ]] || max=1024
    [[ "$keep" -le 20 ]] || keep=3
    [[ -f "$log" ]] || return 0
    size="$(wc -c < "$log" 2>/dev/null | tr -d ' ')"
    [[ -z "$size" ]] && return 0
    if [[ "$size" -gt $(( max * 1024 )) ]]; then
        i="$keep"
        while [[ "$i" -gt 1 ]]; do
            [[ -f "${log}.$(( i - 1 ))" ]] && mv -f "${log}.$(( i - 1 ))" "${log}.$i"
            i=$(( i - 1 ))
        done
        mv -f "$log" "${log}.1"
    fi
}

_append_scan_log() {
    local log ts correlation kind cat name status severity summary remediation doc event_type overall
    log="$(state_path 'log/scan.log')"
    _log_rotate "$log"
    ts="$(iso_now)"
    printf '%s\n' "$OMS_SCAN_RESULTS" | awk -F'\t' -v ts="$ts" '
        $1=="result" && $4!="ok" && $4!="skip" {
            printf "%s\t%s\t%s/%s\t%s\n", ts, $4, $2, $3, $6
        }' >> "$log" 2>/dev/null || true

    correlation="${ts}:$$"
    while IFS=$'\t' read -r kind cat name status severity summary remediation doc; do
        [[ "$kind" == "result" ]] || continue
        case "$status" in
            warn|critical|error) event_type="finding.observed" ;;
            ok) event_type="check.passed" ;;
            skip) event_type="check.skipped" ;;
            *) event_type="check.result" ;;
        esac
        event_append "$event_type" "$severity" "${OMS_SCAN_SOURCE:-scan}" \
            "$cat/$name" "$summary" "$correlation" || true
    done <<EOF
$OMS_SCAN_RESULTS
EOF
    overall="$(_results_exit_code)"
    if [[ "$overall" -ge 2 ]]; then
        overall="critical"
    elif [[ "$overall" -eq 1 ]]; then
        overall="warn"
    else
        overall="info"
    fi
    event_append "scan.completed" "$overall" \
        "${OMS_SCAN_SOURCE:-scan}" "${OMS_PLATFORM:-unknown}" \
        "$(_count_status ok) ok, $(_count_status warn) warn, $(_count_status critical) critical, $(_count_status skip) skipped, $(_count_status error) error" \
        "$correlation" || true
}

_check_interval_seconds() {
    local file="$1" name="${2:-}" configured fallback managed_interval managed_check
    configured="$(check_meta "$file" CHECK_INTERVAL)"
    fallback="$(config_get 'monitoring.interval' '300')"
    case "$fallback" in ''|*[!0-9]*|0) fallback=300 ;; esac
    [[ "${#fallback}" -le 9 ]] || fallback=300
    fallback="$(( 10#$fallback ))"
    [[ "$fallback" -gt 0 ]] || fallback=300
    case "$configured" in
        '') configured="$fallback" ;;
        *[!0-9]*|0)
            log_warn "Invalid CHECK_INTERVAL in $file; using ${fallback}s"
            configured="$fallback" ;;
    esac
    if [[ "${#configured}" -gt 9 ]]; then
        log_warn "Invalid CHECK_INTERVAL in $file; using ${fallback}s"
        configured="$fallback"
    else
        configured="$(( 10#$configured ))"
        [[ "$configured" -gt 0 ]] || configured="$fallback"
    fi
    if [[ -n "$name" ]]; then
        managed_check="$(config_get "managed.check.${name}" '')"
        managed_interval="$(config_get 'organization.policy.scan_interval_seconds' '')"
        if [[ "$managed_check" == "true" ]]; then
            case "$managed_interval" in ''|*[!0-9]*|0) managed_interval="" ;; esac
            if [[ -n "$managed_interval" && "${#managed_interval}" -le 9 ]]; then
                managed_interval="$(( 10#$managed_interval ))"
                # A signed policy is a maximum interval for checks it requires;
                # a locally stricter manifest remains stricter.
                [[ "$configured" -le "$managed_interval" ]] ||
                    configured="$managed_interval"
            fi
        fi
    fi
    printf '%s' "$configured"
}

_check_is_due() {
    local cat="$1" name="$2" file="$3" now="$4" last interval
    last="$(schedule_last_epoch "$cat" "$name")"
    [[ -z "$last" ]] && return 0
    interval="$(_check_interval_seconds "$file" "$name")"
    [[ "$now" -lt "$last" ]] && return 0
    [[ $(( now - last )) -ge "$interval" ]]
}

# Internal implementation. The public run_scan wrapper below owns the global
# lock, ensuring manual scans and the monitoring daemon cannot overlap.
_run_scan_locked() {
    local only_check="" only_cat="" scheduled=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check) only_check="$2"; shift 2 ;;
            --category) only_cat="$2"; shift 2 ;;
            --offline) OMS_OFFLINE=true; export OMS_OFFLINE; shift ;;
            --deep) OMS_DEEP=true; export OMS_DEEP; shift ;;
            --scheduled) scheduled=true; shift ;;
            *) shift ;;
        esac
    done

    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""

    [[ "${OMS_QUIET:-false}" == "true" ]] || print_header "oh-my-safety scan - $(iso_now)"

    local cat name file now selected=0 partial_mode=false full_dest ran_checks=""
    now="$(date +%s)"
    full_dest="$(state_path 'last-scan.tsv')"
    [[ -n "$only_check" || -n "$only_cat" ]] && partial_mode=true
    [[ "$scheduled" == "true" && -f "$full_dest" ]] && partial_mode=scheduled

    while IFS=$'\t' read -r cat name file; do
        [[ -z "$name" ]] && continue
        [[ -n "$only_cat" && "$cat" != "$only_cat" ]] && continue
        [[ -n "$only_check" && "$name" != "$only_check" ]] && continue
        if [[ "$scheduled" == "true" && -f "$full_dest" ]] && ! _check_is_due "$cat" "$name" "$file" "$now"; then
            continue
        fi
        selected=$(( selected + 1 ))
        run_one_check "$cat" "$name" "$file" || true
        if [[ -z "$ran_checks" ]]; then ran_checks="$cat	$name"; else ran_checks="$ran_checks
$cat	$name"; fi
    done < <(checks_discover | _order_categories)

    # A scheduler tick with nothing due is normal and must not replace posture
    # or be presented as a failed/all-clear scan.
    if [[ "$scheduled" == "true" && "$selected" -eq 0 ]]; then
        log_debug "No checks due on this scheduler tick"
        return 0
    fi

    # Safety guard: a scan that produced no results means check discovery failed
    # (broken install, wrong OMS_ROOT, a clobbered tree). Never let that look like
    # an all-clear — record an error so status and notifications surface it.
    if [[ -z "$OMS_SCAN_RESULTS" ]]; then
        log_error "No checks ran — refusing to record an all-clear."
        _run_emit "runner" "self-check" "error" "critical" "no checks ran (discovery produced nothing)"
        notify_finding "self-check" "critical" "coverage:self-check" \
            "oh-my-safety: scan failed" "No checks ran; installation or discovery is broken"
    fi

    local ok warn crit skip err exit_code
    ok="$(_count_status ok)"; warn="$(_count_status warn)"
    crit="$(_count_status critical)"; skip="$(_count_status skip)"
    err="$(_count_status error)"
    exit_code="$(_results_exit_code)"

    if _persist_scan_results "$exit_code" "$partial_mode"; then
        while IFS=$'\t' read -r cat name; do
            [[ -z "$name" ]] && continue
            schedule_record_epoch "$cat" "$name" "$now" || \
                log_warn "Could not record schedule state for $cat/$name"
        done <<EOF
$ran_checks
EOF
    else
        log_error "Could not persist scan results; refusing to advance check schedules"
        exit_code=3
    fi
    _append_scan_log

    if [[ "${OMS_QUIET:-false}" != "true" ]]; then
        echo ""
        print_header "Summary"
        printf '  %s ok · %s warn · %s critical · %s skipped · %s error\n' "$ok" "$warn" "$crit" "$skip" "$err"
        echo ""
        if [[ "$exit_code" -eq 0 ]]; then
            print_check_result pass "All checks passed."
        elif [[ "$exit_code" -ge 2 ]]; then
            print_check_result critical "$crit critical / $err error finding(s) — review above."
        else
            print_check_result warn "$warn warning(s) — review above."
        fi
        print_separator
    fi

    return "$exit_code"
}

# Run a full, filtered, or scheduled scan. Returns
# 0=ok / 1=warn / 2=critical / 3=error-or-busy.
run_scan() {
    if ! scan_lock_acquire; then
        if [[ "${OMS_SCAN_SOURCE:-scan}" == "agent" ]]; then
            log_debug "A scan is already running; scheduler tick skipped"
        else
            log_warn "A scan is already running; request not started"
        fi
        return 3
    fi

    _run_scan_locked "$@"
    local rc=$?
    scan_lock_release || log_warn "Could not release scan lock cleanly"
    return $rc
}
# Human or JSON listing of the check catalog (JSON drives the docs generator).
checks_list() {
    if [[ "${1:-}" == "--json" ]]; then
        _checks_json
        return 0
    fi
    local cat name file desc severity state
    printf '%-4s %-10s %-20s %-9s %s\n' "ON?" "CATEGORY" "CHECK" "SEVERITY" "DESCRIPTION"
    while IFS=$'\t' read -r cat name file; do
        [[ -z "$name" ]] && continue
        desc="$(check_meta "$file" CHECK_DESCRIPTION)"
        severity="$(check_meta "$file" CHECK_SEVERITY)"; severity="${severity:-warn}"
        if config_enabled "categories.${cat}.enabled" "true" && config_enabled "checks.${cat}.${name//-/_}.enabled" "true"; then
            state="on"
        else
            state="off"
        fi
        printf '%-4s %-10s %-20s %-9s %s\n' "$state" "$cat" "$name" "$severity" "$desc"
    done < <(checks_discover | _order_categories)
}

_checks_json() {
    local first=1 cat name file
    printf '['
    while IFS=$'\t' read -r cat name file; do
        [[ -z "$name" ]] && continue
        if [[ $first -eq 1 ]]; then first=0; else printf ','; fi
        printf '{"category":"%s","name":"%s","description":"%s","severity":"%s","platforms":"%s","interval":"%s","contract":"%s","doc":"%s","remediation":"%s"}' \
            "$(json_escape "$cat")" \
            "$(json_escape "$name")" \
            "$(json_escape "$(check_meta "$file" CHECK_DESCRIPTION)")" \
            "$(json_escape "$(check_meta "$file" CHECK_SEVERITY)")" \
            "$(json_escape "$(check_meta "$file" CHECK_PLATFORMS)")" \
            "$(json_escape "$(check_meta "$file" CHECK_INTERVAL)")" \
            "$(json_escape "$(check_meta "$file" CHECK_CONTRACT)")" \
            "$(json_escape "$(check_meta "$file" CHECK_DOC)")" \
            "$(json_escape "$(check_meta "$file" CHECK_REMEDIATION)")"
    done < <(checks_discover | _order_categories)
    printf ']\n'
}
