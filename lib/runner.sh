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
    rec="$(printf 'result\t%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$(_sanitize_field "$5")")"
    if [[ -z "$OMS_SCAN_RESULTS" ]]; then
        OMS_SCAN_RESULTS="$rec"
    else
        OMS_SCAN_RESULTS="$OMS_SCAN_RESULTS
$rec"
    fi
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
    local underscored func platforms severity desc contract requires_net
    underscored="${name//-/_}"
    func="check_${underscored}"

    platforms="$(check_meta "$file" CHECK_PLATFORMS)"
    severity="$(check_meta "$file" CHECK_SEVERITY)"; severity="${severity:-warn}"
    desc="$(check_meta "$file" CHECK_DESCRIPTION)"; desc="${desc:-$name}"
    contract="$(check_meta "$file" CHECK_CONTRACT)"
    requires_net="$(check_meta "$file" CHECK_REQUIRES_NETWORK)"

    # Whole-category toggle (e.g. `disable privacy`) then per-check toggle.
    if ! config_enabled "categories.${cat}.enabled" "true"; then
        log_debug "Category disabled: $cat"
        return 0
    fi
    if ! config_enabled "checks.${cat}.${underscored}.enabled" "true"; then
        log_debug "Check disabled: $cat/$name"
        return 0
    fi

    if [[ -n "$platforms" && "$platforms" != "all" ]]; then
        case " $platforms " in
            *" ${OMS_PLATFORM:-} "*) : ;;
            *) _run_emit "$cat" "$name" "skip" "info" "not supported on ${OMS_PLATFORM:-unknown}"; return 0 ;;
        esac
    fi

    if [[ -n "$contract" && "$contract" -gt "$OMS_CONTRACT_VERSION" ]]; then
        log_warn "Skipping $name: requires check contract v$contract (this build supports v$OMS_CONTRACT_VERSION)"
        _run_emit "$cat" "$name" "skip" "info" "requires newer check contract v$contract"
        return 0
    fi

    if [[ "${OMS_OFFLINE:-false}" == "true" && "$requires_net" == "true" ]]; then
        _run_emit "$cat" "$name" "skip" "info" "skipped (offline mode)"
        return 0
    fi

    # shellcheck source=/dev/null
    source "$file"
    if ! type "$func" >/dev/null 2>&1; then
        log_error "Check $name defines no function $func()"
        _run_emit "$cat" "$name" "error" "critical" "missing function $func"
        return 3
    fi

    CHECK_FINDING_SUMMARY=""
    CHECK_RESULT_SEVERITY=""
    local rc=0
    if [[ "${OMS_QUIET:-false}" == "true" ]]; then
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

    _run_emit "$cat" "$name" "$status" "$eff_sev" "$summary"

    if [[ "$status" == "warn" || "$status" == "critical" ]]; then
        notify_finding "$name" "$eff_sev" "$name" "oh-my-safety: $name" "$summary"
    fi

    return $rc
}

_write_last_scan() {
    local exit_code="$1" dest
    dest="$(state_path 'last-scan.tsv')"
    {
        printf 'schema\t1\n'
        printf 'meta\ttimestamp\t%s\n' "$(iso_now)"
        printf 'meta\tversion\t%s\n' "$OMS_VERSION"
        printf 'meta\tplatform\t%s\n' "${OMS_PLATFORM:-unknown}"
        printf 'meta\tsource\t%s\n' "${OMS_SCAN_SOURCE:-scan}"
        printf 'meta\texit\t%s\n' "$exit_code"
        printf 'meta\tfda\t%s\n' "$(_probe_fda)"
        [[ -n "${OMS_PUBLIC_IP:-}" ]] && printf 'meta\tpublic_ip\t%s\n' "$OMS_PUBLIC_IP"
        [[ -n "$OMS_SCAN_RESULTS" ]] && printf '%s\n' "$OMS_SCAN_RESULTS"
    } | _state_write_atomic "$dest"
}

_log_rotate() {
    local log="$1" max keep size i
    max="$(config_get 'logging.max_size_kb' '1024')"
    keep="$(config_get 'logging.keep_rotations' '3')"
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
    local log ts
    log="$(state_path 'log/scan.log')"
    _log_rotate "$log"
    ts="$(iso_now)"
    printf '%s\n' "$OMS_SCAN_RESULTS" | awk -F'\t' -v ts="$ts" '
        $1=="result" && $4!="ok" && $4!="skip" {
            printf "%s\t%s\t%s/%s\t%s\n", ts, $4, $2, $3, $6
        }' >> "$log" 2>/dev/null || true
}

# Run a full (or filtered) scan. Writes last-scan.tsv, appends the log, and
# returns 0=ok / 1=warn / 2=critical / 3=error.
run_scan() {
    local only_check="" only_cat=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check) only_check="$2"; shift 2 ;;
            --category) only_cat="$2"; shift 2 ;;
            --offline) OMS_OFFLINE=true; export OMS_OFFLINE; shift ;;
            --deep) OMS_DEEP=true; export OMS_DEEP; shift ;;
            *) shift ;;
        esac
    done

    OMS_SCAN_RESULTS=""

    [[ "${OMS_QUIET:-false}" == "true" ]] || print_header "oh-my-safety scan - $(iso_now)"

    local cat name file
    while IFS=$'\t' read -r cat name file; do
        [[ -z "$name" ]] && continue
        [[ -n "$only_cat" && "$cat" != "$only_cat" ]] && continue
        [[ -n "$only_check" && "$name" != "$only_check" ]] && continue
        run_one_check "$cat" "$name" "$file" || true
    done < <(checks_discover | _order_categories)

    local ok warn crit skip err exit_code
    ok="$(_count_status ok)"; warn="$(_count_status warn)"
    crit="$(_count_status critical)"; skip="$(_count_status skip)"
    err="$(_count_status error)"
    exit_code=0
    [[ "$warn" -gt 0 ]] && exit_code=1
    [[ "$crit" -gt 0 ]] && exit_code=2
    [[ "$err" -gt 0 ]] && exit_code=3

    _write_last_scan "$exit_code"
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

    return $exit_code
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
        printf '{"category":"%s","name":"%s","description":"%s","severity":"%s","platforms":"%s","interval":"%s","contract":"%s","doc":"%s"}' \
            "$(json_escape "$cat")" \
            "$(json_escape "$name")" \
            "$(json_escape "$(check_meta "$file" CHECK_DESCRIPTION)")" \
            "$(json_escape "$(check_meta "$file" CHECK_SEVERITY)")" \
            "$(json_escape "$(check_meta "$file" CHECK_PLATFORMS)")" \
            "$(json_escape "$(check_meta "$file" CHECK_INTERVAL)")" \
            "$(json_escape "$(check_meta "$file" CHECK_CONTRACT)")" \
            "$(json_escape "$(check_meta "$file" CHECK_DOC)")"
    done < <(checks_discover | _order_categories)
    printf ']\n'
}
