#!/bin/bash
# oh-my-safety - `status` subcommand
# Reads the last scan result from local state and renders it. Makes NO network
# calls and runs NO checks — it is a pure consumer of last-scan.tsv, so menu
# bar plugins and scripts can poll it cheaply.

_status_meta() { awk -F'\t' -v k="$2" '$1=="meta" && $2==k {print $3; exit}' "$1"; }

_scan_age() {
    local ts="$1" epoch now
    [[ -z "$ts" ]] && { echo -1; return; }
    epoch="$(TZ=UTC date -j -f '%Y-%m-%dT%H:%M:%SZ' "$ts" +%s 2>/dev/null)"
    now="$(date +%s)"
    [[ -z "$epoch" ]] && { echo -1; return; }
    echo $(( now - epoch ))
}

_agent_running() { launchctl list 2>/dev/null | grep -q 'oh-my-safety'; }
_agent_manager() {
    if launchctl list 2>/dev/null | grep -q 'homebrew.mxcl.oh-my-safety'; then echo brew
    elif launchctl list 2>/dev/null | grep -q 'com.vardominator.oh-my-safety'; then echo manual
    else echo none; fi
}

_count_result() { awk -F'\t' -v s="$1" '$1=="result" && $4==s{c++} END{print c+0}' "$2"; }

cmd_status() {
    local fmt="human"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --format) fmt="${2:-human}"; shift 2 ;;
            --json) fmt="json"; shift ;;
            *) shift ;;
        esac
    done

    local f="$OMS_STATE_DIR/last-scan.tsv"
    if [[ ! -f "$f" ]]; then
        case "$fmt" in
            json) echo '{"schema":1,"available":false}' ;;
            swiftbar)
                echo "🌀"
                echo "---"
                echo "oh-my-safety: no scan yet"
                echo "Run a scan | bash=\"$OMS_BIN\" param1=scan terminal=true" ;;
            *) log_warn "No scan recorded yet. Run: oh-my-safety scan" ;;
        esac
        return 3
    fi

    case "$fmt" in
        tsv)      cat "$f" ;;
        json)     _status_json "$f" ;;
        swiftbar) _status_swiftbar "$f" ;;
        *)        _status_human "$f" ;;
    esac
}

_status_human() {
    local f="$1" ts ver ex fda age
    ts="$(_status_meta "$f" timestamp)"
    ver="$(_status_meta "$f" version)"
    ex="$(_status_meta "$f" exit)"
    fda="$(_status_meta "$f" fda)"
    age="$(_scan_age "$ts")"

    print_header "oh-my-safety status"
    echo "Last scan:  $ts (${age}s ago, source: $(_status_meta "$f" source))"
    echo "Version:    $ver    Platform: $(_status_meta "$f" platform)    Full Disk Access: ${fda:-unknown}"
    echo "Agent:      $(_agent_running && echo "running ($(_agent_manager))" || echo "not running")"
    echo ""
    awk -F'\t' '$1=="result"{printf "  [%-8s] %-9s %-20s %s\n", $4, $2, $3, $6}' "$f"
    echo ""
    case "$ex" in
        0) print_check_result pass "Overall: OK" ;;
        1) print_check_result warn "Overall: warning(s) present" ;;
        *) print_check_result critical "Overall: critical/error present" ;;
    esac
}

_status_json() {
    local f="$1" ts ver plat ex src fda ip age stale interval overall
    ts="$(_status_meta "$f" timestamp)"; ver="$(_status_meta "$f" version)"
    plat="$(_status_meta "$f" platform)"; ex="$(_status_meta "$f" exit)"
    src="$(_status_meta "$f" source)"; fda="$(_status_meta "$f" fda)"
    ip="$(_status_meta "$f" public_ip)"
    age="$(_scan_age "$ts")"
    interval="$(config_get 'monitoring.interval' '300')"
    stale=false
    { [[ "$age" -lt 0 ]] || [[ "$age" -gt $(( interval * 3 )) ]]; } && stale=true
    overall="ok"; [[ "$ex" == "1" ]] && overall="warn"; { [[ "$ex" == "2" ]] || [[ "$ex" == "3" ]]; } && overall="critical"

    local ok warn crit skip err
    ok="$(_count_result ok "$f")"; warn="$(_count_result warn "$f")"
    crit="$(_count_result critical "$f")"; skip="$(_count_result skip "$f")"
    err="$(_count_result error "$f")"

    printf '{'
    printf '"schema":1,"available":true,'
    printf '"version":"%s","generated_at":"%s","source":"%s","platform":"%s",' \
        "$(json_escape "$ver")" "$(json_escape "$ts")" "$(json_escape "$src")" "$(json_escape "$plat")"
    printf '"age_seconds":%s,"stale":%s,"overall":"%s","fda":%s,' "$age" "$stale" "$overall" "${fda:-false}"
    [[ -n "$ip" ]] && printf '"public_ip":"%s",' "$(json_escape "$ip")"
    printf '"agent":{"running":%s,"manager":"%s"},' \
        "$(_agent_running && echo true || echo false)" "$(_agent_manager)"
    printf '"counts":{"ok":%s,"warn":%s,"critical":%s,"skipped":%s,"error":%s},' "$ok" "$warn" "$crit" "$skip" "$err"
    printf '"checks":['
    awk -F'\t' '
        function esc(s){gsub(/\\/,"\\\\",s);gsub(/"/,"\\\"",s);return s}
        BEGIN{first=1}
        $1=="result"{
            if(!first)printf","; first=0
            printf "{\"category\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"severity\":\"%s\",\"summary\":\"%s\"}", \
                esc($2),esc($3),esc($4),esc($5),esc($6)
        }' "$f"
    printf ']}'
    printf '\n'
}

_status_swiftbar() {
    local f="$1" ts ex age stale interval crit warn icon
    ts="$(_status_meta "$f" timestamp)"
    ex="$(_status_meta "$f" exit)"
    age="$(_scan_age "$ts")"
    interval="$(config_get 'monitoring.interval' '300')"
    stale=false
    { [[ "$age" -lt 0 ]] || [[ "$age" -gt $(( interval * 3 )) ]]; } && stale=true
    crit="$(_count_result critical "$f")"; warn="$(_count_result warn "$f")"

    if [[ "$stale" == "true" ]]; then icon="🌀"
    elif [[ "$crit" -gt 0 ]]; then icon="🚨 $crit"
    elif [[ "$warn" -gt 0 ]]; then icon="⚠️ $warn"
    else icon="🛡️"; fi

    echo "$icon"
    echo "---"
    echo "oh-my-safety | size=13"
    [[ "$stale" == "true" ]] && echo "Last scan is stale (${age}s ago) | color=orange"
    awk -F'\t' '
        $1=="result"{
            c="green"
            if($4=="warn")c="orange"; else if($4=="critical"||$4=="error")c="red"; else if($4=="skip")c="gray"
            printf "%s/%s: %s | color=%s\n", $2, $3, $6, c
        }' "$f"
    echo "---"
    echo "Run deep scan | bash=\"$OMS_BIN\" param1=scan param2=--deep terminal=true"
    echo "Full status | bash=\"$OMS_BIN\" param1=status terminal=true"
    echo "Refresh | refresh=true"
}
