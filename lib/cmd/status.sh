#!/bin/bash
# oh-my-safety - `status` subcommand
# Reads the last scan result from local state and renders it. Makes NO network
# calls and runs NO checks — it is a pure consumer of last-scan.tsv, so menu
# bar plugins and scripts can poll it cheaply.

_status_meta() { awk -F'\t' -v k="$2" '$1=="meta" && $2==k {print $3; exit}' "$1"; }

_scan_age() {
    local ts="$1" epoch now
    [[ -z "$ts" ]] && { echo -1; return; }
    # GNU date (Linux) and BSD date (macOS) use different parsing flags.
    epoch="$(TZ=UTC date -d "$ts" +%s 2>/dev/null)"
    if [[ -z "$epoch" ]]; then
        epoch="$(TZ=UTC date -j -f '%Y-%m-%dT%H:%M:%SZ' "$ts" +%s 2>/dev/null)"
    fi
    now="$(date +%s)"
    [[ -z "$epoch" ]] && { echo -1; return; }
    echo $(( now - epoch ))
}

_agent_running() {
    local platform out
    platform="$(detect_platform)"
    case "$platform" in
        macos)
            # Capture launchctl output then string-match: piping large output
            # into grep -q can SIGPIPE launchctl under pipefail.
            out="$(launchctl list 2>/dev/null)"
            case "$out" in *oh-my-safety*) return 0 ;; esac
            ;;
        linux|wsl)
            if command -v systemctl >/dev/null 2>&1; then
                systemctl --user is-active --quiet oh-my-safety.service 2>/dev/null && return 0
                systemctl --user is-active --quiet snap.oh-my-safety.monitor.service 2>/dev/null && return 0
                systemctl is-active --quiet oh-my-safety.service 2>/dev/null && return 0
            fi
            ;;
    esac
    pgrep -f '[o]h-my-safety.*monitor' >/dev/null 2>&1
}

_agent_manager() {
    local platform out
    platform="$(detect_platform)"
    case "$platform" in
        macos)
            out="$(launchctl list 2>/dev/null)"
            case "$out" in
                *homebrew.mxcl.oh-my-safety*) echo brew ;;
                *com.vardominator.oh-my-safety*) echo manual ;;
                *) pgrep -f '[o]h-my-safety.*monitor' >/dev/null 2>&1 && echo manual || echo none ;;
            esac
            ;;
        linux|wsl)
            if command -v systemctl >/dev/null 2>&1; then
                if systemctl --user is-active --quiet oh-my-safety.service 2>/dev/null; then
                    echo systemd-user
                    return 0
                fi
                if systemctl --user is-active --quiet snap.oh-my-safety.monitor.service 2>/dev/null; then
                    echo snap
                    return 0
                fi
                if systemctl is-active --quiet oh-my-safety.service 2>/dev/null; then
                    echo systemd-system
                    return 0
                fi
            fi
            pgrep -f '[o]h-my-safety.*monitor' >/dev/null 2>&1 && echo manual || echo none
            ;;
        *)
            pgrep -f '[o]h-my-safety.*monitor' >/dev/null 2>&1 && echo manual || echo none
            ;;
    esac
}

_count_result() { awk -F'\t' -v s="$1" '$1=="result" && $4==s{c++} END{print c+0}' "$2"; }

_status_check_label() {
    case "$1" in
        dns-leak)            echo "DNS leak" ;;
        ip-address)          echo "Public IP" ;;
        ipv6-leak)           echo "IPv6 leak" ;;
        routing)             echo "VPN routing" ;;
        vpn-tunnel)          echo "VPN tunnel" ;;
        hardening-posture)   echo "Firewall & hardening" ;;
        linux-hardening-posture) echo "Linux hardening" ;;
        linux-persistence-scan) echo "Linux persistence" ;;
        network-exposure)    echo "Network exposure" ;;
        persistence-scan)    echo "Startup persistence" ;;
        process-audit)       echo "Suspicious processes" ;;
        secrets-content)     echo "Secret content scan" ;;
        secrets-exposure)    echo "Secret permissions" ;;
        tcc-audit)           echo "Privacy permissions" ;;
        wallet-guard)        echo "Wallet exposure" ;;
        yara-scan)           echo "Malware scan" ;;
        *)                   printf '%s' "$1" | tr '-' ' ' ;;
    esac
}

_status_manifest_field() {
    local cat="$1" name="$2" field="$3" file
    file="$OMS_ROOT/lib/checks/$cat/$name.sh"
    [[ -f "$file" ]] || return 0
    sed -n "s/^${field}=\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$file" | head -1
}

_status_clean_detail() {
    local s="$1" prefix
    s="$(printf '%s' "$s" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    for prefix in "✅ " "⚠️  " "⚠️ " "❌ " "ℹ️  " "ℹ️ " "⏭️  " "⏭️ " "✗ "; do
        case "$s" in "$prefix"*) s="${s#"$prefix"}"; break ;; esac
    done
    case "$s" in "- "*) s="${s#- }" ;; esac
    printf '%s' "$s"
}

# Choose a concrete finding for the top-level SwiftBar row. Generic count lines
# are skipped in favor of the first item emitted by the check.
_status_primary_detail() {
    local f="$1" cat="$2" name="$3" summary="$4" raw trimmed clean
    local first_id="" fallback=""
    while IFS= read -r raw; do
        trimmed="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//')"
        case "$trimmed" in
            "✅ "*|"ℹ️  "*|"ℹ️ "*|"⏭️  "*|"⏭️ "*) continue ;;
        esac
        clean="$(_status_clean_detail "$raw")"
        [[ -z "$clean" ]] && continue
        case "$clean" in
            "$summary"*) continue ;;
            "Accept with:"*|"Accept expected"*|"Run '"*|"Configured DNS servers:"*) continue ;;
        esac
        clean="$(printf '%s' "$clean" | sed 's/[[:space:]]*\[id:.*$//')"
        [[ ${#clean} -gt 105 ]] && clean="${clean:0:102}..."
        case "$trimmed" in
            "⚠️ "*|"❌ "*|"✗ "*)
                printf '%s' "$clean"
                return 0 ;;
        esac
        if [[ "$raw" == *"[id:"* && -z "$first_id" ]]; then
            first_id="$clean"
        elif [[ -z "$fallback" ]]; then
            fallback="$clean"
        fi
    done < <(awk -F'\t' -v c="$cat" -v n="$name" '$1=="detail" && $2==c && $3==n {print $4}' "$f")
    [[ -n "$first_id" ]] && { printf '%s' "$first_id"; return 0; }
    [[ -n "$fallback" ]] && { printf '%s' "$fallback"; return 0; }
    return 1
}

_swiftbar_text() {
    printf '%s' "$1" | tr '\n\r' '  ' | sed 's/|/¦/g'
}

_status_age_label() {
    local age="$1"
    if [[ "$age" -lt 0 ]]; then echo "unknown"
    elif [[ "$age" -lt 60 ]]; then echo "${age}s ago"
    elif [[ "$age" -lt 3600 ]]; then echo "$(( age / 60 ))m ago"
    else echo "$(( age / 3600 ))h ago"
    fi
}

_status_interval() {
    local interval
    interval="$(config_get 'monitoring.interval' '300')"
    case "$interval" in ''|*[!0-9]*|0) interval=300 ;; esac
    [[ "${#interval}" -le 9 ]] || interval=300
    interval="$(( 10#$interval ))"
    [[ "$interval" -gt 0 ]] || interval=300
    printf '%s' "$interval"
}

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
    local f="$1" ts updated scope ver ex fda age
    ts="$(_status_meta "$f" timestamp)"
    updated="$(_status_meta "$f" updated_at)"
    scope="$(_status_meta "$f" scope)"
    ver="$(_status_meta "$f" version)"
    ex="$(_status_meta "$f" exit)"
    fda="$(_status_meta "$f" fda)"
    age="$(_scan_age "$ts")"

    print_header "oh-my-safety status"
    echo "Last scan:  $ts (${age}s ago, source: $(_status_meta "$f" source))"
    [[ -n "$updated" ]] && echo "Updated:    $updated    Scope: ${scope:-unknown}"
    echo "Version:    $ver    Platform: $(_status_meta "$f" platform)    Full Disk Access: ${fda:-unknown}"
    echo "Agent:      $(_agent_running && echo "running ($(_agent_manager))" || echo "not running")"
    echo ""
    awk -F'\t' '$1=="result"{printf "  [%-8s] %-9s %-20s %s\n", $4, $2, $3, $6}' "$f"

    local kind cat name status severity summary remediation doc label any_details=false
    while IFS=$'\t' read -r kind cat name status severity summary remediation doc; do
        [[ "$kind" == "result" ]] || continue
        case "$status" in ok) continue ;; esac
        if [[ "$any_details" == "false" ]]; then
            echo ""
            echo "Actionable details"
            any_details=true
        fi
        label="$(_status_check_label "$name")"
        [[ -z "$remediation" ]] && remediation="$(_status_manifest_field "$cat" "$name" CHECK_REMEDIATION)"
        [[ -z "$doc" ]] && doc="$(_status_manifest_field "$cat" "$name" CHECK_DOC)"
        echo ""
        printf '  %s (%s)\n' "$label" "$status"
        awk -F'\t' -v c="$cat" -v n="$name" \
            '$1=="detail" && $2==c && $3==n {printf "    %s\n", $4}' "$f"
        [[ -n "$remediation" ]] && printf '    Suggested action: %s\n' "$remediation"
        [[ -n "$doc" ]] && printf '    Guide: https://github.com/Vardominator/oh-my-safety/blob/main/%s\n' "$doc"
    done < "$f"

    echo ""
    case "$ex" in
        0) print_check_result pass "Overall: OK" ;;
        1) print_check_result warn "Overall: warning(s) present" ;;
        *) print_check_result critical "Overall: critical/error present" ;;
    esac
}

_status_json() {
    local f="$1" ts updated scope ver plat ex src fda ip age stale interval overall
    ts="$(_status_meta "$f" timestamp)"; ver="$(_status_meta "$f" version)"
    updated="$(_status_meta "$f" updated_at)"; scope="$(_status_meta "$f" scope)"
    plat="$(_status_meta "$f" platform)"; ex="$(_status_meta "$f" exit)"
    src="$(_status_meta "$f" source)"; fda="$(_status_meta "$f" fda)"
    ip="$(_status_meta "$f" public_ip)"
    age="$(_scan_age "$ts")"
    interval="$(_status_interval)"
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
    printf '"updated_at":"%s","scope":"%s",' \
        "$(json_escape "${updated:-$ts}")" "$(json_escape "${scope:-full}")"
    printf '"age_seconds":%s,"stale":%s,"overall":"%s","fda":%s,' "$age" "$stale" "$overall" "${fda:-false}"
    [[ -n "$ip" ]] && printf '"public_ip":"%s",' "$(json_escape "$ip")"
    printf '"agent":{"running":%s,"manager":"%s"},' \
        "$(_agent_running && echo true || echo false)" "$(_agent_manager)"
    printf '"counts":{"ok":%s,"warn":%s,"critical":%s,"skipped":%s,"error":%s},' "$ok" "$warn" "$crit" "$skip" "$err"
    printf '"checks":['
    awk -F'\t' '
        function esc(s){gsub(/\\/,"\\\\",s);gsub(/"/,"\\\"",s);return s}
        $1=="result"{
            count++
            cat[count]=$2; name[count]=$3; status[count]=$4; severity[count]=$5
            summary[count]=$6; remediation[count]=$7; doc[count]=$8
        }
        $1=="detail"{
            key=$2 SUBSEP $3
            detail_count[key]++
            detail[key SUBSEP detail_count[key]]=$4
        }
        END{
            for(i=1;i<=count;i++){
                if(i>1)printf","
                printf "{\"category\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"severity\":\"%s\",\"summary\":\"%s\",\"remediation\":\"%s\",\"doc\":\"%s\",\"details\":[", \
                    esc(cat[i]),esc(name[i]),esc(status[i]),esc(severity[i]),esc(summary[i]),esc(remediation[i]),esc(doc[i])
                key=cat[i] SUBSEP name[i]
                for(j=1;j<=detail_count[key];j++){
                    if(j>1)printf","
                    printf "\"%s\"",esc(detail[key SUBSEP j])
                }
                printf "]}"
            }
        }' "$f"
    printf ']}'
    printf '\n'
}

_status_swiftbar() {
    local f="$1" ts ex age stale interval crit warn skip ok icon agent attention
    # SwiftBar supports comma-separated light/dark variants. Explicit,
    # high-contrast colors remain legible over both of its translucent menu
    # appearances; named colors such as "orange" and "gray" do not.
    local color_primary="#1F2937,#F9FAFB"
    local color_secondary="#4B5563,#D1D5DB"
    local color_warning="#7A3E00,#FFD166"
    local color_critical="#A51D16,#FF8A80"
    local color_healthy="#166534,#86EFAC"
    local color_remediation="#17603A,#8CE3B0"
    ts="$(_status_meta "$f" timestamp)"
    ex="$(_status_meta "$f" exit)"
    age="$(_scan_age "$ts")"
    interval="$(_status_interval)"
    stale=false
    { [[ "$age" -lt 0 ]] || [[ "$age" -gt $(( interval * 3 )) ]]; } && stale=true
    crit="$(_count_result critical "$f")"; warn="$(_count_result warn "$f")"
    skip="$(_count_result skip "$f")"; ok="$(_count_result ok "$f")"

    if [[ "$stale" == "true" ]]; then icon="🌀"
    elif [[ "$crit" -gt 0 ]]; then icon="🚨 $crit"
    elif [[ "$warn" -gt 0 ]]; then icon="⚠️ $warn"
    else icon="🛡️"; fi

    echo "$icon"
    echo "---"
    if _agent_running; then agent="agent running ($(_agent_manager))"; else agent="agent stopped"; fi
    if [[ "$crit" -gt 0 || "$warn" -gt 0 ]]; then
        attention=$(( crit + warn ))
        if [[ "$attention" -eq 1 ]]; then
            echo "**oh-my-safety — 1 item needs attention** | color=$color_primary size=14 md=true"
        else
            echo "**oh-my-safety — $attention items need attention** | color=$color_primary size=14 md=true"
        fi
    else
        echo "**oh-my-safety — all checks clear** | color=$color_primary size=14 md=true"
    fi
    echo "Last scan $(_status_age_label "$age") · $agent | color=$color_secondary size=12"
    [[ "$stale" == "true" ]] && \
        echo "Last scan is stale (${age}s ago) | color=$color_warning size=12"

    local kind cat name status severity summary remediation doc label primary
    local color marker raw clean detail_count omitted detail_started trimmed
    if [[ "$crit" -gt 0 || "$warn" -gt 0 ]]; then
        echo "---"
        echo "**Needs attention** | color=$color_warning size=13 md=true"
        while IFS=$'\t' read -r kind cat name status severity summary remediation doc; do
            [[ "$kind" == "result" ]] || continue
            case "$status" in warn|critical|error) : ;; *) continue ;; esac
            label="$(_status_check_label "$name")"
            [[ -z "$remediation" ]] && remediation="$(_status_manifest_field "$cat" "$name" CHECK_REMEDIATION)"
            [[ -z "$doc" ]] && doc="$(_status_manifest_field "$cat" "$name" CHECK_DOC)"
            case "$status" in
                warn) color="$color_warning"; marker="⚠️" ;;
                *)    color="$color_critical"; marker="🚨" ;;
            esac
            primary="$(_status_primary_detail "$f" "$cat" "$name" "$summary")"
            [[ -z "$primary" ]] && primary="$summary"
            echo "$marker $(_swiftbar_text "$label — $primary") | color=$color size=13"
            echo "--Summary: $(_swiftbar_text "$summary") | color=$color size=13"
            detail_count=0
            omitted=0
            detail_started=false
            while IFS= read -r raw; do
                trimmed="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//')"
                if [[ "$detail_started" == "false" ]]; then
                    case "$trimmed" in
                        "⚠️ "*|"❌ "*|"✗ "*) detail_started=true ;;
                        *"[id:"*) detail_started=true ;;
                        *) continue ;;
                    esac
                fi
                clean="$(_status_clean_detail "$raw")"
                [[ -z "$clean" ]] && continue
                detail_count=$(( detail_count + 1 ))
                if [[ "$detail_count" -le 18 ]]; then
                    echo "--$(_swiftbar_text "$clean") | color=$color_primary size=12"
                else
                    omitted=$(( omitted + 1 ))
                fi
            done < <(awk -F'\t' -v c="$cat" -v n="$name" \
                '$1=="detail" && $2==c && $3==n {print $4}' "$f")
            if [[ "$detail_count" -eq 0 ]]; then
                echo "--Exact details were not saved by this older scan | color=$color_secondary size=12"
                echo "--Run recheck to capture them | color=$color_secondary size=12"
            fi
            [[ "$omitted" -gt 0 ]] && \
                echo "--… $omitted more detail line(s); open Full status below | color=$color_secondary size=12"
            [[ -n "$remediation" ]] && \
                echo "--Suggested: $(_swiftbar_text "$remediation") | color=$color_remediation size=12"
            echo "--Recheck $(_swiftbar_text "$label") | bash=\"$OMS_BIN\" param1=recheck param2=\"$name\" terminal=true refresh=true"
            [[ -n "$doc" ]] && \
                echo "--Open remediation guide | href=https://github.com/Vardominator/oh-my-safety/blob/main/$doc"
        done < "$f"
    fi

    if [[ "$skip" -gt 0 ]]; then
        echo "---"
        echo "**Limited coverage ($skip)** | color=$color_secondary size=13 md=true"
        while IFS=$'\t' read -r kind cat name status severity summary remediation doc; do
            [[ "$kind" == "result" && "$status" == "skip" ]] || continue
            label="$(_status_check_label "$name")"
            [[ -z "$remediation" ]] && remediation="$(_status_manifest_field "$cat" "$name" CHECK_REMEDIATION)"
            echo "--⏭ $(_swiftbar_text "$label — $summary") | color=$color_secondary size=12"
            while IFS= read -r raw; do
                clean="$(_status_clean_detail "$raw")"
                [[ -n "$clean" ]] && echo "----$(_swiftbar_text "$clean") | color=$color_secondary size=12"
            done < <(awk -F'\t' -v c="$cat" -v n="$name" \
                '$1=="detail" && $2==c && $3==n {print $4}' "$f")
            [[ -n "$remediation" ]] && \
                echo "----Suggested: $(_swiftbar_text "$remediation") | color=$color_secondary size=12"
            echo "----Recheck $(_swiftbar_text "$label") | bash=\"$OMS_BIN\" param1=recheck param2=\"$name\" terminal=true refresh=true"
        done < "$f"
    fi

    if [[ "$ok" -gt 0 ]]; then
        echo "---"
        echo "**Healthy checks ($ok)** | color=$color_healthy size=13 md=true"
        while IFS=$'\t' read -r kind cat name status severity summary remediation doc; do
            [[ "$kind" == "result" && "$status" == "ok" ]] || continue
            label="$(_status_check_label "$name")"
            echo "--✓ $(_swiftbar_text "$label — $summary") | color=$color_healthy size=12"
        done < "$f"
    fi

    echo "---"
    echo "Run deep scan now | bash=\"$OMS_BIN\" param1=scan param2=--deep terminal=true refresh=true"
    echo "Full status | bash=\"$OMS_BIN\" param1=status terminal=true"
    echo "Refresh | refresh=true"
}
