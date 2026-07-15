#!/bin/bash
# oh-my-safety - detect newly-appeared listening network services (baseline drift)
CHECK_NAME="network-exposure"
CHECK_DESCRIPTION="New listening TCP network services detected via baseline drift"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="60"
CHECK_DOC="docs/checks/security/network-exposure.md"

# ---------------------------------------------------------------------------
# Finding-id scheme (stable across runs, path-based, never pid-based):
#     tcp|<port_or_*>|<exe>|<scope>
#   port  : the listening port, or "*" when it is an ephemeral port folded down
#   exe   : executable path of the owning process (oms_proc_path)
#   scope : "wan" (all interfaces / routable addr) or "loopback"
# The id IS the baseline entry, so `oh-my-safety accept` and allowlisting match.
# ---------------------------------------------------------------------------

# Build one snapshot line per current TCP listener. $1 = ephemeral port floor.
_ne_tcp_snapshot() {
    local floor="$1"
    # lsof without sudo only surfaces the *current user's* listeners, which is
    # exactly what catches user-level malware. NAME looks like "*:8080",
    # "127.0.0.1:8080" or "[::1]:8080".
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $2, $9}' | \
    while read -r pid name; do
        [ -z "$pid" ] && continue
        [ -z "$name" ] && continue

        local port addr scope exe
        port="${name##*:}"     # substring after the last ':'
        addr="${name%:*}"      # everything before the last ':'

        case "$addr" in
            127.*|localhost|"[::1]") scope="loopback" ;;
            *)                        scope="wan" ;;
        esac

        # Fold ephemeral high ports so churn does not create endless "new" ids.
        case "$port" in
            ''|*[!0-9]*) : ;;  # non-numeric (e.g. "*") -> leave as-is
            *) if [ "$port" -ge "$floor" ] 2>/dev/null; then port="*"; fi ;;
        esac

        exe="$(oms_proc_path "$pid")"
        [ -z "$exe" ] && exe="unknown"
        exe="${exe//|/_}"      # keep the '|'-delimited id parseable

        printf 'tcp|%s|%s|%s\n' "$port" "$exe" "$scope"
    done
}

# UDP is inventory-only in v1 (never baseline-flagged). Surface at debug, and
# in --deep mode print a short list at info level.
_ne_udp_inventory() {
    local udp count
    udp="$(lsof -nP -iUDP 2>/dev/null | awk 'NR>1{print $1, $2, $9}' | sort -u)"
    [ -z "$udp" ] && return 0
    count="$(printf '%s\n' "$udp" | grep -c .)"
    log_debug "network-exposure: $count UDP endpoint(s) seen (inventory only, not baselined)"
    if [ "${OMS_DEEP:-}" = "true" ]; then
        print_check_result info "UDP endpoints (inventory only, not flagged in v1): $count"
        printf '%s\n' "$udp" | head -20 | sed 's/^/    /'
    fi
}

check_network_exposure() {
    local NAME="network-exposure"
    local floor loopback_mode
    floor="$(config_get "checks.security.network_exposure.ephemeral_port_floor" "49152")"
    loopback_mode="$(config_get "checks.security.network_exposure.loopback_new_listener" "info")"

    log_debug "network-exposure: lsof runs without sudo, so only the current user's listeners are visible"

    _ne_udp_inventory

    local current
    current="$(_ne_tcp_snapshot "$floor" | sort -u)"

    # First run: record a quiet baseline, flag nothing.
    if ! baseline_exists "$NAME"; then
        printf '%s\n' "$current" | baseline_save "$NAME"
        local n
        n="$(printf '%s\n' "$current" | grep -c .)"
        print_check_result pass "Baseline recorded ($n TCP listener(s)). New listeners will be flagged."
        CHECK_FINDING_SUMMARY="baseline created ($n listeners)"
        return 0
    fi

    local drift drift_rc added
    drift="$(printf '%s\n' "$current" | baseline_diff "$NAME")"
    drift_rc=$?
    added="$(printf '%s\n' "$drift" | sed -n 's/^+//p')"

    local finding_lines="" info_lines="" actionable="" max_sev="" n_find=0

    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        allowlist_match "$NAME" "$entry" && continue

        local proto port exe scope verdict sig_bad writable portdesc sev
        proto="$(printf '%s' "$entry" | cut -d'|' -f1)"
        port="$(printf '%s' "$entry" | cut -d'|' -f2)"
        exe="$(printf '%s' "$entry" | cut -d'|' -f3)"
        scope="$(printf '%s' "$entry" | cut -d'|' -f4)"
        [ "$proto" = "tcp" ] || continue

        verdict="$(oms_codesign_verdict "$exe")"
        sig_bad="no"
        case "$verdict" in
            unsigned|adhoc) sig_bad="yes" ;;
        esac
        writable="no"
        oms_is_user_writable_path "$exe" && writable="yes"

        if [ "$port" = "*" ]; then
            portdesc="port * (ephemeral/any)"
        else
            portdesc="port $port"
        fi

        if [ "$scope" = "wan" ]; then
            sev="warn"
            [ "$sig_bad" = "yes" ] && sev="critical"
            [ "$writable" = "yes" ] && sev="critical"
            finding_lines="$finding_lines  - NEW WAN-reachable TCP listener: ${exe} on ${portdesc} [sig: ${verdict}]   [id: ${entry}]
"
            n_find=$((n_find + 1))
            actionable="$actionable$entry
"
            if [ "$sev" = "critical" ]; then max_sev="critical"; elif [ -z "$max_sev" ]; then max_sev="warn"; fi
        else
            # loopback
            if [ "$sig_bad" = "yes" ]; then
                # Unsigned/adhoc always warrants a warning regardless of config.
                finding_lines="$finding_lines  - NEW loopback TCP listener (unsigned/adhoc): ${exe} on ${portdesc} [sig: ${verdict}]   [id: ${entry}]
"
                n_find=$((n_find + 1))
                actionable="$actionable$entry
"
                [ -z "$max_sev" ] && max_sev="warn"
            elif [ "$loopback_mode" = "warn" ]; then
                finding_lines="$finding_lines  - NEW loopback TCP listener: ${exe} on ${portdesc} [sig: ${verdict}]   [id: ${entry}]
"
                n_find=$((n_find + 1))
                actionable="$actionable$entry
"
                [ -z "$max_sev" ] && max_sev="warn"
            elif [ "$loopback_mode" = "off" ]; then
                : # ignored by config
            else
                # info (default): visibility without a finding
                info_lines="$info_lines  - new loopback TCP listener: ${exe} on ${portdesc} [sig: ${verdict}]   [id: ${entry}]
"
            fi
        fi
    done <<EOF2
$added
EOF2

    # Findings present -> stage current for `accept`, report, and fail.
    if [ -n "$actionable" ]; then
        printf '%s\n' "$current" | baseline_stage_pending "$NAME"
        if [ "$max_sev" = "critical" ]; then
            print_check_result critical "$n_find new network listener(s) detected"
        else
            print_check_result warn "$n_find new network listener(s) detected"
        fi
        printf '%s' "$finding_lines"
        [ -n "$info_lines" ] && printf '%s' "$info_lines"
        echo "  (lsof without sudo only sees the current user's listeners)"
        echo "  Accept with: oh-my-safety accept $NAME   (or allowlist an id above)"
        CHECK_FINDING_SUMMARY="$n_find new network listener(s)"
        CHECK_RESULT_SEVERITY="$max_sev"
        return 1
    fi

    # No findings. Absorb benign drift (removals, info/off loopback additions)
    # into the baseline so it does not nag every run.
    if [ "$drift_rc" -ne 0 ]; then
        printf '%s\n' "$current" | baseline_save "$NAME"
    fi

    if [ -n "$info_lines" ]; then
        print_check_result info "New loopback listener(s) (informational, added to baseline)"
        printf '%s' "$info_lines"
        CHECK_FINDING_SUMMARY="no findings; informational loopback listener(s)"
        return 0
    fi

    print_check_result pass "No new network listeners since baseline"
    CHECK_FINDING_SUMMARY="no new listeners"
    return 0
}
