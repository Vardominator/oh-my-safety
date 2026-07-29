#!/bin/bash
# oh-my-safety - `monitor` subcommand: continuous foreground monitoring loop.
# Designed to be supervised by launchd (via `brew services` or install-agent).
# A cheap route-flip loop remains responsive while due checks run in a
# non-overlapping background worker.

_monitor_valid_interval() {
    case "$1" in ''|*[!0-9]*|0) return 1 ;; esac
    [[ "${#1}" -le 9 ]] || return 1
    [[ "$(( 10#$1 ))" -gt 0 ]]
}

# Reload all config layers as one snapshot. If either monitor cadence is
# invalid, retain the prior known-good snapshot rather than partially applying
# a file while the daemon is running.
_monitor_reload_config() {
    local old_file="${OMS_CONFIG_FILE:-}" old_user="${OMS_CONFIG_FLAT_USER:-}"
    local old_default="${OMS_CONFIG_FLAT_DEFAULT:-}" old_overrides_file="${OMS_OVERRIDES_FILE:-}"
    local old_override="${OMS_CONFIG_FLAT_OVERRIDE:-}" interval fast
    local old_managed="${OMS_CONFIG_FLAT_MANAGED:-}"

    if ! load_config "${OMS_CONFIG_FILE_ARG:-}"; then
        OMS_CONFIG_FILE="$old_file"
        OMS_CONFIG_FLAT_USER="$old_user"
        OMS_CONFIG_FLAT_DEFAULT="$old_default"
        OMS_OVERRIDES_FILE="$old_overrides_file"
        OMS_CONFIG_FLAT_OVERRIDE="$old_override"
        OMS_CONFIG_FLAT_MANAGED="$old_managed"
        log_warn "Config reload failed; retaining the previous configuration"
        return 1
    fi

    interval="$(config_get 'monitoring.interval' '300')"
    fast="$(config_get 'monitoring.fast_interval' '15')"
    if ! _monitor_valid_interval "$interval" || ! _monitor_valid_interval "$fast"; then
        OMS_CONFIG_FILE="$old_file"
        OMS_CONFIG_FLAT_USER="$old_user"
        OMS_CONFIG_FLAT_DEFAULT="$old_default"
        OMS_OVERRIDES_FILE="$old_overrides_file"
        OMS_CONFIG_FLAT_OVERRIDE="$old_override"
        OMS_CONFIG_FLAT_MANAGED="$old_managed"
        log_warn "Invalid monitoring interval in reloaded config; retaining the previous configuration"
        return 1
    fi

    OMS_MONITOR_INTERVAL="$(( 10#$interval ))"
    OMS_MONITOR_FAST_INTERVAL="$(( 10#$fast ))"
    export OMS_MONITOR_INTERVAL OMS_MONITOR_FAST_INTERVAL
}

_monitor_stop() {
    trap - INT TERM
    if [[ -n "${OMS_MONITOR_SCAN_PID:-}" ]] && kill -0 "$OMS_MONITOR_SCAN_PID" 2>/dev/null; then
        kill "$OMS_MONITOR_SCAN_PID" 2>/dev/null || true
        wait "$OMS_MONITOR_SCAN_PID" 2>/dev/null || true
    fi
    # Bash 3.2 keeps $$ unchanged in a background subshell, so a worker killed
    # mid-scan leaves a lock owned by this still-live supervisor PID.
    scan_lock_release 2>/dev/null || true
    log_info "Monitoring stopped."
    exit 0
}

cmd_monitor() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -q|--quiet) OMS_QUIET=true; export OMS_QUIET; shift ;;
            *) shift ;;
        esac
    done

    load_platform

    local interval fast route cur last_vpn
    interval="$(config_get 'monitoring.interval' '300')"
    fast="$(config_get 'monitoring.fast_interval' '15')"
    _monitor_valid_interval "$interval" || interval=300
    _monitor_valid_interval "$fast" || fast=15
    OMS_MONITOR_INTERVAL="$(( 10#$interval ))"
    OMS_MONITOR_FAST_INTERVAL="$(( 10#$fast ))"
    OMS_MONITOR_SCAN_PID=""
    export OMS_MONITOR_INTERVAL OMS_MONITOR_FAST_INTERVAL OMS_MONITOR_SCAN_PID
    _monitor_reload_config || true

    OMS_SCAN_SOURCE="agent"; export OMS_SCAN_SOURCE

    log_info "oh-my-safety monitoring (per-check schedules, route check every ${OMS_MONITOR_FAST_INTERVAL}s)"
    trap '_monitor_stop' INT TERM

    last_vpn="unknown"

    while true; do
        # Configuration is intentionally re-read between ticks, never during a
        # running check. A forked scan therefore sees one consistent snapshot.
        _monitor_reload_config || true
        fast="$OMS_MONITOR_FAST_INTERVAL"
        case "$(config_get 'profile.connectivity' 'connected')" in
            offline|airgapped) OMS_OFFLINE=true ;;
            *) OMS_OFFLINE=false ;;
        esac
        export OMS_OFFLINE

        # Fast VPN route-flip check (edge-triggered alert on disconnect)
        if [[ "$OMS_OFFLINE" != "true" ]] && config_enabled "categories.privacy.enabled" "true"; then
            route="$(get_default_route_interface)"
            if is_vpn_interface "$route"; then cur="connected"; else cur="disconnected"; fi
            if [[ "$cur" == "disconnected" && "$last_vpn" == "connected" ]]; then
                notify "oh-my-safety" "VPN disconnected — traffic now via ${route:-unknown}" ""
            fi
            last_vpn="$cur"
        fi

        # Reap a completed worker, then launch one scheduler tick. The worker
        # selects checks whose manifest CHECK_INTERVAL has elapsed. Keeping it
        # in the background ensures expensive scanners never delay route-flip
        # detection.
        if [[ -n "$OMS_MONITOR_SCAN_PID" ]] && ! kill -0 "$OMS_MONITOR_SCAN_PID" 2>/dev/null; then
            wait "$OMS_MONITOR_SCAN_PID" 2>/dev/null || true
            scan_lock_release 2>/dev/null || true
            OMS_MONITOR_SCAN_PID=""
            managed_sync_if_due || true
        fi
        if [[ -z "$OMS_MONITOR_SCAN_PID" ]]; then
            if config_enabled "monitoring.deep" "false"; then
                ( run_scan --scheduled --deep || true ) &
            else
                ( run_scan --scheduled || true ) &
            fi
            OMS_MONITOR_SCAN_PID=$!
            export OMS_MONITOR_SCAN_PID
        fi

        sleep "$fast"
    done
}
