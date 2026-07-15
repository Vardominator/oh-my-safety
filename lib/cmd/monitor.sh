#!/bin/bash
# oh-my-safety - `monitor` subcommand: continuous foreground monitoring loop.
# Designed to be supervised by launchd (via `brew services` or install-agent).
# Two cadences: a cheap fast route-flip check, and periodic full scans.

cmd_monitor() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -q|--quiet) OMS_QUIET=true; export OMS_QUIET; shift ;;
            *) shift ;;
        esac
    done

    load_platform

    local interval fast last_full now route cur last_vpn
    interval="$(config_get 'monitoring.interval' '300')"
    fast="$(config_get 'monitoring.fast_interval' '15')"
    OMS_SCAN_SOURCE="agent"; export OMS_SCAN_SOURCE

    log_info "oh-my-safety monitoring (full scan every ${interval}s, route check every ${fast}s)"
    trap 'log_info "Monitoring stopped."; exit 0' INT TERM

    last_full=0
    last_vpn="unknown"

    while true; do
        now="$(date +%s)"

        # Fast VPN route-flip check (edge-triggered alert on disconnect)
        route="$(get_default_route_interface)"
        if is_vpn_interface "$route"; then cur="connected"; else cur="disconnected"; fi
        if [[ "$cur" == "disconnected" && "$last_vpn" == "connected" ]]; then
            notify "oh-my-safety" "VPN disconnected — traffic now via ${route:-unknown}" ""
        fi
        last_vpn="$cur"

        # Periodic full scan (writes last-scan.tsv, appends log, notifies findings)
        if [[ $(( now - last_full )) -ge $interval ]]; then
            run_scan --deep || true
            last_full="$now"
        fi

        sleep "$fast"
    done
}
