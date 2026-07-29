#!/bin/bash
# oh-my-safety - `doctor` subcommand: environment & readiness diagnostics.

cmd_doctor() {
    load_platform
    local platform
    platform="$(detect_platform)"

    print_header "oh-my-safety doctor"
    echo "Version:   $OMS_VERSION"
    echo "Platform:  $platform"
    echo "Bash:      ${BASH_VERSION:-unknown}"
    echo "Binary:    ${OMS_BIN:-unknown}"
    echo "Config:    ${OMS_CONFIG_FILE:-unknown}"
    echo "Overrides: ${OMS_OVERRIDES_FILE:-unknown}"
    echo "State dir: $OMS_STATE_DIR"
    echo "Profile:   $(config_get 'profile.name' 'personal-balanced')"
    echo "Network:   $(config_get 'profile.connectivity' 'connected')"
    echo ""

    # State dir writable
    if state_dir >/dev/null 2>&1 && [[ -w "$OMS_STATE_DIR" ]]; then
        print_check_result pass "State directory is writable"
    else
        print_check_result fail "State directory is NOT writable: $OMS_STATE_DIR"
    fi

    # Config parses
    if [[ -f "$OMS_CONFIG_FILE" ]] && [[ -n "$(yaml_flatten "$OMS_CONFIG_FILE")" ]]; then
        print_check_result pass "Config parsed OK"
    else
        print_check_result warn "Config produced no keys — check 2-space indentation in $OMS_CONFIG_FILE"
    fi

    # Legacy config migration note
    if [[ -f "$HOME/.config/oh-my-privacy/config.yaml" ]]; then
        print_check_result info "Legacy ~/.config/oh-my-privacy/config.yaml present (migrated on first run)"
    fi

    # Monitoring agent
    if _agent_running 2>/dev/null; then
        print_check_result pass "Monitoring agent is loaded (manager: $(_agent_manager 2>/dev/null))"
    else
        print_check_result warn "Monitoring agent not loaded"
        case "$platform" in
            macos)
                echo "    Start it with:  brew services start oh-my-safety"
                echo "    Or (non-brew):  oh-my-safety install-agent"
                ;;
            linux|wsl)
                if [[ -n "${SNAP:-}" ]]; then
                    echo "    Install and start the per-user monitor with:"
                    echo "        oh-my-safety install-agent"
                else
                    echo "    Start the packaged user service with:"
                    echo "        systemctl --user enable --now oh-my-safety.service"
                fi
                ;;
            *)
                echo "    Run in the foreground with: oh-my-safety monitor --quiet"
                ;;
        esac
    fi

    # Full Disk Access (macOS)
    [[ "$platform" == "macos" ]] && _doctor_fda
    [[ "$platform" == "linux" || "$platform" == "wsl" ]] && _doctor_linux

    # Optional tools
    _doctor_tools "$platform"

    if command -v oh-my-safety-agent >/dev/null 2>&1 || [[ -x "$OMS_ROOT/bin/oh-my-safety-agent" ]]; then
        print_check_result pass "Portable journal/scanner core installed"
    else
        print_check_result info "Portable agent core not installed (Bash compatibility runtime remains active)"
    fi

    # Notification smoke test
    echo ""
    echo "Sending a test notification..."
    notify "oh-my-safety" "Doctor test — if you can read this, notifications work." ""
    case "$platform" in
        macos)
            echo "If you saw nothing: System Settings › Notifications (allow 'Script Editor'),"
            echo "or install terminal-notifier for a dedicated notification identity."
            ;;
        linux|wsl)
            echo "If you saw nothing, install libnotify/notify-send and verify the user"
            echo "service has access to the desktop notification bus."
            ;;
    esac

    # Endpoint policy
    _doctor_endpoints
}

_doctor_fda() {
    echo ""
    if oms_has_fda 2>/dev/null; then
        print_check_result pass "Full Disk Access available (TCC audit + protected-folder scans enabled)"
    else
        print_check_result warn "Full Disk Access NOT granted for this context"
        echo "    Effect: TCC audit and protected-folder scans are skipped."
        echo "    Option A (recommended): run deep scans from an FDA-granted terminal:"
        echo "        oh-my-safety scan --deep"
        echo "    Option B: grant FDA to /bin/bash for background agent coverage"
        echo "        (WARNING: this grants Full Disk Access to ALL bash scripts on this Mac)"
        echo "    Open the settings pane with:"
        echo "        open 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'"
    fi
}

_doctor_linux() {
    echo ""
    echo "Linux runtime capabilities:"
    local tool
    for tool in ip ss stat sha256sum systemctl; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_check_result pass "$tool available"
        else
            print_check_result warn "$tool missing (one or more checks will have limited coverage)"
        fi
    done
    if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
        print_check_result pass "HTTPS client available"
    else
        print_check_result warn "curl/wget missing (connected privacy checks cannot run)"
    fi
}

_doctor_tools() {
    local platform="${1:-$(detect_platform)}"
    echo ""
    echo "Optional integrations (used only if enabled in config AND installed):"
    local t
    for t in gitleaks trufflehog yara; do
        if command -v "$t" >/dev/null 2>&1; then
            print_check_result pass "$t installed"
        else
            print_check_result info "$t not installed"
        fi
    done
    if [[ "$platform" == "macos" ]]; then
        command -v terminal-notifier >/dev/null 2>&1 &&
            print_check_result pass "terminal-notifier installed" ||
            print_check_result info "terminal-notifier not installed"
    elif [[ "$platform" == "linux" || "$platform" == "wsl" ]]; then
        command -v notify-send >/dev/null 2>&1 &&
            print_check_result pass "notify-send installed" ||
            print_check_result info "notify-send not installed"
    fi
}

_doctor_endpoints() {
    echo ""
    print_header "Network policy"
    echo "Core security checks make ZERO network calls. Connected privacy checks may use:"
    echo "  - ifconfig.me / api.ipify.org / icanhazip.com   public IP"
    echo "  - api64.ipify.org                                IPv6 leak test"
    echo "  - ns1.google.com (TXT o-o.myaddr.l.google.com)   DNS resolver identity"
    echo ""
    echo "Optional external notification adapters are explicitly gated:"
    echo "  external enabled: $(config_get 'notifications.external.enabled' 'false')"
    echo "  active connectivity: $(config_get 'profile.connectivity' 'connected')"
    echo "Use 'oh-my-safety notifications show' for channel state."
    echo "There is no oh-my-safety telemetry or hosted collection endpoint."
    echo "See docs/privacy.md for every shipped endpoint and disclosed field."
}
