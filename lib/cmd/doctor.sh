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
        echo "    Start it with:  brew services start oh-my-safety"
        echo "    Or (non-brew):  oh-my-safety install-agent"
    fi

    # Full Disk Access (macOS)
    [[ "$platform" == "macos" ]] && _doctor_fda

    # Optional tools
    _doctor_tools

    # Notification smoke test
    echo ""
    echo "Sending a test notification..."
    notify "oh-my-safety" "Doctor test — if you can read this, notifications work." ""
    echo "If you saw nothing: System Settings › Notifications (allow 'Script Editor'),"
    echo "or install terminal-notifier for a dedicated notification identity."

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

_doctor_tools() {
    echo ""
    echo "Optional integrations (used only if enabled in config AND installed):"
    local t
    for t in terminal-notifier gitleaks trufflehog yara; do
        if command -v "$t" >/dev/null 2>&1; then
            print_check_result pass "$t installed"
        else
            print_check_result info "$t not installed"
        fi
    done
}

_doctor_endpoints() {
    echo ""
    print_header "Network policy"
    echo "Security checks make ZERO network calls. The only outbound requests are"
    echo "from privacy checks (disable any in config):"
    echo "  - ifconfig.me / api.ipify.org / icanhazip.com   public IP"
    echo "  - api64.ipify.org                                IPv6 leak test"
    echo "  - ns1.google.com (TXT o-o.myaddr.l.google.com)   DNS resolver identity"
    echo "Nothing is ever uploaded to any oh-my-safety server. See docs/privacy.md."
}
