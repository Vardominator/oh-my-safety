#!/bin/bash
# oh-my-safety - launchd/systemd user-agent management for non-Homebrew installs.
# Homebrew users should prefer `brew services start oh-my-safety`.

_OMS_AGENT_LABEL="com.vardominator.oh-my-safety"
_agent_plist_path() { echo "$HOME/Library/LaunchAgents/${_OMS_AGENT_LABEL}.plist"; }
_agent_systemd_path() { echo "$HOME/.config/systemd/user/oh-my-safety.service"; }

_agent_service_executable() {
    if [[ -n "${SNAP:-}" ]]; then
        local instance="${SNAP_INSTANCE_NAME:-oh-my-safety}"
        case "$instance" in
            ''|*[!a-z0-9_-]*) return 1 ;;
        esac
        printf '/snap/bin/%s' "$instance"
    else
        printf '%s' "$OMS_BIN"
    fi
}

cmd_install_agent() {
    case "$(detect_platform)" in
        macos) _install_launchd_agent ;;
        linux|wsl) _install_systemd_user_agent ;;
        *) log_error "install-agent is supported on macOS and systemd-based Linux"; return 1 ;;
    esac
}

_install_launchd_agent() {
    local loaded; loaded="$(launchctl list 2>/dev/null)"
    case "$loaded" in
        *homebrew.mxcl.oh-my-safety*)
            log_error "Already managed by Homebrew. Use: brew services {start|stop} oh-my-safety"
            return 1 ;;
    esac

    local plist logdir
    plist="$(_agent_plist_path)"
    logdir="$HOME/Library/Logs/oh-my-safety"
    mkdir -p "$HOME/Library/LaunchAgents" "$logdir"

    cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${_OMS_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${OMS_BIN}</string>
        <string>monitor</string>
        <string>--quiet</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ProcessType</key><string>Background</string>
    <key>ThrottleInterval</key><integer>30</integer>
    <key>StandardOutPath</key><string>${logdir}/agent.log</string>
    <key>StandardErrorPath</key><string>${logdir}/agent.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

    launchctl bootout "gui/$(id -u)/${_OMS_AGENT_LABEL}" 2>/dev/null || true
    if launchctl bootstrap "gui/$(id -u)" "$plist" 2>/dev/null || launchctl load "$plist" 2>/dev/null; then
        log_info "Monitoring agent installed and started: ${_OMS_AGENT_LABEL}"
        log_info "Logs: ${logdir}/agent.log"
        log_info "Check anytime with: oh-my-safety status"
    else
        log_error "Failed to load the launchd agent. Plist written to: $plist"
        return 1
    fi
}

_install_systemd_user_agent() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_error "systemd is not available; run 'oh-my-safety monitor --quiet' under your service manager"
        return 1
    fi
    if systemctl --user is-active --quiet snap.oh-my-safety.monitor.service 2>/dev/null; then
        log_error "A legacy Snap-managed monitor is still active"
        log_error "Stop it first with: snap stop --user oh-my-safety.monitor"
        return 1
    fi

    local unit service_bin escaped_bin
    unit="$(_agent_systemd_path)"
    service_bin="$(_agent_service_executable)" || {
        log_error "Unable to resolve a safe monitoring executable"
        return 1
    }

    # Distribution packages already install the user unit. Source/manual
    # installs receive a unit pointing at the exact current binary. A Snap
    # unit uses /snap/bin so it remains valid across package refreshes.
    if systemctl --user cat oh-my-safety.service >/dev/null 2>&1; then
        if [[ -n "${SNAP:-}" ]] &&
           ! systemctl --user cat oh-my-safety.service 2>/dev/null |
               grep -Fq "ExecStart=\"$service_bin\""; then
            log_error "A non-Snap oh-my-safety user service is already installed"
            log_error "Remove it before enabling monitoring from the Snap"
            return 1
        fi
    else
        mkdir -p "$(dirname "$unit")"
        escaped_bin="$(printf '%s' "$service_bin" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g')"
        {
            printf '%s\n' \
                '[Unit]' \
                'Description=oh-my-safety local safety monitor' \
                'After=network-online.target' \
                'Wants=network-online.target' \
                '' \
                '[Service]' \
                'Type=simple' \
                "ExecStart=\"$escaped_bin\" monitor --quiet" \
                'Restart=on-failure' \
                'RestartSec=10s' \
                'TimeoutStopSec=30s' \
                'KillSignal=SIGTERM' \
                'UMask=0077' \
                'NoNewPrivileges=true' \
                '' \
                '[Install]' \
                'WantedBy=default.target'
        } | _state_write_atomic "$unit"
    fi

    systemctl --user daemon-reload
    if systemctl --user enable --now oh-my-safety.service; then
        log_info "Monitoring agent installed and started with systemd --user"
        log_info "Logs: journalctl --user -u oh-my-safety.service"
        log_info "To keep it running after logout: sudo loginctl enable-linger $USER"
    else
        log_error "Failed to start the systemd user service"
        return 1
    fi
}

cmd_uninstall_agent() {
    case "$(detect_platform)" in
        macos) _uninstall_launchd_agent ;;
        linux|wsl) _uninstall_systemd_user_agent ;;
        *) log_error "uninstall-agent is supported on macOS and systemd-based Linux"; return 1 ;;
    esac
}

_uninstall_launchd_agent() {
    local plist
    plist="$(_agent_plist_path)"
    launchctl bootout "gui/$(id -u)/${_OMS_AGENT_LABEL}" 2>/dev/null || launchctl unload "$plist" 2>/dev/null || true
    rm -f "$plist"
    log_info "Monitoring agent removed: ${_OMS_AGENT_LABEL}"
}

_uninstall_systemd_user_agent() {
    local unit
    unit="$(_agent_systemd_path)"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now oh-my-safety.service >/dev/null 2>&1 || true
    fi
    if [[ -f "$unit" ]]; then
        rm -f "$unit"
        command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload
    fi
    log_info "Monitoring agent disabled for the current Linux user"
}
