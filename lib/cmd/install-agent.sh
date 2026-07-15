#!/bin/bash
# oh-my-safety - launchd agent management for non-Homebrew installs.
# (Homebrew users should prefer `brew services start oh-my-safety`.)

_OMS_AGENT_LABEL="com.vardominator.oh-my-safety"
_agent_plist_path() { echo "$HOME/Library/LaunchAgents/${_OMS_AGENT_LABEL}.plist"; }

cmd_install_agent() {
    if [[ "$(detect_platform)" != "macos" ]]; then
        log_error "install-agent is macOS-only"
        return 1
    fi
    if launchctl list 2>/dev/null | grep -q 'homebrew.mxcl.oh-my-safety'; then
        log_error "Already managed by Homebrew. Use: brew services {start|stop} oh-my-safety"
        return 1
    fi

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

cmd_uninstall_agent() {
    local plist
    plist="$(_agent_plist_path)"
    launchctl bootout "gui/$(id -u)/${_OMS_AGENT_LABEL}" 2>/dev/null || launchctl unload "$plist" 2>/dev/null || true
    rm -f "$plist"
    log_info "Monitoring agent removed: ${_OMS_AGENT_LABEL}"
}
