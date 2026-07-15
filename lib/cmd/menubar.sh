#!/bin/bash
# oh-my-safety - `menubar` subcommand: install the optional SwiftBar plugin.

cmd_menubar() {
    local sub="${1:-install}"
    case "$sub" in
        install)   _menubar_install ;;
        uninstall) _menubar_uninstall ;;
        *) echo "usage: oh-my-safety menubar {install|uninstall}"; return 1 ;;
    esac
}

_menubar_install() {
    local dest="$HOME/Library/Application Support/SwiftBar/Plugins"
    local src="$OMS_ROOT/plugins/swiftbar/oh-my-safety.30s.sh"

    if [[ ! -f "$src" ]]; then
        log_error "Plugin not found: $src"
        return 1
    fi
    if ! command -v swiftbar >/dev/null 2>&1 && [[ ! -d "/Applications/SwiftBar.app" ]]; then
        log_warn "SwiftBar not detected. Install it with: brew install --cask swiftbar"
    fi

    mkdir -p "$dest"
    cp "$src" "$dest/"
    chmod +x "$dest/oh-my-safety.30s.sh"
    log_info "Installed SwiftBar plugin: $dest/oh-my-safety.30s.sh"
    log_info "Open SwiftBar (or set its plugin folder to the path above) to see the menu bar icon."
}

_menubar_uninstall() {
    local f="$HOME/Library/Application Support/SwiftBar/Plugins/oh-my-safety.30s.sh"
    rm -f "$f"
    log_info "Removed SwiftBar plugin."
}
