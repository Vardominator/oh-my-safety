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

# Resolve SwiftBar's configured plugin directory, falling back to the default.
_menubar_plugin_dir() {
    local dir
    dir="$(defaults read com.ameba.SwiftBar PluginDirectory 2>/dev/null)"
    if [[ -n "$dir" ]]; then
        printf '%s' "$dir"
    else
        printf '%s' "$HOME/Library/Application Support/SwiftBar/Plugins"
    fi
}

_menubar_install() {
    local src="$OMS_ROOT/plugins/swiftbar/oh-my-safety.30s.sh"
    if [[ ! -f "$src" ]]; then
        log_error "Plugin not found: $src"
        return 1
    fi
    if ! command -v swiftbar >/dev/null 2>&1 && [[ ! -d "/Applications/SwiftBar.app" ]]; then
        log_warn "SwiftBar not detected. Install it with: brew install --cask swiftbar"
    fi

    local dest pin pin_tmp
    dest="$(_menubar_plugin_dir)"
    mkdir -p "$dest"

    # Migrate: retire any old oh-my-privacy plugin in the same folder so it stops
    # rendering (renaming to .disabled makes SwiftBar ignore it; reversible).
    local old
    for old in "$dest"/oh-my-privacy*.sh; do
        [[ -e "$old" || -L "$old" ]] || continue
        mv -f "$old" "$old.disabled" 2>/dev/null && \
            log_info "Retired old plugin: $(basename "$old") (renamed to .disabled)"
    done

    case "$OMS_BIN" in
        *$'\n'*|*$'\r'*)
            log_error "Cannot pin SwiftBar to an executable path containing a newline"
            return 1
            ;;
        /*) : ;;
        *)
            log_error "Cannot pin SwiftBar to a non-absolute executable path: $OMS_BIN"
            return 1
            ;;
    esac
    if [[ ! -x "$OMS_BIN" ]]; then
        log_error "Cannot pin SwiftBar to a missing executable: $OMS_BIN"
        return 1
    fi

    cp "$src" "$dest/oh-my-safety.30s.sh" || {
        log_error "Failed to copy the SwiftBar plugin into: $dest"
        return 1
    }
    chmod +x "$dest/oh-my-safety.30s.sh" || return 1
    pin="$dest/.oh-my-safety-bin"
    pin_tmp="$(mktemp "$dest/.oh-my-safety-bin.XXXXXX")" || return 1
    chmod 600 "$pin_tmp"
    if ! printf '%s\n' "$OMS_BIN" > "$pin_tmp"; then
        rm -f "$pin_tmp"
        return 1
    fi
    if ! mv -f "$pin_tmp" "$pin"; then
        rm -f "$pin_tmp"
        return 1
    fi
    log_info "Installed SwiftBar plugin: $dest/oh-my-safety.30s.sh"
    log_info "Pinned SwiftBar to: $OMS_BIN"

    # Nudge SwiftBar to reload if it's running.
    if pgrep -x SwiftBar >/dev/null 2>&1; then
        open -g "swiftbar://refreshallplugins" 2>/dev/null || true
        log_info "Asked SwiftBar to reload plugins."
    else
        log_info "Open SwiftBar to see the menu-bar icon."
    fi
}

_menubar_uninstall() {
    local dest
    dest="$(_menubar_plugin_dir)"
    rm -f "$dest/oh-my-safety.30s.sh" "$dest/.oh-my-safety-bin"
    log_info "Removed SwiftBar plugin from: $dest"
}
