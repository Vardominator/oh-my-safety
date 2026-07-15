#!/bin/bash
# oh-my-safety installer (secondary install path).
# Prefer Homebrew:  brew install vardominator/oh-my-safety/oh-my-safety
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --with-agent     # also install the launchd agent
#   curl -fsSL .../install.sh | bash -s -- uninstall

set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

REPO_URL="https://github.com/Vardominator/oh-my-safety"
PREFIX="${OMS_INSTALL_PREFIX:-$HOME/.local}"
LIBDIR="$PREFIX/lib/oh-my-safety"
BINDIR="$PREFIX/bin"

install_tree() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    info "Downloading oh-my-safety..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "$REPO_URL.git" "$tmp/src" >/dev/null 2>&1
    elif command -v curl >/dev/null 2>&1; then
        mkdir -p "$tmp/src"
        curl -fsSL "$REPO_URL/archive/refs/heads/main.tar.gz" | tar xz -C "$tmp/src" --strip-components=1
    else
        error "Need git or curl to install."; exit 1
    fi

    info "Installing to $LIBDIR ..."
    rm -rf "$LIBDIR"
    mkdir -p "$LIBDIR" "$BINDIR"
    cp -R "$tmp/src/bin" "$tmp/src/lib" "$tmp/src/config" "$tmp/src/plugins" "$LIBDIR/"
    [ -d "$tmp/src/docs" ] && cp -R "$tmp/src/docs" "$LIBDIR/" || true
    chmod +x "$LIBDIR/bin/oh-my-safety"

    # Symlink into PATH; the entry script resolves its own root via the symlink.
    ln -sf "$LIBDIR/bin/oh-my-safety" "$BINDIR/oh-my-safety"
    ln -sf "$LIBDIR/bin/oh-my-privacy" "$BINDIR/oh-my-privacy"

    info "Installed. Binary: $BINDIR/oh-my-safety"
    case ":$PATH:" in
        *":$BINDIR:"*) : ;;
        *) warn "Add $BINDIR to your PATH:"; echo "    echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
    esac

    echo ""
    echo "Quick start:"
    echo "  oh-my-safety scan       # run all checks now"
    echo "  oh-my-safety status     # your current safety posture"
    echo "  oh-my-safety doctor     # setup & permissions"
    echo ""
    echo "Tip: 'brew install vardominator/oh-my-safety/oh-my-safety' is the recommended install."
}

uninstall() {
    info "Uninstalling oh-my-safety..."
    "$BINDIR/oh-my-safety" uninstall-agent >/dev/null 2>&1 || true
    local p
    for p in \
        "$HOME/.local/bin/oh-my-safety" "$HOME/.local/bin/oh-my-privacy" \
        "$HOME/.local/lib/oh-my-safety" \
        "/usr/local/bin/oh-my-safety" "/usr/local/bin/oh-my-privacy" \
        "/usr/local/lib/oh-my-safety" \
        "/usr/local/bin/oh-my-privacy" "/usr/local/lib/oh-my-privacy" \
        "$HOME/.local/bin/oh-my-privacy" "$HOME/.local/lib/oh-my-privacy"; do
        [ -e "$p" ] && { rm -rf "$p"; info "Removed: $p"; }
    done
    echo "Config (~/.config/oh-my-safety) and state (~/.local/state/oh-my-safety) were preserved."
}

main() {
    local with_agent=0 action="install"
    for a in "$@"; do
        case "$a" in
            --with-agent) with_agent=1 ;;
            uninstall) action="uninstall" ;;
            install) action="install" ;;
        esac
    done

    echo "oh-my-safety installer"
    case "$action" in
        install)
            install_tree
            if [ "$with_agent" -eq 1 ]; then
                info "Installing launchd monitoring agent..."
                "$BINDIR/oh-my-safety" install-agent || warn "Agent install failed; run 'oh-my-safety install-agent' manually."
            fi
            ;;
        uninstall) uninstall ;;
    esac
}

main "$@"
