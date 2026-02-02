#!/bin/bash
# oh-my-privacy installer
# Usage: curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/install.sh | bash

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
REPO_URL="https://github.com/Vardominator/oh-my-privacy"
INSTALL_DIR="${OMP_INSTALL_DIR:-/usr/local}"
CONFIG_DIR="${HOME}/.config/oh-my-privacy"

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)
            if grep -q Microsoft /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "linux"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

# Check if we have write permission
check_permissions() {
    local dir="$1"
    if [[ -w "$dir" ]]; then
        return 0
    elif [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Install from git clone
install_from_git() {
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    info "Downloading oh-my-privacy..."
    if command -v git &>/dev/null; then
        git clone --depth 1 "$REPO_URL.git" "$tmp_dir" 2>/dev/null
    elif command -v curl &>/dev/null; then
        curl -sL "${REPO_URL}/archive/main.tar.gz" | tar xz -C "$tmp_dir" --strip-components=1
    elif command -v wget &>/dev/null; then
        wget -qO- "${REPO_URL}/archive/main.tar.gz" | tar xz -C "$tmp_dir" --strip-components=1
    else
        error "Neither git, curl, nor wget found. Please install one of them."
        exit 1
    fi

    # Determine install location
    if ! check_permissions "$INSTALL_DIR"; then
        # Try user-local install
        INSTALL_DIR="${HOME}/.local"
        warn "No write permission to /usr/local, installing to ~/.local"
    fi

    local bin_dir="$INSTALL_DIR/bin"
    local lib_dir="$INSTALL_DIR/lib/oh-my-privacy"

    info "Installing to $INSTALL_DIR..."

    # Create directories
    mkdir -p "$bin_dir" "$lib_dir" "$CONFIG_DIR"

    # Copy files
    cp -r "$tmp_dir/lib/"* "$lib_dir/"
    cp -r "$tmp_dir/config/"* "$CONFIG_DIR/" 2>/dev/null || true

    # Create wrapper script that points to the lib directory
    cat > "$bin_dir/oh-my-privacy" << EOF
#!/bin/bash
export OMP_ROOT="$lib_dir/.."
exec "$lib_dir/../bin/oh-my-privacy" "\$@"
EOF

    # Actually copy the bin script
    mkdir -p "$INSTALL_DIR/bin"
    cp "$tmp_dir/bin/oh-my-privacy" "$bin_dir/oh-my-privacy"
    chmod +x "$bin_dir/oh-my-privacy"

    # Update OMP_ROOT in the installed script
    sed -i.bak "s|OMP_ROOT=\"\$(cd -P \"\$(dirname \"\$SCRIPT_PATH\")/..\" && pwd)\"|OMP_ROOT=\"$lib_dir/..\"|" "$bin_dir/oh-my-privacy" 2>/dev/null || \
    sed -i '' "s|OMP_ROOT=\"\$(cd -P \"\$(dirname \"\$SCRIPT_PATH\")/..\" && pwd)\"|OMP_ROOT=\"$lib_dir/..\"|" "$bin_dir/oh-my-privacy" 2>/dev/null || true
    rm -f "$bin_dir/oh-my-privacy.bak"

    # Create lib parent structure
    mkdir -p "$lib_dir/../bin" "$lib_dir/../config"
    cp "$tmp_dir/bin/oh-my-privacy" "$lib_dir/../bin/"
    chmod +x "$lib_dir/../bin/oh-my-privacy"
    cp -r "$tmp_dir/config/"* "$lib_dir/../config/" 2>/dev/null || true

    info "Installation complete!"
}

# Post-install instructions
post_install() {
    local bin_dir="$INSTALL_DIR/bin"
    local platform
    platform=$(detect_platform)

    echo ""
    echo "============================================"
    echo "  oh-my-privacy installed successfully!"
    echo "============================================"
    echo ""

    # Check if bin_dir is in PATH
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        warn "Add $bin_dir to your PATH:"
        echo ""
        case "$platform" in
            macos)
                echo "  echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.zshrc"
                echo "  source ~/.zshrc"
                ;;
            linux|wsl)
                echo "  echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.bashrc"
                echo "  source ~/.bashrc"
                ;;
        esac
        echo ""
    fi

    echo "Quick start:"
    echo "  oh-my-privacy --once     # Run a single privacy check"
    echo "  oh-my-privacy            # Start continuous monitoring"
    echo "  oh-my-privacy --help     # Show all options"
    echo ""
    echo "Configuration file: $CONFIG_DIR/default.yaml"
    echo "Documentation: $REPO_URL"
    echo ""
}

# Uninstall
uninstall() {
    info "Uninstalling oh-my-privacy..."

    local locations=(
        "/usr/local/bin/oh-my-privacy"
        "/usr/local/lib/oh-my-privacy"
        "${HOME}/.local/bin/oh-my-privacy"
        "${HOME}/.local/lib/oh-my-privacy"
    )

    for loc in "${locations[@]}"; do
        if [[ -e "$loc" ]]; then
            rm -rf "$loc"
            info "Removed: $loc"
        fi
    done

    echo ""
    echo "Note: Configuration at $CONFIG_DIR was preserved."
    echo "Remove it manually if desired: rm -rf $CONFIG_DIR"
}

# Main
main() {
    echo ""
    echo "oh-my-privacy installer"
    echo "======================="
    echo ""

    case "${1:-install}" in
        install)
            install_from_git
            post_install
            ;;
        uninstall)
            uninstall
            ;;
        *)
            echo "Usage: $0 [install|uninstall]"
            exit 1
            ;;
    esac
}

main "$@"
