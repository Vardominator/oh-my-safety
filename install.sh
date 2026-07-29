#!/bin/bash
# oh-my-safety installer (secondary install path).
# Prefer Homebrew:  brew install vardominator/oh-my-safety/oh-my-safety
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --with-agent     # also install the background agent
#   curl -fsSL .../install.sh | bash -s -- --version v0.3.0
#   curl -fsSL .../install.sh | bash -s -- --head           # explicit development build
#   curl -fsSL .../install.sh | bash -s -- uninstall

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

REPO_URL="https://github.com/Vardominator/oh-my-safety"
PREFIX="${OMS_INSTALL_PREFIX:-$HOME/.local}"
LIBDIR="$PREFIX/lib/oh-my-safety"
BINDIR="$PREFIX/bin"
INSTALL_TAG="${OMS_INSTALL_VERSION:-}"
INSTALL_HEAD=0
INSTALL_TMP=""

cleanup_install_tmp() {
    if [ -n "${INSTALL_TMP:-}" ] && [ -d "$INSTALL_TMP" ]; then
        rm -rf "$INSTALL_TMP"
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

resolve_latest_tag() {
    local effective
    effective="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest")" || return 1
    case "$effective" in
        */tag/v*) printf '%s' "${effective##*/}" ;;
        *) return 1 ;;
    esac
}

valid_release_tag() {
    printf '%s\n' "$1" |
        grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$'
}

install_tree() {
    local tmp tag archive checksums expected actual archive_name
    local platform_arch asset asset_archive asset_root source_version
    tmp="$(mktemp -d)"
    INSTALL_TMP="$tmp"
    trap cleanup_install_tmp EXIT

    if [ "$INSTALL_HEAD" -eq 1 ]; then
        command -v git >/dev/null 2>&1 || {
            error "A --head install requires git."
            exit 1
        }
        warn "Installing the mutable main branch without release verification."
        git clone --depth 1 "$REPO_URL.git" "$tmp/src" >/dev/null 2>&1
    else
        command -v curl >/dev/null 2>&1 || {
            error "curl is required for a verified release install."
            exit 1
        }
        tag="$INSTALL_TAG"
        [ -n "$tag" ] || tag="$(resolve_latest_tag)" || {
            error "Unable to resolve the latest GitHub release."
            exit 1
        }
        case "$tag" in v*) : ;; *) tag="v$tag" ;; esac
        if ! valid_release_tag "$tag"; then
            error "Invalid release version. Expected a tag such as v0.3.0."
            exit 2
        fi

        archive="$tmp/source.tar.gz"
        checksums="$tmp/checksums.txt"
        archive_name="oh-my-safety-${tag}.tar.gz"
        info "Downloading verified oh-my-safety release $tag..."
        curl -fsSL "$REPO_URL/archive/refs/tags/${tag}.tar.gz" -o "$archive"
        curl -fsSL "$REPO_URL/releases/download/${tag}/checksums.txt" -o "$checksums"
        expected="$(awk -v file="$archive_name" '$2==file {print $1; exit}' "$checksums")"
        actual="$(sha256_file "$archive")"
        if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
            error "Release checksum verification failed for $tag."
            exit 1
        fi
        mkdir -p "$tmp/src"
        tar xzf "$archive" -C "$tmp/src" --strip-components=1

        # Linux releases also carry a verified, pure-Go agent-core binary.
        # The Bash monitor remains fully functional when installing an older
        # release that predates this asset.
        if [ "$(uname -s)" = "Linux" ]; then
            case "$(uname -m)" in
                x86_64|amd64) platform_arch="amd64" ;;
                aarch64|arm64) platform_arch="arm64" ;;
                *) platform_arch="" ;;
            esac
            asset="oh-my-safety_${tag#v}_${platform_arch}.tar.gz"
            expected=""
            [ -n "$platform_arch" ] && \
                expected="$(awk -v file="$asset" '$2==file {print $1; exit}' "$checksums")"
            if [ -n "$expected" ]; then
                asset_archive="$tmp/$asset"
                info "Downloading verified Linux agent core ($platform_arch)..."
                curl -fsSL "$REPO_URL/releases/download/${tag}/${asset}" -o "$asset_archive"
                actual="$(sha256_file "$asset_archive")"
                if [ "$actual" != "$expected" ]; then
                    error "Release checksum verification failed for $asset."
                    exit 1
                fi
                asset_root="$tmp/linux-asset"
                mkdir -p "$asset_root"
                tar xzf "$asset_archive" -C "$asset_root" --strip-components=1
                if [ ! -x "$asset_root/bin/oh-my-safety-agent" ] ||
                   [ ! -x "$asset_root/bin/oh-my-safety-intel" ]; then
                    error "Verified Linux asset is missing a required portable command."
                    exit 1
                fi
                cp "$asset_root/bin/oh-my-safety-agent" "$tmp/src/bin/"
                cp "$asset_root/bin/oh-my-safety-intel" "$tmp/src/bin/"
            elif [ -f "$tmp/src/go.mod" ]; then
                warn "No prebuilt agent core is available for this Linux architecture; the Bash monitor will still run."
            fi
        fi
    fi

    # Source/HEAD installs can build the portable commands locally. Tagged
    # Linux releases normally reach this point with verified prebuilt binaries.
    if [ -f "$tmp/src/go.mod" ] && \
       { [ ! -x "$tmp/src/bin/oh-my-safety-agent" ] || \
         [ ! -x "$tmp/src/bin/oh-my-safety-intel" ]; }; then
        if command -v go >/dev/null 2>&1; then
            source_version="$(sed -n 's/^OMS_VERSION="\([^"]*\)".*/\1/p' "$tmp/src/lib/core.sh" | head -1)"
            info "Building the portable local-core commands..."
            (
                cd "$tmp/src"
                CGO_ENABLED=0 go build -trimpath \
                    -ldflags "-X main.agentVersion=${source_version:-development}" \
                    -o bin/oh-my-safety-agent ./cmd/oh-my-safety-agent
                CGO_ENABLED=0 go build -trimpath \
                    -o bin/oh-my-safety-intel ./cmd/oh-my-safety-intel
            )
        else
            warn "Go is not installed; installing the Bash compatibility runtime without portable-core commands."
        fi
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
    rm -f "$BINDIR/oh-my-safety-agent" "$BINDIR/oh-my-safety-intel"
    if [ -x "$LIBDIR/bin/oh-my-safety-agent" ]; then
        ln -sf "$LIBDIR/bin/oh-my-safety-agent" "$BINDIR/oh-my-safety-agent"
    fi
    if [ -x "$LIBDIR/bin/oh-my-safety-intel" ]; then
        ln -sf "$LIBDIR/bin/oh-my-safety-intel" "$BINDIR/oh-my-safety-intel"
    fi

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
        "$HOME/.local/bin/oh-my-safety-agent" \
        "$HOME/.local/bin/oh-my-safety-intel" \
        "$HOME/.local/lib/oh-my-safety" \
        "/usr/local/bin/oh-my-safety" "/usr/local/bin/oh-my-privacy" \
        "/usr/local/bin/oh-my-safety-agent" \
        "/usr/local/bin/oh-my-safety-intel" \
        "/usr/local/lib/oh-my-safety" \
        "/usr/local/bin/oh-my-privacy" "/usr/local/lib/oh-my-privacy" \
        "$HOME/.local/bin/oh-my-privacy" "$HOME/.local/lib/oh-my-privacy"; do
        { [ -e "$p" ] || [ -L "$p" ]; } && {
            rm -rf "$p"
            info "Removed: $p"
        }
    done
    echo "Config (~/.config/oh-my-safety) and state (~/.local/state/oh-my-safety) were preserved."
}

main() {
    local with_agent=0 action="install"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --with-agent) with_agent=1 ;;
            --head) INSTALL_HEAD=1 ;;
            --version)
                [ "$#" -ge 2 ] || { error "--version requires a release version"; exit 2; }
                INSTALL_TAG="$2"
                shift
                ;;
            uninstall) action="uninstall" ;;
            install) action="install" ;;
            *) error "Unknown installer option: $1"; exit 2 ;;
        esac
        shift
    done

    if [ "$INSTALL_HEAD" -eq 1 ] && [ -n "$INSTALL_TAG" ]; then
        error "--head and --version/OMS_INSTALL_VERSION are mutually exclusive."
        exit 2
    fi

    echo "oh-my-safety installer"
    case "$action" in
        install)
            install_tree
            if [ "$with_agent" -eq 1 ]; then
                info "Installing the background monitoring agent..."
                "$BINDIR/oh-my-safety" install-agent || warn "Agent install failed; run 'oh-my-safety install-agent' manually."
            fi
            ;;
        uninstall) uninstall ;;
    esac
}

main "$@"
