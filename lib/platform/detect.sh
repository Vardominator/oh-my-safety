#!/bin/bash
# oh-my-safety - Platform detection utilities (canonical detect_platform)

[[ -n "${_OMS_DETECT_LOADED:-}" ]] && return 0
_OMS_DETECT_LOADED=1

# Detect the current platform
detect_platform() {
    case "$(uname -s)" in
        Darwin)
            echo "macos"
            ;;
        Linux)
            if grep -q Microsoft /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "linux"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "windows"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Check if running as root/admin
is_root() {
    [[ $EUID -eq 0 ]]
}

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Get package manager
get_package_manager() {
    local platform
    platform=$(detect_platform)

    case "$platform" in
        macos)
            if command_exists brew; then
                echo "brew"
            else
                echo "none"
            fi
            ;;
        linux|wsl)
            if command_exists apt-get; then
                echo "apt"
            elif command_exists dnf; then
                echo "dnf"
            elif command_exists yum; then
                echo "yum"
            elif command_exists pacman; then
                echo "pacman"
            elif command_exists apk; then
                echo "apk"
            else
                echo "none"
            fi
            ;;
        *)
            echo "none"
            ;;
    esac
}
