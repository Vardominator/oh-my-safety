#!/bin/bash
# oh-my-privacy - Core utilities
# This file provides shared functionality for the entire application

# Version
OMP_VERSION="0.1.0"

# Get the directory where oh-my-privacy is installed
OMP_ROOT="${OMP_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Colors for terminal output
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    BLUE=''
    BOLD=''
    NC=''
fi

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_debug() {
    if [[ "${OMP_VERBOSE:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
}

# Simple YAML parser (pure bash, no external dependencies)
# Supports basic key: value pairs and nested structures with indentation
# Usage: yaml_get "filename" "path.to.key"
yaml_get() {
    local file="$1"
    local key="$2"
    local value=""

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    # Convert dot notation to grep pattern
    # For nested keys like "checks.ip_address.enabled"
    local IFS='.'
    read -ra parts <<< "$key"

    local current_indent=0
    local found_path=""
    local in_section=true

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Calculate indentation
        local stripped="${line#"${line%%[![:space:]]*}"}"
        local indent=$(( (${#line} - ${#stripped}) / 2 ))

        # Extract key and value from line
        if [[ "$stripped" =~ ^([a-zA-Z0-9_-]+):[[:space:]]*(.*) ]]; then
            local line_key="${BASH_REMATCH[1]}"
            local line_value="${BASH_REMATCH[2]}"

            # Build current path based on indentation
            if [[ $indent -eq 0 ]]; then
                found_path="$line_key"
            elif [[ $indent -eq 1 ]]; then
                found_path="${found_path%%.*}.$line_key"
            elif [[ $indent -eq 2 ]]; then
                local base="${found_path%.*}"
                base="${base%.*}"
                found_path="$base.${found_path#*.}.$line_key"
                found_path="${found_path%%.*}.${found_path#*.*.}.$line_key" 2>/dev/null || found_path="$line_key"
            fi

            # Check if this matches our target key
            if [[ "$found_path" == "$key" ]] || [[ "$line_key" == "$key" && $indent -eq 0 ]]; then
                # Remove quotes if present
                line_value="${line_value#\"}"
                line_value="${line_value%\"}"
                line_value="${line_value#\'}"
                line_value="${line_value%\'}"
                echo "$line_value"
                return 0
            fi
        fi
    done < "$file"

    return 1
}

# Simpler approach: grep-based YAML getter for common patterns
config_get() {
    local key="$1"
    local default="$2"
    local config_file="${OMP_CONFIG_FILE:-}"

    # Try user config first, then default
    if [[ -z "$config_file" ]]; then
        if [[ -f "$HOME/.config/oh-my-privacy/config.yaml" ]]; then
            config_file="$HOME/.config/oh-my-privacy/config.yaml"
        elif [[ -f "$OMP_ROOT/config/default.yaml" ]]; then
            config_file="$OMP_ROOT/config/default.yaml"
        else
            echo "$default"
            return
        fi
    fi

    # Handle nested keys by searching for the leaf key with proper indentation
    local result=""
    local IFS='.'
    read -ra parts <<< "$key"
    # Get last element (bash 3.x compatible)
    local leaf_key="${parts[${#parts[@]}-1]}"

    # Simple grep for leaf key
    result=$(grep -E "^[[:space:]]*${leaf_key}:" "$config_file" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//' | sed 's/[[:space:]]*$//')

    # Clean up the value
    result="${result#\"}"
    result="${result%\"}"
    result="${result#\'}"
    result="${result%\'}"

    if [[ -n "$result" ]]; then
        echo "$result"
    else
        echo "$default"
    fi
}

# Check if a feature is enabled in config
config_enabled() {
    local key="$1"
    local value
    value=$(config_get "$key" "true")
    [[ "$value" == "true" || "$value" == "yes" || "$value" == "1" ]]
}

# Load configuration file
load_config() {
    local config_file="${1:-}"

    if [[ -n "$config_file" ]]; then
        if [[ ! -f "$config_file" ]]; then
            log_error "Config file not found: $config_file"
            return 1
        fi
        export OMP_CONFIG_FILE="$config_file"
    elif [[ -f "$HOME/.config/oh-my-privacy/config.yaml" ]]; then
        export OMP_CONFIG_FILE="$HOME/.config/oh-my-privacy/config.yaml"
    elif [[ -f "$OMP_ROOT/config/default.yaml" ]]; then
        export OMP_CONFIG_FILE="$OMP_ROOT/config/default.yaml"
    fi

    # Load settings into environment variables
    export OMP_CHECK_INTERVAL=$(config_get "check_interval" "60")
    export OMP_FAST_CHECK_INTERVAL=$(config_get "fast_check_interval" "5")
    export OMP_QUIET_MODE=$(config_get "quiet_mode" "false")
    export OMP_NOTIFICATIONS_ENABLED=$(config_get "enabled" "true")
    export OMP_NOTIFICATIONS_SOUND=$(config_get "sound" "true")

    log_debug "Loaded config from: ${OMP_CONFIG_FILE:-defaults}"
}

# Detect platform
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

# Load platform-specific functions
load_platform() {
    local platform
    platform=$(detect_platform)
    local platform_file="$OMP_ROOT/lib/platform/${platform}.sh"

    if [[ -f "$platform_file" ]]; then
        # shellcheck source=/dev/null
        source "$platform_file"
        log_debug "Loaded platform module: $platform"
    else
        log_warn "No platform module for: $platform (using fallback)"
        # Load fallback functions
        send_notification() {
            log_warn "Notifications not supported on this platform"
        }
        send_alert() {
            log_warn "Alerts not supported on this platform"
        }
    fi
}

# Generic notification dispatcher
notify() {
    local title="$1"
    local message="$2"
    local subtitle="${3:-}"

    if [[ "$(config_get 'notifications.enabled' 'true')" != "true" ]]; then
        return
    fi

    send_notification "$title" "$message" "$subtitle"
}

# Generic alert dispatcher (blocking dialog)
alert() {
    local title="$1"
    local message="$2"

    send_alert "$title" "$message"
}

# Print a horizontal separator
print_separator() {
    echo "=========================================="
}

# Print a section header
print_header() {
    local title="$1"
    print_separator
    echo -e "${BOLD}$title${NC}"
    print_separator
}

# Print check result
print_check_result() {
    local status="$1"  # pass, warn, fail
    local message="$2"

    case "$status" in
        pass)
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        warn)
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        fail)
            echo -e "${RED}❌ $message${NC}"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Get list of available checks
list_checks() {
    local checks_dir="$OMP_ROOT/lib/checks"

    if [[ -d "$checks_dir" ]]; then
        for check_file in "$checks_dir"/*.sh; do
            if [[ -f "$check_file" ]]; then
                local name
                name=$(basename "$check_file" .sh)
                echo "$name"
            fi
        done
    fi
}

# Run a specific check
run_check() {
    local check_name="$1"
    local check_file="$OMP_ROOT/lib/checks/${check_name}.sh"

    if [[ ! -f "$check_file" ]]; then
        log_error "Check not found: $check_name"
        return 1
    fi

    # Check if enabled in config
    local config_key="checks.${check_name//-/_}.enabled"
    if ! config_enabled "$config_key"; then
        log_debug "Check disabled: $check_name"
        return 0
    fi

    # Source and run the check
    # shellcheck source=/dev/null
    source "$check_file"

    # Each check file should define a run_check function
    if type "check_${check_name//-/_}" &>/dev/null; then
        "check_${check_name//-/_}"
    else
        log_error "Check function not found in: $check_name"
        return 1
    fi
}
