#!/bin/bash
# oh-my-safety - Core utilities
# Shared functionality for the entire application. Sourced by the bin entry
# point; in turn sources the config, state, and allowlist libraries.

[[ -n "${_OMS_CORE_LOADED:-}" ]] && return 0
_OMS_CORE_LOADED=1

# Single source of truth for the version (CI enforces nothing else hardcodes it)
OMS_VERSION="0.3.0"

# Install root. Honors OMP_ROOT for backward compatibility.
OMS_ROOT="${OMS_ROOT:-${OMP_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}"
export OMS_ROOT

# Colors for terminal output (disabled when not a TTY)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; GRAY='\033[0;90m'
    BOLD='\033[1m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BLUE=''; CYAN=''; GRAY=''; BOLD=''; NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_debug() { [[ "${OMS_VERBOSE:-false}" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $*" >&2 || true; }

# Load the always-needed libraries
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/platform/detect.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/yaml.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/state.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/allowlist.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/events.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/managed.sh"
# shellcheck source=/dev/null
source "$OMS_ROOT/lib/notifications.sh"

# ISO-8601 UTC timestamp
iso_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# JSON-escape a string for embedding in generated JSON output.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

# Load platform-specific accessor functions. WSL reuses the Linux module.
load_platform() {
    local platform file
    platform="$(detect_platform)"
    export OMS_PLATFORM="$platform"
    file="$OMS_ROOT/lib/platform/${platform}.sh"
    [[ "$platform" == "wsl" ]] && file="$OMS_ROOT/lib/platform/linux.sh"

    if [[ -f "$file" ]]; then
        # shellcheck source=/dev/null
        source "$file"
        log_debug "Loaded platform module: $platform"
    else
        log_warn "No platform module for: $platform (using fallbacks)"
        send_notification() { log_warn "Notifications not supported on: $platform"; }
        send_alert() { log_warn "Alerts not supported on: $platform"; }
    fi
}

# Numeric rank for a severity level.
_sev_rank() {
    case "$1" in
        critical) echo 2 ;;
        warn)     echo 1 ;;
        *)        echo 0 ;;   # info
    esac
}

# Simple notification dispatcher (title, message, subtitle). Gated by config.
notify() {
    local title="$1" message="$2" subtitle="${3:-}"
    config_enabled "notifications.enabled" "true" || return 0
    dispatch_notification "$title" "$message" "$subtitle"
}

# Finding-aware notification with dedupe. Console output always; OS
# notification only when severity >= configured threshold and the finding
# hasn't already been notified within its re-notify window.
#   notify_finding <check> <severity> <finding_id> <title> <message>
#                  [console] [deliver]
notify_finding() {
    local check="$1" sev="$2" id="$3" title="$4" msg="$5"
    local console="${6:-true}" deliver="${7:-true}"
    OMS_NOTIFICATION_SENT=false

    if [[ "$console" == "true" ]]; then
        case "$sev" in
            critical) print_check_result critical "$msg" ;;
            warn)     print_check_result warn "$msg" ;;
            *)        print_check_result info "$msg" ;;
        esac
    fi

    config_enabled "notifications.enabled" "true" || return 0
    local minsev; minsev="$(config_get 'notifications.min_severity' 'warn')"
    [[ "$(_sev_rank "$sev")" -lt "$(_sev_rank "$minsev")" ]] && return 0

    local now last last_sev interval hours
    now="$(date +%s)"
    last="$(_notify_last_epoch "$check" "$id")"
    last_sev="$(_notify_last_severity "$check" "$id")"
    case "$last" in ''|*[!0-9]*) last="" ;; esac
    if [[ "$sev" == "critical" ]]; then
        hours="$(config_get 'notifications.renotify_interval_hours' '4')"
        case "$hours" in ''|*[!0-9]*) hours=4 ;; esac
        [[ "${#hours}" -le 6 ]] || hours=4
        hours="$(( 10#$hours ))"
        interval=$(( hours * 3600 ))
    else
        interval=$(( 24 * 3600 ))
    fi

    # Severity escalation is immediately actionable even if the ordinary
    # re-notify interval has not elapsed.
    if [[ -z "$last" ]] || \
       [[ "$(_sev_rank "$sev")" -gt "$(_sev_rank "$last_sev")" ]] || \
       [[ $(( now - last )) -ge $interval ]]; then
        if [[ "$deliver" == "true" ]]; then
            dispatch_notification "$title" "$msg" ""
            OMS_NOTIFICATION_SENT=true
        fi
        _notify_record "$check" "$id" "$sev" "$now"
    fi
}

# Blocking alert dialog
alert() {
    send_alert "$1" "$2"
}

print_separator() { echo "=========================================="; }

print_header() {
    print_separator
    echo -e "${BOLD}$1${NC}"
    print_separator
}

# Print a colored status line. Recognizes both the legacy privacy-check
# statuses (pass/warn/fail) and the framework statuses.
print_check_result() {
    local status="$1" message="$2"
    case "$status" in
        pass|ok)   echo -e "${GREEN}✅ $message${NC}" ;;
        info)      echo -e "${CYAN}ℹ️  $message${NC}" ;;
        warn)      echo -e "${YELLOW}⚠️  $message${NC}" ;;
        fail|critical) echo -e "${RED}❌ $message${NC}" ;;
        skip)      echo -e "${GRAY}⏭️  $message${NC}" ;;
        error)     echo -e "${RED}✗ $message${NC}" ;;
        *)         echo "$message" ;;
    esac
}
