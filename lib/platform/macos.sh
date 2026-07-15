#!/bin/bash
# oh-my-safety - macOS platform module
# Implements the shared platform accessor interface plus macOS-specific
# security helpers (oms_* functions) used by the security checks.

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

# Prefer terminal-notifier (its own signed notification identity) when present;
# otherwise fall back to osascript (attributed to "Script Editor").
send_notification() {
    local title="$1" message="$2" subtitle="${3:-}"

    if command -v terminal-notifier >/dev/null 2>&1; then
        if [[ -n "$subtitle" ]]; then
            terminal-notifier -title "$title" -subtitle "$subtitle" -message "$message" >/dev/null 2>&1 && return 0
        else
            terminal-notifier -title "$title" -message "$message" >/dev/null 2>&1 && return 0
        fi
    fi

    # Neutralize double quotes so they don't break the AppleScript string
    title="${title//\"/\'}"; message="${message//\"/\'}"; subtitle="${subtitle//\"/\'}"

    local sound_arg=""
    [[ "$(config_get 'notifications.sound' 'true')" == "true" ]] && sound_arg='sound name "Basso"'

    if [[ -n "$subtitle" ]]; then
        osascript -e "display notification \"$message\" with title \"$title\" subtitle \"$subtitle\" $sound_arg" 2>/dev/null
    else
        osascript -e "display notification \"$message\" with title \"$title\" $sound_arg" 2>/dev/null
    fi
}

send_alert() {
    local title="$1" message="$2"
    title="${title//\"/\'}"; message="${message//\"/\'}"
    osascript -e "display dialog \"$message\" with title \"$title\" with icon caution buttons {\"OK\"} default button \"OK\"" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Privacy accessors
# ---------------------------------------------------------------------------

get_public_ip() {
    local svc ip any=0
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        any=1
        ip="$(curl -s --max-time 10 "$svc" 2>/dev/null)"
        [[ -n "$ip" ]] && { printf '%s' "$ip"; return 0; }
    done < <(config_get_list 'checks.privacy.ip_address.services')

    [[ $any -eq 1 ]] && return 1
    curl -s --max-time 10 ifconfig.me 2>/dev/null || \
    curl -s --max-time 10 api.ipify.org 2>/dev/null || \
    curl -s --max-time 10 icanhazip.com 2>/dev/null
}

get_dns_resolver_ip() {
    nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | \
        grep "text =" | sed 's/.*"\(.*\)".*/\1/' | head -1
}

get_dns_servers() {
    scutil --dns 2>/dev/null | grep "nameserver\[[0-9]*\]" | sort -u | awk '{print $3}'
}

get_vpn_interfaces() {
    ifconfig 2>/dev/null | grep -E "^(utun|tun|ppp|ipsec|wg)" | cut -d: -f1
}

get_interface_ip() {
    ifconfig "$1" 2>/dev/null | grep "inet " | awk '{print $2}'
}

get_default_route_interface() {
    netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $NF}'
}

get_default_route_gateway() {
    netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $2}'
}

get_default_route() {
    netstat -rn 2>/dev/null | grep "^default" | head -1
}

is_vpn_interface() {
    local iface="$1" pat any=0
    [[ -z "$iface" ]] && return 1
    while IFS= read -r pat; do
        [[ -z "$pat" ]] && continue
        any=1
        # shellcheck disable=SC2254
        case "$iface" in $pat) return 0 ;; esac
    done < <(config_get_list 'checks.privacy.vpn_tunnel.interfaces')
    [[ $any -eq 1 ]] && return 1
    [[ "$iface" =~ ^(utun|tun|ppp|ipsec|wg) ]]
}

get_ipv6_address() {
    curl -s --max-time 5 https://api64.ipify.org 2>/dev/null
}

get_all_interfaces() {
    ifconfig -l 2>/dev/null
}

# ---------------------------------------------------------------------------
# Security helpers (used by lib/checks/security/*)
# ---------------------------------------------------------------------------

# True if this process can read the TCC database (i.e. has Full Disk Access).
oms_has_fda() {
    local db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    [[ -r "$db" ]] || return 1
    sqlite3 "file:${db}?immutable=1" 'SELECT 1 FROM access LIMIT 1;' >/dev/null 2>&1
}

# File metadata accessors (macOS stat)
oms_file_mode()  { stat -f '%Lp' "$1" 2>/dev/null; }
oms_file_mtime() { stat -f '%m'  "$1" 2>/dev/null; }
oms_file_size()  { stat -f '%z'  "$1" 2>/dev/null; }
oms_file_uid()   { stat -f '%u'  "$1" 2>/dev/null; }
oms_sha256()     { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

# Full executable path for a PID (empty if gone).
oms_proc_path() { ps -p "$1" -o comm= 2>/dev/null; }

# Extract the target program of a launchd plist (Program, else ProgramArguments[0]).
oms_plist_program() {
    local plist="$1" p
    p="$(plutil -extract Program raw -o - "$plist" 2>/dev/null)"
    [[ -n "$p" ]] && { printf '%s' "$p"; return 0; }
    p="$(plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null)"
    [[ -n "$p" ]] && { printf '%s' "$p"; return 0; }
    return 1
}

# True if a path lives in a user-writable location (malware-favored).
oms_is_user_writable_path() {
    case "$1" in
        /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/private/var/folders/*|"$HOME"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# True if a path lives inside a cloud-synced folder.
oms_in_cloud_path() {
    case "$1" in
        "$HOME/Library/Mobile Documents"/*|"$HOME/Library/CloudStorage"/*|"$HOME/Dropbox"/*|"$HOME/Google Drive"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Code-signature verdict for a binary, cached by path+inode+mtime.
# Echoes one of: apple | dev:<TEAMID> | adhoc | unsigned | missing
oms_codesign_verdict() {
    local path="$1"
    [[ -e "$path" ]] || { echo "missing"; return 0; }

    # SIP-sealed system locations: assume Apple, skip the codesign fork.
    case "$path" in
        /usr/local/*) : ;;  # user-installed; do verify
        /System/*|/usr/*|/bin/*|/sbin/*) echo "apple"; return 0 ;;
    esac

    local cache line inode mtime verdict
    cache="$(state_path 'cache/codesign.tsv')"
    inode="$(stat -f '%i' "$path" 2>/dev/null)"
    mtime="$(stat -f '%m' "$path" 2>/dev/null)"

    if [[ -f "$cache" ]]; then
        line="$(grep -F "$(printf '%s\t' "$path")" "$cache" 2>/dev/null | head -1 || true)"
        if [[ -n "$line" ]]; then
            local c_inode c_mtime
            c_inode="$(printf '%s' "$line" | awk -F'\t' '{print $2}')"
            c_mtime="$(printf '%s' "$line" | awk -F'\t' '{print $3}')"
            if [[ "$c_inode" == "$inode" && "$c_mtime" == "$mtime" ]]; then
                printf '%s' "$line" | awk -F'\t' '{print $4}'
                return 0
            fi
        fi
    fi

    verdict="$(_oms_codesign_compute "$path")"
    _oms_codesign_cache_put "$cache" "$path" "$inode" "$mtime" "$verdict"
    printf '%s' "$verdict"
}

_oms_codesign_compute() {
    local path="$1" out
    if ! out="$(codesign -dvv "$path" 2>&1)"; then
        echo "unsigned"; return 0
    fi
    printf '%s\n' "$out" | grep -q 'Authority=Software Signing' && { echo "apple"; return 0; }
    printf '%s\n' "$out" | grep -Eq 'Signature=adhoc|flags=0x2\(adhoc\)|adhoc' && { echo "adhoc"; return 0; }
    local team
    team="$(printf '%s\n' "$out" | sed -n 's/^TeamIdentifier=//p' | head -1)"
    if [[ -n "$team" && "$team" != "not set" ]]; then echo "dev:$team"; return 0; fi
    echo "apple"
}

_oms_codesign_cache_put() {
    local cache="$1" path="$2" inode="$3" mtime="$4" verdict="$5" tmp
    tmp="${cache}.tmp.$$"
    if [[ -f "$cache" ]]; then
        grep -vF "$(printf '%s\t' "$path")" "$cache" 2>/dev/null > "$tmp" || true
    else
        : > "$tmp"
    fi
    printf '%s\t%s\t%s\t%s\n' "$path" "$inode" "$mtime" "$verdict" >> "$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$cache"
}
