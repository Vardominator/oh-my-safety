#!/bin/bash
# oh-my-safety - detects exposed secrets, credential files, and unprotected seed/password notes (metadata only, never reads contents)
CHECK_NAME="secrets-exposure"
CHECK_DESCRIPTION="Flags world-readable keys/credential files and credential-looking notes in unprotected locations"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="3600"
CHECK_DOC="docs/checks/security/secrets-exposure.md"

# --- permission helpers -----------------------------------------------------

# Normalize a file's mode to an octal string (falls back to stat if the
# helper returns something non-octal, e.g. a symbolic mode).
_secexp_mode_of() {
    local m
    m="$(oms_file_mode "$1" 2>/dev/null)"
    case "$m" in
        ''|*[!0-7]*) m="$(stat -f '%Lp' "$1" 2>/dev/null)" ;;
    esac
    printf '%s' "$m"
}

# Extract the owner/group/other octal triplet (last 3 octal digits).
_secexp_perm_triplet() {
    local d
    d="$(printf '%s' "$1" | tr -cd '0-7')"
    [ -z "$d" ] && return 0
    while [ "${#d}" -lt 3 ]; do d="0$d"; done
    printf '%s' "${d: -3}"
}

# rc 0 if group OR other has the read bit set.
_secexp_gor_readable() {
    local t g o
    t="$(_secexp_perm_triplet "$1")"
    [ -z "$t" ] && return 1
    g="${t:1:1}"; o="${t:2:1}"
    [ "$(( (g & 4) | (o & 4) ))" -ne 0 ]
}

# rc 0 if other (world) has the write bit set.
_secexp_other_writable() {
    local t o
    t="$(_secexp_perm_triplet "$1")"
    [ -z "$t" ] && return 1
    o="${t:2:1}"
    [ "$(( o & 2 ))" -ne 0 ]
}

# Accumulate a finding into the caller's (dynamically scoped) tally.
_secexp_bump() {
    _secexp_found=1
    _secexp_count=$(( _secexp_count + 1 ))
    if [ "$1" = "critical" ]; then
        _secexp_maxsev="critical"
    elif [ -z "$_secexp_maxsev" ]; then
        _secexp_maxsev="warn"
    fi
}

# Flag a single path on lax perms.
#   $1 path  $2 read-warn msg  $3 write-critical msg  $4 escalate(1/0)
_secexp_flag_perms() {
    local p="$1" read_msg="$2" write_msg="$3" escalate="$4"
    local id mode sev msg
    [ -e "$p" ] || return 0
    id="sec:$p:perms"
    allowlist_match "$CHECK_NAME" "$id" && return 0
    mode="$(_secexp_mode_of "$p")"
    [ -z "$mode" ] && return 0
    if [ "$escalate" = "1" ] && _secexp_other_writable "$mode"; then
        sev="critical"; msg="$write_msg"
    elif _secexp_gor_readable "$mode"; then
        sev="warn"; msg="$read_msg"
    else
        return 0
    fi
    _secexp_bump "$sev"
    print_check_result "$sev" "$msg (mode $mode)"
    echo "  - $p   [id: $id]"
}

# --- 1) ~/.ssh --------------------------------------------------------------

_secexp_ssh() {
    local sshdir="$HOME/.ssh"
    [ -d "$sshdir" ] || return 0

    local dmode dt id sev
    dmode="$(_secexp_mode_of "$sshdir")"
    dt="$(_secexp_perm_triplet "$dmode")"
    if [ -n "$dt" ] && [ "$dt" != "700" ]; then
        id="sec:ssh-dir:perms"
        if ! allowlist_match "$CHECK_NAME" "$id"; then
            sev="warn"
            _secexp_other_writable "$dmode" && sev="critical"
            _secexp_bump "$sev"
            print_check_result "$sev" "~/.ssh directory should be mode 700 (found $dmode)"
            echo "  - $sshdir   [id: $id]"
        fi
    fi

    local f base
    for f in "$sshdir"/* "$sshdir"/.*; do
        [ -f "$f" ] || continue
        base="${f##*/}"
        case "$base" in
            *.pub|*known_hosts*|config|authorized_keys|environment|.DS_Store|.|..) continue ;;
        esac
        _secexp_flag_perms "$f" \
            "SSH private key readable by others" \
            "SSH private key writable by others" "1"
    done

    _secexp_authkeys
}

# authorized_keys: tiny sha256 baseline; flag once per change.
_secexp_authkeys() {
    local ak="$HOME/.ssh/authorized_keys"
    [ -f "$ak" ] || return 0
    local bname="secrets-exposure-authkeys" sha line drift id
    sha="$(oms_sha256 "$ak" 2>/dev/null)"
    [ -z "$sha" ] && return 0
    line="authkeys|$sha"
    if ! baseline_exists "$bname"; then
        printf '%s\n' "$line" | baseline_save "$bname"
        return 0
    fi
    drift="$(printf '%s\n' "$line" | baseline_diff "$bname")" || true
    [ -z "$drift" ] && return 0
    id="sec:authorized_keys:changed"
    if ! allowlist_match "$CHECK_NAME" "$id"; then
        _secexp_bump "warn"
        print_check_result warn "~/.ssh/authorized_keys changed since baseline"
        echo "  - a new authorized SSH key was added — backdoor vector if not yours   [id: $id]"
    fi
    # Re-baseline so each distinct change is reported once, not forever.
    printf '%s\n' "$line" | baseline_save "$bname"
}

# --- 2) fixed credential files ---------------------------------------------

_secexp_credfiles() {
    local p
    for p in \
        "$HOME/.aws/credentials" \
        "$HOME/.aws/config" \
        "$HOME/.config/gcloud/legacy_credentials" \
        "$HOME/.config/gcloud/application_default_credentials.json" \
        "$HOME/.npmrc" \
        "$HOME/.pypirc" \
        "$HOME/.docker/config.json" \
        "$HOME/.kube/config"; do
        _secexp_flag_perms "$p" \
            "credential file readable by others" \
            "credential file writable by others" "1"
    done
    _secexp_netrc
}

# .netrc must be 600: any group/other access is a finding.
_secexp_netrc() {
    local p="$HOME/.netrc" id mode t g o sev
    [ -e "$p" ] || return 0
    id="sec:$p:perms"
    allowlist_match "$CHECK_NAME" "$id" && return 0
    mode="$(_secexp_mode_of "$p")"
    t="$(_secexp_perm_triplet "$mode")"
    [ -z "$t" ] && return 0
    g="${t:1:1}"; o="${t:2:1}"
    if _secexp_other_writable "$mode"; then
        sev="critical"
    elif [ "$g" != "0" ] || [ "$o" != "0" ]; then
        sev="warn"
    else
        return 0
    fi
    _secexp_bump "$sev"
    print_check_result "$sev" ".netrc must be mode 600 (found $mode)"
    echo "  - $p   [id: $id]"
}

# --- 3) shell histories -----------------------------------------------------

_secexp_histories() {
    local p
    for p in \
        "$HOME/.zsh_history" \
        "$HOME/.bash_history" \
        "$HOME/.python_history" \
        "$HOME/.psql_history" \
        "$HOME/.mysql_history" \
        "$HOME/.node_repl_history"; do
        _secexp_flag_perms "$p" \
            "shell history readable by others (may contain secrets)" \
            "shell history writable by others" "0"
    done
}

# --- 4) .env sweep ----------------------------------------------------------

_secexp_envfiles() {
    local depth root raw f mode count=0 found_list=""
    depth="$(config_get "checks.security.secrets_exposure.env_scan_depth" "3")"
    case "$depth" in
        ''|*[!0-9]*) depth=3 ;;
    esac

    for root in "$HOME/Projects" "$HOME/Developer" "$HOME/code" "$HOME/src" "$HOME/dev"; do
        [ -d "$root" ] || continue
        raw="$(find "$root" -maxdepth "$depth" \
            \( -name node_modules -o -name .git -o -name vendor \) -prune -o \
            -type f -name '.env*' ! -name '*.example' ! -name '*.sample' -print 2>/dev/null)"
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            [ -f "$f" ] || continue
            mode="$(_secexp_mode_of "$f")"
            _secexp_gor_readable "$mode" || continue
            found_list="$found_list$f
"
            count=$(( count + 1 ))
        done <<EOF
$raw
EOF
    done

    [ "$count" -eq 0 ] && return 0
    local id="sec:env-files"
    allowlist_match "$CHECK_NAME" "$id" && return 0

    _secexp_bump "warn"
    print_check_result warn "$count unprotected .env file(s) — group/other-readable"
    local shown=0 line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        shown=$(( shown + 1 ))
        [ "$shown" -gt 10 ] && break
        echo "  - $line   [id: $id]"
    done <<EOF
$found_list
EOF
    [ "$count" -gt 10 ] && echo "  ... and $(( count - 10 )) more"
}

# --- 5) filename scan (Spotlight, local; degrades on TCC/no index) ----------

# rc 0 if the extension is plaintext-ish (or none).
_secexp_ext_ok() {
    local base="${1##*/}" ext
    case "$base" in
        *.*) ext="${base##*.}" ;;
        *)   ext="" ;;
    esac
    ext="$(printf '%s' "$ext" | tr 'A-Z' 'a-z')"
    case "$ext" in
        ""|txt|md|rtf|csv|doc|docx|pages|numbers|xlsx) return 0 ;;
        *) return 1 ;;
    esac
}

_secexp_filename_scan() {
    config_enabled "checks.security.secrets_exposure.filename_scan" "true" || return 0
    command -v mdfind >/dev/null 2>&1 || return 0

    local q d out hit id limited=0
    q="kMDItemFSName == '*password*'cd"
    q="$q || kMDItemFSName == '*seed*phrase*'cd"
    q="$q || kMDItemFSName == '*mnemonic*'cd"
    q="$q || kMDItemFSName == '*recovery*phrase*'cd"
    q="$q || kMDItemFSName == '*private*key*'cd"
    q="$q || kMDItemFSName == '*2fa*'cd"

    for d in \
        "$HOME/Desktop" \
        "$HOME/Documents" \
        "$HOME/Downloads" \
        "$HOME/Library/Mobile Documents/com~apple~CloudDocs"; do
        [ -d "$d" ] || continue
        out="$(mdfind -onlyin "$d" "$q" 2>/dev/null)"
        if [ $? -ne 0 ]; then
            limited=1
            continue
        fi
        while IFS= read -r hit; do
            [ -z "$hit" ] && continue
            [ -f "$hit" ] || continue
            _secexp_ext_ok "$hit" || continue
            id="sec:file:$hit"
            allowlist_match "$CHECK_NAME" "$id" && continue
            _secexp_bump "warn"
            print_check_result warn "possible credential/seed note in an unprotected location"
            echo "  - $hit   [id: $id]"
        done <<EOF
$out
EOF
    done

    [ "$limited" -eq 1 ] && print_check_result info \
        "Filename scan was limited (Spotlight unavailable or a folder is not readable without Full Disk Access)"
    return 0
}

# --- entry point ------------------------------------------------------------

check_secrets_exposure() {
    local _secexp_found=0 _secexp_maxsev="" _secexp_count=0
    log_debug "secrets-exposure: metadata-only scan (no file contents read)"

    _secexp_ssh
    _secexp_credfiles
    _secexp_histories
    _secexp_envfiles
    _secexp_filename_scan

    if [ "$_secexp_found" -eq 1 ]; then
        [ -z "$_secexp_maxsev" ] && _secexp_maxsev="warn"
        CHECK_RESULT_SEVERITY="$_secexp_maxsev"
        CHECK_FINDING_SUMMARY="$_secexp_count secret/credential exposure finding(s)"
        return 1
    fi

    print_check_result pass "No exposed keys, credential files, or unprotected credential notes found"
    CHECK_FINDING_SUMMARY="no secret exposure detected"
    return 0
}
