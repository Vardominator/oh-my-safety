#!/bin/bash
# oh-my-safety - local and opt-in external notification dispatch
#
# External channels are disabled by default. Secrets are read only from named
# environment variables or the strict per-user credential file, written to a
# mode-600 temporary curl config, and never included in logs or error messages.

[[ -n "${_OMS_NOTIFICATIONS_LOADED:-}" ]] && return 0
_OMS_NOTIFICATIONS_LOADED=1

_notification_credentials_path() {
    local path config_home
    path="$(config_get 'notifications.external.credentials_file' '')"
    if [[ -z "$path" ]]; then
        if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
            config_home="$XDG_CONFIG_HOME"
        elif [[ -n "${HOME:-}" ]]; then
            config_home="$HOME/.config"
        else
            return 1
        fi
        path="$config_home/oh-my-safety/notifications.env"
    fi
    case "$path" in
        "~"|"~/"*) [[ -n "${HOME:-}" ]] || return 1 ;;
    esac
    config_expand_path "$path"
}

_notification_credentials_secure() {
    local file="$1" stat_file stat_style metadata mode owner size rest permissions
    [[ -f "$file" && ! -L "$file" ]] || return 1
    stat_file="$file"
    case "$stat_file" in -*) stat_file="./$stat_file" ;; esac
    if metadata="$(stat -f '%Lp %u %z' "$stat_file" 2>/dev/null)"; then
        stat_style="bsd"
    elif metadata="$(stat -c '%a %u %s' "$stat_file" 2>/dev/null)"; then
        stat_style="gnu"
    else
        return 1
    fi
    size="${metadata##* }"
    rest="${metadata% *}"
    owner="${rest##* }"
    mode="${rest% *}"
    case "$owner" in ''|*[!0-9]*) return 1 ;; esac
    case "$size" in ''|*[!0-9]*) return 1 ;; esac
    [[ "$owner" == "$(id -u)" ]] || return 1
    [[ "${#size}" -le 6 && "$size" -le 65536 ]] || return 1
    case "$mode" in 400|600) : ;; *) return 1 ;; esac

    # Numeric modes alone do not expose a macOS extended ACL. Reject any ACL
    # rather than treating a nominal mode-600 file as private when a named
    # principal may still have access.
    if [[ "$stat_style" == "bsd" ]]; then
        permissions="$(LC_ALL=C ls -lde "$stat_file" 2>/dev/null)" || return 1
    else
        permissions="$(LC_ALL=C ls -ld "$stat_file" 2>/dev/null)" || return 1
    fi
    permissions="${permissions%% *}"
    case "$permissions" in *+*) return 1 ;; esac
    return 0
}

_notification_credentials_valid() {
    local file="$1"
    _notification_credentials_secure "$file" || return 1
    LC_ALL=C awk '
        /^[[:space:]]*($|#)/ { next }
        {
            if (index($0, "\r") != 0) exit 1
            separator = index($0, "=")
            if (separator == 0) exit 1
            key = substr($0, 1, separator - 1)
            if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/) exit 1
            if (++seen[key] != 1) exit 1
        }
    ' < "$file" >/dev/null
}

_notification_secret_from_file() {
    local name="$1" file value
    file="$(_notification_credentials_path)" || return 1
    _notification_credentials_secure "$file" || return 1
    value="$(LC_ALL=C awk -v wanted="$name" '
        /^[[:space:]]*($|#)/ { next }
        {
            if (index($0, "\r") != 0) {
                invalid = 1
                exit 1
            }
            separator = index($0, "=")
            if (separator == 0) {
                invalid = 1
                exit 1
            }
            key = substr($0, 1, separator - 1)
            if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || ++seen[key] != 1) {
                invalid = 1
                exit 1
            }
            if (key == wanted) {
                matches++
                value = substr($0, separator + 1)
            }
        }
        END {
            if (invalid || matches != 1) exit 1
            printf "%s", value
        }
    ' < "$file")" || return 1
    case "$value" in *$'\r'*|*$'\n'*) return 1 ;; esac
    printf '%s' "$value"
}

_notification_secret() {
    local name="$1" value
    case "$name" in ''|[0-9]*|*[!A-Za-z0-9_]*)
        return 1 ;;
    esac
    if value="$(printenv "$name" 2>/dev/null)"; then
        printf '%s' "$value"
        return 0
    fi
    _notification_secret_from_file "$name"
}

_notification_safe_endpoint() {
    case "$1" in
        https://*) return 0 ;;
        http://127.0.0.1:*|http://localhost:*)
            [[ "${OMS_NOTIFICATION_ALLOW_HTTP:-false}" == "true" ]]
            return ;;
        *) return 1 ;;
    esac
}

_notification_timeout() {
    local value
    value="$(config_get 'notifications.external.timeout_seconds' '10')"
    case "$value" in ''|*[!0-9]*) value=10 ;; esac
    [[ "${#value}" -le 3 ]] || value=10
    value="$(( 10#$value ))"
    [[ "$value" -ge 1 && "$value" -le 60 ]] || value=10
    printf '%s' "$value"
}

_notification_http_post() (
    local channel="$1" url="$2" authorization="$3" payload="$4"
    local cfg="" body="" err_file="" code rc timeout temp_dir
    trap 'rm -f "${cfg:-}" "${body:-}" "${err_file:-}"' EXIT
    trap 'exit 1' HUP INT TERM
    command_exists curl || return 1
    _notification_safe_endpoint "$url" || return 1
    case "$url$authorization" in
        *$'\t'*|*$'\n'*|*$'\r'*|*\"*|*\\*) return 1 ;;
    esac

    temp_dir="${TMPDIR:-/tmp}"
    case "$temp_dir" in /*) : ;; *) temp_dir="$PWD/$temp_dir" ;; esac
    cfg="$(mktemp "$temp_dir/oh-my-safety-curl.XXXXXX")" || return 1
    body="$(mktemp "$temp_dir/oh-my-safety-notification.XXXXXX")" || {
        rm -f "$cfg"
        return 1
    }
    err_file="$(mktemp "$temp_dir/oh-my-safety-curl-error.XXXXXX")" || {
        rm -f "$cfg" "$body"
        return 1
    }
    case "$cfg$body$err_file" in
        *$'\t'*|*$'\n'*|*$'\r'*|*\"*|*\\*)
            rm -f "$cfg" "$body" "$err_file"
            return 1 ;;
    esac
    if ! chmod 600 "$cfg" "$body" "$err_file" 2>/dev/null; then
        rm -f "$cfg" "$body" "$err_file"
        return 1
    fi
    if ! printf '%s' "$payload" > "$body"; then
        rm -f "$cfg" "$body" "$err_file"
        return 1
    fi
    timeout="$(_notification_timeout)"
    if ! {
        printf 'url = "%s"\n' "$url"
        printf 'request = "POST"\n'
        printf 'header = "Content-Type: application/json"\n'
        [[ -n "$authorization" ]] && printf 'header = "Authorization: %s"\n' "$authorization"
        printf 'data-binary = "@%s"\n' "$body"
        printf 'output = "/dev/null"\n'
        printf 'silent\nshow-error\n'
        printf 'connect-timeout = "%s"\nmax-time = "%s"\n' "$timeout" "$timeout"
        printf 'write-out = "%%{http_code}"\n'
    } > "$cfg"; then
        rm -f "$cfg" "$body" "$err_file"
        return 1
    fi

    # -q must be curl's first argument. It prevents ~/.curlrc from adding
    # redirects, verbose output, or another output destination for secrets.
    code="$(curl -q --config "$cfg" 2>"$err_file")"
    rc=$?
    rm -f "$cfg" "$body" "$err_file"
    if [[ "$rc" -ne 0 ]]; then
        event_append "notification.failed" "warn" "notifier" "$channel" \
            "transport error (credentials and response suppressed)" || true
        return 1
    fi
    case "$code" in
        2??)
            event_append "notification.delivered" "info" "notifier" "$channel" \
                "provider accepted notification" || true
            return 0 ;;
        *)
            event_append "notification.failed" "warn" "notifier" "$channel" \
                "provider returned HTTP ${code:-unknown}" || true
            return 1 ;;
    esac
)

_notification_message() {
    local message="$1"
    if config_enabled "notifications.external.include_details" "false"; then
        printf '%.2000s' "$message"
    else
        printf '%s' "A safety finding changed. Open oh-my-safety status locally for details."
    fi
}

_notification_title() {
    printf '%.200s' "$1"
}

_notification_channel_enabled() {
    config_enabled "notifications.channels.$1.enabled" "false"
}

_notification_discord() {
    local title="$1" message="$2" env_name url payload
    env_name="$(config_get 'notifications.channels.discord.webhook_url_env' 'OMS_DISCORD_WEBHOOK_URL')"
    url="$(_notification_secret "$env_name")"
    [[ -n "$url" ]] || return 1
    payload="$(printf '{"content":"**%s**\\n%s"}' \
        "$(json_escape "$(_notification_title "$title")")" "$(json_escape "$(_notification_message "$message")")")"
    _notification_http_post "discord" "$url" "" "$payload"
}

_notification_telegram() {
    local title="$1" message="$2" env_name token chat_id base url payload
    env_name="$(config_get 'notifications.channels.telegram.bot_token_env' 'OMS_TELEGRAM_BOT_TOKEN')"
    token="$(_notification_secret "$env_name")"
    chat_id="$(config_get 'notifications.channels.telegram.chat_id' '')"
    base="$(config_get 'notifications.channels.telegram.api_base' 'https://api.telegram.org')"
    [[ -n "$token" && -n "$chat_id" ]] || return 1
    case "$token" in *[/[:space:]\"]*) return 1 ;; esac
    url="${base%/}/bot${token}/sendMessage"
    payload="$(printf '{"chat_id":"%s","text":"%s\\n%s","disable_web_page_preview":true}' \
        "$(json_escape "$chat_id")" "$(json_escape "$(_notification_title "$title")")" \
        "$(json_escape "$(_notification_message "$message")")")"
    _notification_http_post "telegram" "$url" "" "$payload"
}

_notification_sendgrid() {
    local title="$1" message="$2" env_name key from to endpoint payload
    env_name="$(config_get 'notifications.channels.sendgrid.api_key_env' 'SENDGRID_API_KEY')"
    key="$(_notification_secret "$env_name")"
    from="$(config_get 'notifications.channels.sendgrid.from' '')"
    to="$(config_get 'notifications.channels.sendgrid.to' '')"
    endpoint="$(config_get 'notifications.channels.sendgrid.endpoint' 'https://api.sendgrid.com/v3/mail/send')"
    [[ -n "$key" && -n "$from" && -n "$to" ]] || return 1
    case "$key" in *[$'\t\r\n\"']*) return 1 ;; esac
    payload="$(printf '{"personalizations":[{"to":[{"email":"%s"}]}],"from":{"email":"%s"},"subject":"%s","content":[{"type":"text/plain","value":"%s"}]}' \
        "$(json_escape "$to")" "$(json_escape "$from")" "$(json_escape "$(_notification_title "$title")")" \
        "$(json_escape "$(_notification_message "$message")")")"
    _notification_http_post "sendgrid" "$endpoint" "Bearer $key" "$payload"
}

_notification_whatsapp() {
    local title="$1" message="$2" env_name token phone_id to base version url payload
    env_name="$(config_get 'notifications.channels.whatsapp.access_token_env' 'OMS_WHATSAPP_ACCESS_TOKEN')"
    token="$(_notification_secret "$env_name")"
    phone_id="$(config_get 'notifications.channels.whatsapp.phone_number_id' '')"
    to="$(config_get 'notifications.channels.whatsapp.to' '')"
    version="$(config_get 'notifications.channels.whatsapp.graph_version' '')"
    base="$(config_get 'notifications.channels.whatsapp.api_base' 'https://graph.facebook.com')"
    [[ -n "$token" && -n "$phone_id" && -n "$to" && -n "$version" ]] || return 1
    case "$token" in *[$'\t\r\n\"']*) return 1 ;; esac
    case "$phone_id$version" in *[!A-Za-z0-9._-]*) return 1 ;; esac
    url="${base%/}/${version}/${phone_id}/messages"
    payload="$(printf '{"messaging_product":"whatsapp","to":"%s","type":"text","text":{"preview_url":false,"body":"%s\\n%s"}}' \
        "$(json_escape "$to")" "$(json_escape "$(_notification_title "$title")")" \
        "$(json_escape "$(_notification_message "$message")")")"
    _notification_http_post "whatsapp" "$url" "Bearer $token" "$payload"
}

_notification_webhook() {
    local title="$1" message="$2" env_name url bearer_env bearer auth payload
    env_name="$(config_get 'notifications.channels.webhook.url_env' 'OMS_WEBHOOK_URL')"
    bearer_env="$(config_get 'notifications.channels.webhook.bearer_token_env' '')"
    url="$(_notification_secret "$env_name")"
    [[ -n "$url" ]] || return 1
    auth=""
    if [[ -n "$bearer_env" ]]; then
        bearer="$(_notification_secret "$bearer_env")"
        [[ -n "$bearer" ]] || return 1
        case "$bearer" in *[$'\t\r\n\"']*) return 1 ;; esac
        auth="Bearer $bearer"
    fi
    payload="$(printf '{"schema":"io.oh-my-safety/notification","schema_version":1,"title":"%s","message":"%s"}' \
        "$(json_escape "$(_notification_title "$title")")" "$(json_escape "$(_notification_message "$message")")")"
    _notification_http_post "webhook" "$url" "$auth" "$payload"
}

_notifications_external_allowed() {
    config_enabled "notifications.external.enabled" "false" || return 1
    [[ "$(config_get 'profile.connectivity' 'connected')" == "connected" ]]
}

# Preserve the platform notification contract, then deliver to explicitly
# enabled network channels. Provider failures never make a safety check fail.
dispatch_notification() {
    local title="$1" message="$2" subtitle="${3:-}" channel
    if config_enabled "notifications.channels.desktop.enabled" "true"; then
        if type send_notification >/dev/null 2>&1; then
            send_notification "$title" "$message" "$subtitle" || true
        fi
    fi
    _notifications_external_allowed || return 0

    for channel in discord telegram sendgrid whatsapp webhook; do
        _notification_channel_enabled "$channel" || continue
        if ! "_notification_${channel}" "$title" "$message"; then
            log_warn "Notification channel '$channel' failed; see 'oh-my-safety history'"
        fi
    done
    return 0
}
