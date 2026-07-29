#!/bin/bash
# oh-my-safety - notification configuration visibility and test delivery

_notifications_show() {
    local channel state secret_name configured credentials_file credentials_state
    echo "External delivery: $(config_get 'notifications.external.enabled' 'false')"
    echo "Connectivity:      $(config_get 'profile.connectivity' 'connected')"
    echo "Include details:   $(config_get 'notifications.external.include_details' 'false')"
    credentials_file="$(_notification_credentials_path)" || credentials_file=""
    if [[ -z "$credentials_file" ]]; then
        credentials_state="unavailable (HOME and XDG_CONFIG_HOME are unset)"
    elif [[ ! -e "$credentials_file" && ! -L "$credentials_file" ]]; then
        credentials_state="not present"
    elif ! _notification_credentials_secure "$credentials_file"; then
        credentials_state="rejected (must be user-owned, non-symlink, mode 600/400, ACL-free, and at most 64 KiB)"
    elif _notification_credentials_valid "$credentials_file"; then
        credentials_state="secure and valid"
    else
        credentials_state="rejected (invalid or duplicate KEY=value rows)"
    fi
    echo "Credential file:   ${credentials_file:-<unresolved>} ($credentials_state)"
    printf '\n%-12s %-9s %s\n' "CHANNEL" "ENABLED" "CREDENTIAL"
    printf '%-12s %-9s %s\n' "desktop" \
        "$(config_get 'notifications.channels.desktop.enabled' 'true')" "local OS"
    for channel in discord telegram sendgrid whatsapp webhook; do
        state="$(config_get "notifications.channels.${channel}.enabled" 'false')"
        case "$channel" in
            discord) secret_name="$(config_get 'notifications.channels.discord.webhook_url_env' 'OMS_DISCORD_WEBHOOK_URL')" ;;
            telegram) secret_name="$(config_get 'notifications.channels.telegram.bot_token_env' 'OMS_TELEGRAM_BOT_TOKEN')" ;;
            sendgrid) secret_name="$(config_get 'notifications.channels.sendgrid.api_key_env' 'SENDGRID_API_KEY')" ;;
            whatsapp) secret_name="$(config_get 'notifications.channels.whatsapp.access_token_env' 'OMS_WHATSAPP_ACCESS_TOKEN')" ;;
            webhook) secret_name="$(config_get 'notifications.channels.webhook.url_env' 'OMS_WEBHOOK_URL')" ;;
        esac
        if [[ -n "$(_notification_secret "$secret_name")" ]]; then configured="available"; else configured="missing"; fi
        printf '%-12s %-9s %s (%s)\n' "$channel" "$state" "$secret_name" "$configured"
    done
}

cmd_notifications() {
    local action="${1:-show}"
    case "$action" in
        show|channels) _notifications_show ;;
        test)
            load_platform
            dispatch_notification "oh-my-safety test" \
                "Test notification from $(hostname 2>/dev/null || echo this-device)." ""
            echo "Notification test dispatched. Check local UI and enabled channels."
            ;;
        -h|--help|help)
            echo "usage: oh-my-safety notifications [show|test]"
            ;;
        *)
            log_error "Unknown notifications action: $action"
            echo "usage: oh-my-safety notifications [show|test]"
            return 1
            ;;
    esac
}
