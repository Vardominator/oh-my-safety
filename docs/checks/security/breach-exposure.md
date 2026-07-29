# Opt-in monitored-account breach exposure

- **Check name:** `breach-exposure`
- **Platforms:** macOS, Linux
- **Default:** off
- **Network:** explicit HIBP breached-account API
- **Scheduled interval:** 24 hours

This optional check asks Have I Been Pwned whether explicitly configured email
addresses appear in known breach records. It is disabled by default because
the complete email address and request metadata are necessarily disclosed to
HIBP and the API requires a subscription key.

The core scanner and all ordinary security checks remain useful without this
adapter. Offline and air-gapped profiles block it before any request.

## Configure

Keep emails and the HIBP key out of YAML. Configure only their environment
variable names:

```yaml
checks:
  security:
    breach_exposure:
      enabled: true
      api_key_env: HIBP_API_KEY
      account_envs:
        - OMS_MONITORED_EMAIL
        - OMS_SECURITY_EMAIL
```

Then supply those values through the protected environment of the interactive
shell, launchd service, or systemd user service:

```bash
export HIBP_API_KEY='...'
export OMS_MONITORED_EMAIL='person@example.com'
oh-my-safety recheck breach-exposure
```

An interactive export reaches only commands launched from that shell; Homebrew
launchd and systemd services do not inherit it. For scheduled monitoring,
provision both variables in the service's environment using your operating
system or organization's secret-management process. The
`notifications.env` file is intentionally notification-only and is not read by
this check. If the service cannot receive these values securely, leave the
scheduled check disabled and use the explicit interactive lookup instead.

Interactive lookup and disclosure contract:

```bash
oh-my-safety exposure contracts
oh-my-safety exposure account --allow-network --email-env OMS_MONITORED_EMAIL
```

The status finding is intentionally generic and uses only the configured
environment-variable name as a stable item ID. It does not put the email,
breach titles, data classes, or provider body in scan history or external
notifications. The explicit interactive command returns breach metadata
locally for investigation.

## Respond

Treat a match as evidence that data associated with that account appeared in a
known incident, not proof that every current credential is compromised.
Privately review dates and data classes, change reused or affected passwords,
revoke sessions and API tokens, enable phishing-resistant MFA, inspect account
recovery methods and forwarding rules, and watch for targeted phishing.

A provider `not_found` result is not proof that an account is private. Breach
sources can be incomplete, delayed, or unable to include sensitive incidents.
