# Bounded built-in credential content scan

- **Check name:** `local-secret-scan`
- **Platforms:** macOS, Linux
- **Default:** off; enabled by strict workstation, developer,
  managed-workstation, and air-gapped high-assurance profiles
- **Network:** none
- **Scheduled interval:** 24 hours

This check uses the self-contained pure-Go portable core to inspect configured
local files for high-confidence credential formats, private-key blocks, and
secret-like assignments. It complements the lightweight permission/filename
`secrets-exposure` check and the optional gitleaks/trufflehog adapters.

The scanner is self-contained and bounded:

- symlinks, devices, binaries, and non-regular files are not followed;
- default limits cap file bytes, total bytes, depth, files, and findings;
- matched values never appear in JSON, status, history, or notifications;
- findings contain detector ID, local path, line, fixed redacted excerpt, and
  an HMAC fingerprint made with a random per-install mode-`600` key;
- reaching a bound is a visible coverage finding, not a clean result.

The scheduled monitor runs it only when `monitoring.deep` is true. A manual
`oh-my-safety scan` or `oh-my-safety secret-scan PATH` runs it explicitly.

## Configure roots

Without configured roots it checks existing `~/Projects`, `~/Developer`,
`~/code`, and `~/src` directories:

```yaml
checks:
  security:
    local_secret_scan:
      enabled: true
      scan_roots:
        - ~/Projects
        - ~/.config/my-service
```

Do not point it at `/`; the CLI refuses filesystem roots and enforces bounded
scope.

## Respond

Run the redacted local detail command:

```bash
oh-my-safety secret-scan ~/Projects
```

Confirm the credential type and file without copying the value into a ticket,
chat, shell history, or notification. Revoke or rotate it at the issuing
provider, remove it from the working tree and relevant history, invalidate
derived sessions, then recheck. A source-history rewrite does not revoke an
already copied credential.

False positives can be handled through the ordinary stable finding lifecycle,
but never allowlist a real live credential merely because it is inconvenient
to rotate.
