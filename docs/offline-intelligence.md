# Signed offline intelligence

`oh-my-safety-intel` verifies and installs bounded intelligence bundles from
local files. It performs no network requests and never executes bundle content.
This is the update path for offline and air-gapped installations and a trust
boundary for future connected download adapters.

The v0.3.0 implementation provides signing, verification, rollback-safe
installation, and inspection. Individual endpoint detectors consume these
typed records only as their matching support is released; installing a bundle
by itself is not a malware block or vulnerability scan.

`oh-my-safety-intel` is included in v0.3.0 Homebrew and Linux packages. Source
installs build it when Go 1.26.5 or newer is available. The v0.2.3
compatibility line does not install it.

## Security model

A bundle is canonical, versioned JSON signed with Ed25519. Verification checks:

- a pinned key ID and public key from a mode-`600` trust store;
- signature and SHA-256 payload binding;
- exact canonical encoding and a closed schema;
- issue and expiry times plus minimum agent schema;
- total bytes, record count, per-record bytes, pattern bytes, and duplicates;
- sequence rollback and same-sequence content conflicts.

Installation writes an immutable content-addressed bundle first, fsyncs it, and
atomically replaces a small `current.json` pointer last. State directories must
be mode `700`; current, trust, private-key, and bundle files are mode `600`.

The schema has no command, script, action, argument, URL, replacement, or
filesystem-path field. Secret detector patterns use Go's bounded RE2 engine
and cannot carry executable code.

A valid signature proves that a pinned publisher produced the exact bytes. It
does not prove that the publisher's intelligence is correct. Review publisher
process, false-positive handling, key custody, and bundle provenance.

## Create publisher keys

Run key generation on the signing workstation, not on every endpoint:

```bash
umask 077
oh-my-safety-intel keygen \
  --key-id organization-intel-2026 \
  --private-key intel-signing-private.json \
  --trust-store intel-trust-store.json
```

Both outputs are regular mode-`600` files and existing paths are never
overwritten. The private-key file is protected by filesystem permissions but
is not passphrase-encrypted; keep it offline or in a protected signing system.
Distribute only `intel-trust-store.json` to endpoints through an authenticated
out-of-band process. `keygen` creates a new one-key trust store; key rotation
and adding keys to an existing store require a separately reviewed provisioning
procedure.

## Define and sign a bundle

An unsigned publisher input contains envelope metadata and declarative records:

```json
{
  "bundle_id": "organization-baseline",
  "sequence": 1,
  "issued_at": "2026-07-29T12:00:00Z",
  "expires_at": "2026-08-29T12:00:00Z",
  "minimum_agent_schema": 1,
  "records": [
    {
      "type": "malicious_sha256",
      "malicious_sha256": {
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    },
    {
      "type": "revoked_signer",
      "revoked_signer": {
        "kind": "team_id",
        "identifier": "ABCDE12345"
      }
    },
    {
      "type": "vulnerable_package",
      "vulnerable_package": {
        "ecosystem": "deb",
        "package": "example-package",
        "constraints": [
          {"operator": "lt", "version": "2.0.0"}
        ]
      }
    },
    {
      "type": "secret_detector_pattern",
      "secret_detector_pattern": {
        "detector_id": "organization-token",
        "pattern": "org_[A-Za-z0-9]{32}"
      }
    }
  ]
}
```

Sign to a new output path:

```bash
oh-my-safety-intel sign \
  --input unsigned-bundle.json \
  --private-key intel-signing-private.json \
  --output signed-bundle.json
```

The signer canonicalizes and orders records, computes the payload digest, and
refuses invalid, duplicate, oversized, or unknown executable fields. Input must
be a bounded regular non-symlink local file. The signed output is created at
mode `600`, and `sign` refuses to replace an existing output.

## Verify and install on an endpoint

Copy the signed bundle and pinned trust store to the endpoint. Verify without
changing installed state:

```bash
chmod 600 intel-trust-store.json
oh-my-safety-intel verify \
  --bundle signed-bundle.json \
  --trust-store intel-trust-store.json
```

All commands take explicit local paths: there is no URL fetch or stdin bundle
mode. Verification defaults to agent schema `1`, the current UTC time, and zero
clock skew. Use `--agent-schema`, `--at` (RFC 3339), or `--clock-skew` only when
the deployment policy requires an explicit override.

Install it into a private endpoint directory:

```bash
install -d -m 700 "${XDG_STATE_HOME:-$HOME/.local/state}/oh-my-safety/intel"
oh-my-safety-intel install \
  --bundle signed-bundle.json \
  --trust-store intel-trust-store.json \
  --dir "${XDG_STATE_HOME:-$HOME/.local/state}/oh-my-safety/intel"
```

Inspect and re-verify the installed current bundle:

```bash
oh-my-safety-intel current \
  --dir "${XDG_STATE_HOME:-$HOME/.local/state}/oh-my-safety/intel" \
  --trust-store intel-trust-store.json
```

Reinstalling identical sequence/content is an idempotent replay. A lower
sequence or different content at an accepted sequence fails. Old immutable
bundles are retained for audit; garbage collection is not yet automatic.

Use one updater process per intelligence directory. The library serializes
writers in one process, but separate updater processes need an external
single-writer lock.

## Air-gapped procedure

For a high-assurance environment:

1. Pin the publisher trust store during system provisioning.
2. Sign on an isolated publishing system with a reviewed manifest.
3. Hash and inventory the transfer media and bundle out of band.
4. Verify on a staging endpoint with the production trust store.
5. Import to production and record bundle ID, sequence, digest, signer key ID,
   time, and operator in the site's audit system.
6. Test expiry and rollback rejection before relying on the process.

Never lower the sequence, extend expiry by editing JSON, or replace a trust
store merely to make a failed bundle install.
