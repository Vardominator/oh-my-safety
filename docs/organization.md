# Self-hosted organization controller

The optional organization controller turns standalone endpoints into a
redacted fleet-safety system without moving endpoint scanning into the cloud.
Employees keep the same local checks, history, notifications, and offline
behavior. The controller adds enrollment, signed declarative policy, fleet
inventory, current redacted findings, roles, and an administrative audit trail.

It is an early self-hosted control-plane release, not an MDM, remote shell,
remote attestation service, HA cluster, or replacement for EDR.

The controller and managed endpoint commands are included in v0.3.0. The
v0.2.3 compatibility line does not include them.

## Data boundary

An enrolled endpoint may send:

- a device identifier assigned at enrollment;
- the configured display name, platform, OS version, and agent version;
- heartbeat time;
- for each finding: detector ID, category, severity, lifecycle state, first and
  last observation time, and occurrence count.

The report schema cannot contain finding titles, summaries, evidence, labels,
paths, usernames, command lines, secret fingerprints, hostnames, or arbitrary
JSON payloads. Controller policies likewise cannot contain commands, scripts,
arguments, URLs, filesystem paths, or executable content.

If `--device-name` is omitted, enrollment uses the local hostname as the
display name. Supply an inventory ID or pseudonymous label explicitly when the
hostname itself is sensitive; the finding-report schema never adds a hostname
separately.

Endpoints initiate every connection. A controller cannot open a connection
back to an agent. Local protection continues if the controller is unavailable.

## Install the controller

Tagged releases attach pure-Go Linux archives for `amd64` and `arm64`:

```text
oh-my-safety-controller_VERSION_linux_amd64.tar.gz
oh-my-safety-controller_VERSION_linux_arm64.tar.gz
```

Verify the archive against the release `checksums.txt`, extract it, and place
`oh-my-safety-controller` in an administrator-only executable location. From a
source checkout:

```bash
make build-controller
./dist/oh-my-safety-controller -h
```

The SQLite database, administrator config, signing key, and TLS private key
are sensitive. Run the service under a dedicated unprivileged OS account and
keep its state in a private directory.

## Bootstrap once

Bootstrap creates a mode-`600` administrator config containing only a SHA-256
token digest and a persistent mode-`600` Ed25519 policy-signing key. It refuses
to overwrite the administrator config.

```bash
install -d -m 700 /var/lib/oh-my-safety-controller
umask 077
oh-my-safety-controller \
  -bootstrap \
  -admin-id security-admin \
  -admin-config /var/lib/oh-my-safety-controller/admins.json \
  -signing-key /var/lib/oh-my-safety-controller/signing.json \
  > /var/lib/oh-my-safety-controller/bootstrap.json
chmod 600 /var/lib/oh-my-safety-controller/bootstrap.json
```

`bootstrap.json` contains the administrator bearer token exactly once and the
public policy-verification key. Move the token into your secret manager, copy
the public key through an authenticated out-of-band channel to endpoint
configuration, then securely remove the bootstrap output. Losing the private
signing key invalidates policy continuity; leaking it lets an attacker sign
policy, so back it up separately from the database.

Additional administrators are configured as explicit `admin`, `operator`, or
`viewer` principal entries in `admins.json`, using SHA-256 token digests. Keep
the file a regular mode-`600` file; restart the service after editing it.
The closed file shape is:

```json
{
  "schema": "io.oh-my-safety/controller-admins",
  "schema_version": 1,
  "principals": [
    {
      "id": "security-admin",
      "role": "admin",
      "token_sha256": "64-lowercase-hex-characters"
    },
    {
      "id": "security-operator",
      "role": "operator",
      "token_sha256": "a-different-64-character-sha256-digest"
    }
  ]
}
```

Generate a separate cryptographically random bearer value for every principal,
store only its SHA-256 digest in this file, and deliver the original value once
through the secret manager. Never reuse the bootstrap token. The controller
rejects duplicate IDs or token digests, plaintext/invalid digests, unknown
fields, and a file with no administrator. This MVP has no live principal-edit
API, so make a protected backup, replace the file atomically, retain mode
`600`, and restart the service.

## Start the service

Loopback-only development or a same-host TLS reverse proxy:

```bash
oh-my-safety-controller \
  -listen 127.0.0.1:8443 \
  -db /var/lib/oh-my-safety-controller/controller.db \
  -admin-config /var/lib/oh-my-safety-controller/admins.json \
  -signing-key /var/lib/oh-my-safety-controller/signing.json
```

Any non-loopback listener is rejected unless a certificate and key are
provided:

```bash
oh-my-safety-controller \
  -listen 0.0.0.0:8443 \
  -tls-cert /etc/oh-my-safety-controller/tls.crt \
  -tls-key /etc/oh-my-safety-controller/tls.key \
  -db /var/lib/oh-my-safety-controller/controller.db \
  -admin-config /var/lib/oh-my-safety-controller/admins.json \
  -signing-key /var/lib/oh-my-safety-controller/signing.json
```

The built-in server enforces TLS 1.2 or newer, bounded headers and bodies,
read/write/idle timeouts, strict JSON, no-store responses, and graceful
shutdown. Put rate limiting and access-network policy in a reverse proxy or
firewall until native rate limiting ships.

Health check:

```bash
# Direct loopback development listener:
curl --fail --silent --show-error http://127.0.0.1:8443/healthz
# TLS production listener or reverse-proxy origin:
curl --fail --silent --show-error https://controller.example.test:8443/healthz
```

## Administrative workflow

Administrator APIs use:

```text
Authorization: Bearer ADMIN_TOKEN
Content-Type: application/json
```

Avoid putting bearer values directly in shell history or process arguments.
Use a mode-`600` curl config or an equivalent secret-aware API client.

Create a one-use enrollment token for the `engineering` group:

```http
POST /v1/admin/enrollment-tokens

{"group":"engineering","ttl_seconds":3600}
```

Create a command-free policy:

```http
POST /v1/admin/policies

{
  "schema": "io.oh-my-safety/organization-policy",
  "schema_version": 1,
  "id": "engineering-workstation",
  "revision": 1,
  "checks": [
    {"id": "hardening-posture", "enabled": true},
    {"id": "persistence-scan", "enabled": true},
    {"id": "secrets-exposure", "enabled": true}
  ],
  "profile": "managed-workstation",
  "cadence": {
    "scan_interval_seconds": 300,
    "jitter_seconds": 30
  },
  "reporting": {
    "enabled": true,
    "sync_interval_seconds": 300
  },
  "remediation": "observe"
}
```

Assign it to the group:

```http
PUT /v1/admin/groups/engineering/policy

{"policy_id":"engineering-workstation"}
```

Policy revisions must be positive and are explicitly updated. An endpoint
accepts a policy only after validating the closed schema, Ed25519 signature,
and out-of-band pinned public key.

## Enroll an endpoint

Send the employee or provisioning system these values through authenticated
channels:

- controller HTTPS origin;
- one-use enrollment token;
- signing public key from controller bootstrap;
- intended managed profile and device label.

On the endpoint, put the token in the named environment variable, never in a
command argument:

```bash
export OMS_ENROLLMENT_TOKEN='one-use-token'
oh-my-safety organization enroll \
  --url https://controller.example.test:8443 \
  --policy-key 'RAW_BASE64_ED25519_PUBLIC_KEY' \
  --device-name 'engineering-laptop-017' \
  --profile managed-workstation
unset OMS_ENROLLMENT_TOKEN
```

Enrollment requires `oh-my-safety-agent`, which Homebrew v0.3.0, a v0.3.0
Linux package, or a source install with Go 1.26.5 or newer provides. The
notification credential file is not consulted for enrollment tokens.

Enrollment atomically writes a regular mode-`600`
`managed-enrollment.json` beneath the endpoint state directory and enables the
selected managed profile. The state contains the device credential and pinned
public key; do not copy it into support tickets, backups shared across devices,
or another endpoint.

Run the first sync and inspect the verified policy:

```bash
oh-my-safety organization sync
oh-my-safety organization status
oh-my-safety organization policy
oh-my-safety status
```

Sync sends a heartbeat, fetches and verifies the signed policy, atomically
caches the full signed envelope, checks the persistent revision ledger for
rollback/equivocation, and sends the redacted current finding projection only
when reporting is enabled. Cached policy is reverified against the enrolled
pin on every read.

The background monitor performs managed sync at the signed reporting cadence
after local scan workers finish. A controller failure records a local coverage
event and deduplicated warning; it does not stop local scans or create a tight
retry loop. When policy reporting is disabled, the endpoint still heartbeats
and polls for a later policy at the local bootstrap sync interval, but the Go
client omits the posture report. Offline and air-gapped profiles block every
managed network request.

`jitter_seconds` is validated and retained in the signed policy for a future
deterministic early-staggering algorithm. v0.3.0 does not apply it: a positive
delay must never extend a policy's maximum scan or reporting interval.

Signed policy has highest precedence only for fields it explicitly controls:
the known profile, maximum scan interval for explicitly required checks,
reporting cadence, remediation intent, and listed per-check enable/disable
values. Unlisted checks keep their local settings. A policy cannot install a
new check or carry code. `safe-automatic` intent remains non-destructive until
the transactional remediation engine ships.

Rotate the device credential:

```bash
oh-my-safety organization rotate-credential
```

Pause synchronization and policy enforcement while retaining enrollment state:

```bash
oh-my-safety organization disable
```

The local user who owns the process and state can disable or remove the agent;
this MVP is visibility and signed configuration, not tamper-proof MDM. Use
existing device-management controls to require installation and service health.

## API and roles

| Role | Capabilities |
|------|--------------|
| `viewer` | list devices, redacted findings, and policies |
| `operator` | viewer rights plus enrollment tokens, policy CRUD, and device/group assignments |
| `admin` | operator rights plus device revocation and audit-history access |

Agent-authenticated endpoints support enrollment, heartbeat, signed-policy
fetch, redacted-report synchronization, and device-credential rotation.
Administrator routes support device inventory/grouping, finding inventory,
policy CRUD/assignment, and append-only audit reads.

All list APIs are bounded. Enrollment tokens are one-use and expire between one
minute and seven days. Device and administrator bearer values are stored as
SHA-256 digests and compared without early exit.

## Back up and operate

Back up these files while preserving owner and mode:

- `controller.db`;
- `admins.json`;
- `signing.json`;
- TLS key/certificate and the external secret-manager records.

Test restoring them to an isolated controller before relying on the backup.
Monitor `/healthz`, database filesystem capacity, TLS expiry, failed
authentication at the reverse proxy, stale device heartbeats, and endpoints
that stop reporting coverage.

Current production gaps are listed in the [roadmap](roadmap.md): HA and
replication, SSO/OIDC, native rate limiting, staged rollout acknowledgements,
unused-token revocation, mTLS/hardware identity, HSM signing, sealed off-host
audit checkpoints, and automated backup/restore are not yet implemented.
