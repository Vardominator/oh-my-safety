# Local history and finding lifecycle

The `history` command and portable SQLite journal are available in v0.3.0. The
v0.2.3 compatibility line stores current scan state but does not expose this
durable event interface.

`status` is the current posture. `history` is the durable local timeline of how
that posture changed:

```bash
oh-my-safety history
oh-my-safety history --limit 25
oh-my-safety history --json
oh-my-safety history --format tsv
```

The compatibility runtime stores append-only event rows at:

```text
${XDG_STATE_HOME:-~/.local/state}/oh-my-safety/log/events.tsv
```

It records:

- every completed scan and its counts;
- pass, skip, warning, critical, and execution-error results;
- finding resolution;
- accepted or failed notification delivery metadata.

Credential values and provider response bodies are never event fields. Check
summaries are local but may still contain usernames or paths, so the state
directory is mode `700` and the history file is mode `600`.

The log uses `logging.max_size_kb` and `logging.keep_rotations`. The reader
includes rotated files, newest event first.

## Portable SQLite journal

Linux packages also install `oh-my-safety-agent`, the migration-compatible Go
core. Its SQLite journal is:

```text
${XDG_STATE_HOME:-~/.local/state}/oh-my-safety/journal.db
```

The database has database-enforced append-only event rows and a replayable
current-finding projection. After every persisted scan, the compatibility
runtime passes the versioned scan TSV to the Go core. Ingestion is deterministic
and idempotent: retrying the same snapshot does not duplicate events, `skip`
does not resolve an existing finding, and an `ok` result does. If the portable
core is missing or rejects a snapshot, the scan itself remains valid, the TSV
posture stays authoritative, and a local `journal.ingest_failed` event records
the coverage gap.

The compatibility history and portable journal can be inspected independently:

```bash
oh-my-safety history
oh-my-safety-agent --history --limit 100
oh-my-safety-agent --findings --limit 100
```

Both formats are versioned so migration never requires parsing
human-readable output.

Do not edit either history to clear a finding. Fix and recheck it, suppress the
specific stable finding ID, or approve an expected baseline through the CLI.
