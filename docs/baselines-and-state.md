# Baselines & state

Some checks answer an absolute question ("is the firewall on?"). Others answer a
relative one: **"has anything changed since I last approved my machine's state?"**
That relative detection is what makes oh-my-safety a tripwire, and it's powered by
per-check *baselines*.

## Where state lives

Everything is local, under `${XDG_STATE_HOME:-~/.local/state}/oh-my-safety/`
(directory created mode `700`, files `600`):

```
baselines/<check>.tsv     approved snapshot of a check's "normal" state
pending/<check>.tsv       a drifted snapshot awaiting your `accept`
allowlist/<check>.list    finding-ids you chose to ignore (exact or glob)
notified/<check>.tsv      notification de-dupe bookkeeping
cache/codesign.tsv        cached code-signature verdicts (by path+inode+mtime)
last-scan.tsv             the most recent scan result (what `status` reads)
log/scan.log[.1-3]        rotated local log of non-ok findings
```

Writes are atomic (temp file + `mv`). Nothing here is ever transmitted.

## How drift detection works

1. **First run:** the check snapshots the current state (e.g. every LaunchAgent,
   every listening port) and saves it as the baseline — **quietly**, so you're not
   alarmed about things that were already there.
2. **Later runs:** it compares the current snapshot to the baseline. Anything new
   is a finding; anything removed is reported at info level. New items whose
   signature/location looks dangerous (e.g. an unsigned launchd program in a
   user-writable path) are escalated to critical.
3. When drift is found, the current snapshot is staged as `pending`.

## Approving changes

When a flagged change is legitimate (you installed an app, opened a dev port):

```bash
oh-my-safety accept persistence-scan     # promote the pending snapshot to the baseline
```

Now that state is the new "normal" and won't be flagged again. Related commands:

```bash
oh-my-safety baseline list               # baselines and entry counts
oh-my-safety baseline show <check>       # dump a baseline
oh-my-safety baseline reset <check>      # forget it; next scan re-snapshots quietly
```

## Ignoring individual findings

`accept` re-baselines everything; **`ignore`** targets one item you never want to
hear about again, by its stable finding-id:

```bash
oh-my-safety ignore network-exposure 'tcp|*|/opt/homebrew/bin/syncthing|wan'
oh-my-safety ignored network-exposure    # review what's ignored
```

Allowlist entries may be globs (e.g. `proc:$HOME/Projects/*`).

## Confirming a fix

After you address a finding, ask the checker to re-verify:

```bash
oh-my-safety recheck secrets-exposure
```

If it's gone, the check passes. This is the intended loop: **see it → fix or
accept it → confirm.**
