# network-exposure

Watches for new programs on your Mac that start listening for incoming network connections, and flags any that appear after a quiet baseline is recorded.

**Category:** security · **Default severity:** warn · **Platforms:** macos · **Runs every:** 60s (in the background agent)

## What it protects you from

A "listening" service is any program on your Mac that opens a network port and waits for something to connect to it. Legitimate software does this all the time (AirPlay, file sharing, dev servers, sync clients). But malware does it too:

- A **backdoor** or **remote-access trojan** opens a port so an attacker can reach into your machine from the network.
- **Infostealers and droppers** sometimes run a small local server to receive commands or hand off stolen data to another process.
- A program listening on a **WAN-reachable** address (not just localhost) can potentially be reached by anything on your Wi-Fi, your local network, or in some cases the wider internet.

The danger is that a new listener can appear silently the moment you run a bad installer or a compromised app updates itself. This check notices when something new starts listening that was not there before, so an unexplained open port gets in front of you instead of sitting quietly for months.

## How it works

The check makes **no network calls**. Everything it inspects is local system state.

- It runs `lsof -nP -iTCP -sTCP:LISTEN` to list every TCP socket currently in the LISTEN state. Because it runs **without sudo**, `lsof` only returns listeners owned by *your* user account, which is exactly the surface user-level malware runs in.
- For each listener it parses the local address (e.g. `*:8080`, `127.0.0.1:8080`, `[::1]:8080`) into a **port** and a **scope**:
  - `127.*`, `localhost`, and `[::1]` are treated as **loopback** (only reachable from your own machine).
  - Everything else is treated as **wan** (bound to a routable/all-interfaces address).
- It resolves the owning process to an executable path via `oms_proc_path` (backed by `ps -p <pid> -o comm=`).
- For each new listener it also computes:
  - a **code-signature verdict** (`oms_codesign_verdict`): `apple`, `dev:<TEAMID>`, `adhoc`, `unsigned`, or `missing`.
  - whether the executable lives in a **user-writable path** (`oms_is_user_writable_path`): `/tmp`, `/private/var/folders`, anywhere under your home folder, etc. — locations malware favors because they need no admin rights.
- **UDP** is inventory-only in this version. UDP endpoints are counted at debug level (and listed at info level only under `--deep`), and are **never baseline-flagged**.
- **Ephemeral ports** (>= 49152 by default) are folded down to `*` so that normal port churn from outbound-turned-listening sockets does not create an endless stream of "new" findings.

## What it flags (and how serious)

The check compares the current set of listeners against a saved baseline and only reasons about listeners that are **newly added**. Each new listener is evaluated as follows:

- **New WAN-reachable listener** → **warn** by default. It escalates to **critical** if the executable is `unsigned`/`adhoc` **or** lives in a user-writable path. Example line:
  `- NEW WAN-reachable TCP listener: /path/to/exe on port 8080 [sig: unsigned]   [id: tcp|8080|/path/to/exe|wan]`
- **New loopback listener that is unsigned/adhoc** → **warn**, regardless of configuration (an unsigned local server still deserves a look).
- **New loopback listener that is properly signed** → controlled by config (`loopback_new_listener`):
  - `info` (default): shown as informational and quietly folded into the baseline, not counted as a finding.
  - `warn`: reported as a warn finding.
  - `off`: ignored entirely.

When one or more findings are present, the overall check result is **critical** if any single finding is critical, otherwise **warn**, and the check returns failure. When nothing new is actionable, it reports **pass** ("No new network listeners since baseline").

## What's baselined

This check is **baseline-driven**.

- **First run**: it records every current TCP listener as a quiet baseline and flags nothing, reporting `pass` with a message like "Baseline recorded (N TCP listener(s)). New listeners will be flagged."
- **Later runs**: only listeners that are **new relative to the baseline** are evaluated. Removals and benign additions (loopback listeners handled at `info`/`off`) are absorbed back into the baseline automatically so they do not nag you every minute.
- When real findings exist, the current snapshot is **staged as pending** so you can promote it with `accept`.

Each baseline entry is also the check's **finding id**, using the stable, path-based (never pid-based) scheme:

```
tcp|<port_or_*>|<exe>|<scope>
```

where `port` is the listening port (or `*` for a folded ephemeral port), `exe` is the executable path, and `scope` is `wan` or `loopback`. Because the id equals the baseline entry, `accept` and allowlisting match cleanly across runs.

## Permissions

No special permissions are required — **no Full Disk Access and no TCC prompt**. The check deliberately runs `lsof` without sudo. The trade-off is that it only sees **your own user's** listeners; ports opened by root or other users are invisible to it (see Limitations). It does not self-skip; it simply reports on the surface it can see.

## Configuration

Config keys under `checks.security.network_exposure` in `~/.config/oh-my-privacy/config.yaml` (defaults from `config/default.yaml`):

- `enabled` — `true`
- `loopback_new_listener` — `info` (one of `info | warn | off`; how new signed loopback listeners are treated)
- `ephemeral_port_floor` — `49152` (ports at or above this are folded to `*`)

It also depends on the code-signature helper (`oms_codesign_verdict`) and the user-writable-path helper, both provided by the macOS platform layer; there are no `tools.*` keys specific to this check.

Enable or disable the whole check:

```
oh-my-safety disable network-exposure
oh-my-safety enable  network-exposure
```

## Handling findings

When a new listener is flagged, identify the program (the `exe` path in the finding) and decide whether you started it.

1. **If it is malicious or unwanted**: quit/remove the program so the port closes, then confirm with:
   `oh-my-safety recheck network-exposure`
2. **If it is a specific listener you trust** (e.g. your own dev server): permanently accept just that item using its id:
   `oh-my-safety ignore network-exposure 'tcp|8080|/path/to/exe|wan'`
   (Copy the exact id from the `[id: ...]` field in the finding.)
3. **If everything currently listening is expected** and you want the whole current state to become the new normal:
   `oh-my-safety accept network-exposure`
   This promotes the staged snapshot to the baseline, so today's listeners stop being flagged while future new ones still will.

## Limitations

- **User-scope only**: because `lsof` runs without sudo, listeners opened by `root` or other users are invisible. Root-level malware can open a backdoor this check will never see. Like all userspace checks, it can be bypassed by anything running with root privileges.
- **TCP only for flagging**: UDP is inventory-only and is never flagged in this version, so UDP-based services and beacons are not caught here.
- **Ephemeral ports are blurred**: ports at or above `ephemeral_port_floor` are collapsed to `*`, so it does not distinguish individual high-numbered ports — useful for reducing noise, but it means a specific high port is not pinpointed.
- **Signature verdict is a heuristic**: `unsigned`/`adhoc` raises severity, but plenty of legitimate developer tools and locally built binaries are unsigned, so a critical rating is not proof of malware — it is a prompt to investigate.
- **Point-in-time snapshot**: a listener that opens and closes entirely between two runs (inside the 60s window) can be missed.
- **Baseline trust**: if the machine is already compromised on the very first run, that malicious listener gets recorded into the baseline as "normal" and will not be flagged later.
