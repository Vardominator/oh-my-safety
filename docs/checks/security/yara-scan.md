# yara-scan

Scans your Downloads and temp folders with your own local YARA malware rules and flags any file that matches, so known malware can be caught before you run it.

**Category:** security · **Default severity:** critical · **Platforms:** macos · **Runs every:** 86400s (in the background agent)

## What it protects you from

Most malware that hits Mac users arrives as a download: a fake app installer, a cracked application, a "Flash update," or a booby-trapped DMG. Families like Atomic Stealer (AMOS) and other infostealers are frequently caught by pattern-based signatures because their code, strings, and packaging reuse recognizable fingerprints.

YARA is the industry-standard tool for exactly this: you write (or download) rules that describe what a malware family looks like — specific byte sequences, strings, or structural traits — and YARA tells you which files match. This check runs those rules against the folders where freshly-downloaded and temporary files land, so a known-bad file sitting in `~/Downloads` gets flagged as **critical** before you double-click it.

Signature scanning is a useful second opinion, but it only catches malware someone has already written a rule for. Treat a match as a strong danger signal, and treat a clean result as "no *known* signatures matched," not "definitely safe."

## How it works

This check is a thin, offline wrapper around the real `yara` binary. It never downloads rules and makes no network calls of any kind — you supply the rules yourself from a local directory.

For it to do anything, three things must be true:

1. `tools.yara.enabled` is `true` in your config, and the `yara` command is installed. If not, the check prints a skip and exits (the `optional_tool yara` gate).
2. `checks.security.yara_scan.rules_dir` points at a directory that exists on disk. If it is empty or missing, the check skips.
3. That directory contains rule files ending in `.yar` or `.yara`.

When those hold, it:

- Reads the list of scan targets from `checks.security.yara_scan.scan_paths` (default: `~/Downloads` and `/tmp`). A leading `~` is expanded to your home directory, and targets that don't exist are skipped.
- Loops over every `*.yar` and `*.yara` file in your rules directory.
- For each rule file and each existing target, runs:

      yara -r -w <rulefile> <target>

  `-r` scans directories recursively; `-w` suppresses YARA's own warnings. YARA's error output is discarded (`2>/dev/null`).
- If a rule produces any output (a match), the file is flagged **critical**, the raw match lines are printed indented for context, and a finding ID is emitted.

oh-my-safety deliberately does **not** fetch or update rules for you — downloading rules would break its no-network guarantee. Clone a rules repository yourself (for example a public YARA rules collection) and point `rules_dir` at it.

## What it flags (and how serious)

- **pass** — the scan ran and no rule matched any file in the scan paths. Summary: `clean`.
- **critical** — one or more files matched a rule. Each match is reported as:

      YARA match (<rulefile>.yar) in <target-path>
          <the matching rule name and details from yara>
        [id: yara:<rulefile>.yar]

  The overall result summarizes as `N YARA match(es)`.

There is no "warn" tier — a YARA match is always treated as critical, because rules describe known-bad files.

Note that matches are grouped by **rule file**, not by matched file: if several files match rules in `malware.yar`, they all share the finding ID `yara:malware.yar`.

## What's baselined

Nothing. This check has no baseline and no drift detection. Every run is a fresh scan and reports the current state of your scan paths. Because there is no baseline, `oh-my-safety accept yara-scan` does not apply here — use `ignore` (below) to suppress a specific rule file's matches.

## Permissions

The check itself requests no special permission and never self-skips on TCC grounds — it only skips when the tool is disabled/missing or `rules_dir` is unset.

However, the `yara` process can only match files it can actually read. On modern macOS, `~/Downloads` is a TCC-protected location, so the background agent (running under launchd) may need **Full Disk Access** to read files there. If the agent lacks that access, YARA's read errors are silently discarded (`2>/dev/null`) and those files simply won't be scanned — the check will report clean without ever having seen them. Grant Full Disk Access to the process that runs the agent if you rely on this check for `~/Downloads`. `/tmp` is generally readable without extra permission.

## Configuration

Under `checks.security.yara_scan`:

- `enabled` — default `false`. Off by default.
- `rules_dir` — default `""`. Path to a local directory of `.yar`/`.yara` rule files. `~` is expanded.
- `scan_paths` — default `~/Downloads` and `/tmp`. List of files or directories to scan; `~` is expanded and non-existent entries are skipped.

It also depends on the opt-in tool gate:

- `tools.yara.enabled` — default `false`. Must be `true` *and* `yara` must be installed for the check to run.

Enable or disable the check:

    oh-my-safety disable yara-scan
    oh-my-safety enable  yara-scan

(Remember that enabling the check is not enough on its own — you still need `tools.yara.enabled: true`, `yara` installed, and a valid `rules_dir`.)

## Handling findings

When you get a YARA match, treat it seriously:

1. Do not run or open the flagged file. Note its path from the finding.
2. Investigate — check the file against a reputable multi-engine scanner, confirm where it came from, and delete it if it is malware.
3. Once the file is gone (or you've resolved the issue), confirm with:

       oh-my-safety recheck yara-scan

If a match is a known false positive from a noisy rule and you want to stop hearing about that rule file:

- `oh-my-safety ignore yara-scan 'yara:<rulefile>.yar'` permanently accepts every match produced by that rule file. The finding ID is always `yara:` followed by the rule file's basename (for example `yara:apt_generic.yar`). Allowlist entries support shell globs, so `oh-my-safety ignore yara-scan 'yara:*'` would suppress all YARA matches — use that with care, since it effectively silences the whole check.

Because this check has no baseline, there is no `accept` workflow — use `ignore` for individual rule files.

## Limitations

- **Signature-only.** YARA catches what its rules describe. Brand-new or repacked malware with no matching rule will pass clean. A clean result means "no rules matched," not "safe."
- **You provide the rules.** With no rules, or stale rules, the check is only as good as the directory you point it at. oh-my-safety never updates them for you, so it is on you to keep a rules repo current.
- **Limited scope.** It only scans the configured `scan_paths` (Downloads and /tmp by default). Malware installed elsewhere — Applications, Library, or hidden locations — is out of scope unless you add those paths.
- **Silent read failures.** YARA errors are discarded, so unreadable files (permissions, TCC, locked files) are skipped without any warning, which can produce a false sense of "clean." See Permissions above.
- **Coarse suppression.** Ignoring a finding suppresses by rule file, not by individual file, so allowlisting a noisy rule also hides genuine future matches from that same rule.
- **Userspace only.** This runs as an ordinary user process. Malware with root or kernel-level access can hide files from it, tamper with the `yara` binary or its rules, or disable the agent entirely. A clean scan cannot rule out a compromise that already has elevated privileges.
