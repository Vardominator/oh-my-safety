# wallet-guard

Inventories the crypto wallets on your Mac (desktop apps and browser extensions) and flags any whose data is readable by other users or is being synced to the cloud.

**Category:** security · **Default severity:** critical · **Platforms:** macOS · **Runs every:** 600s (in the background agent)

## What it protects you from

Crypto wallets are the single most valuable target on a Mac. If an attacker gets your wallet file or its seed phrase, your funds are gone with no bank, no chargeback, and no undo. Two everyday mistakes make this far too easy:

- **Wrong file permissions.** If your wallet's data files are readable by "group" or "other" (anyone else with an account on the machine, or any process running as another user), your seed material is exposed locally. Infostealer malware such as Atomic Stealer (AMOS) makes its money by scooping up exactly these wallet folders and browser-extension data stores and shipping them to a server. Loose permissions make that theft trivial.
- **Cloud-synced seeds.** If a wallet keeps its data in iCloud Drive, Dropbox, or Google Drive, your seed phrase now lives on someone else's servers. A phished or breached cloud account becomes a direct path to draining your wallet, and you may never see the login that did it.

This check does not move money or touch your keys. It just tells you when your wallets are sitting in a dangerous spot so you can lock them down before malware or a nosy account finds them.

## How it works

The check makes **no network calls**. Everything it inspects is local.

It works from two bundled lookup tables:

- `lib/data/wallets.tsv` - known desktop wallet data locations (Electrum, Exodus, Ledger Live, Atomic, Coinomi, Trezor Suite, Bitcoin Core, Sparrow, Wasabi, Monero, Daedalus). Each row is an id plus a path (a leading `~/` is expanded to your home folder, and paths with spaces are kept intact rather than glob-expanded).
- `lib/data/wallet-extensions.tsv` - known browser-wallet extension IDs (MetaMask, Phantom, Coinbase Wallet, Trust Wallet, Binance Wallet, Ronin, TronLink, Solflare, Coin98, Station/Terra, Keplr, Rabby, Sui Wallet, OKX Wallet, Enkrypt).

For each **desktop wallet** whose path exists, it:

1. Records that the wallet is present.
2. Reads the file mode via `stat -f '%Lp'` and looks at the group and "other" permission digits. If either digit is non-zero, the data is accessible beyond just you.
3. Checks whether the path lives under a cloud-synced folder: `~/Library/Mobile Documents` (iCloud), `~/Library/CloudStorage`, `~/Dropbox`, or `~/Google Drive`.

For **browser wallet extensions**, it looks inside each profile of Chrome, Brave, Microsoft Edge, and Arc at `Library/Application Support/.../<profile>/Local Extension Settings/<extension-id>`. If a folder matching a known wallet extension ID exists, it reports that extension as installed. This is inventory only; it does not inspect or flag the extension's contents.

## What it flags (and how serious)

- **info** - `wallet present: <id> (<path>)` for each detected desktop wallet, and `wallet extension: <name> in <browser> (<profile>)` for each detected browser wallet. These are informational inventory lines, not problems.
- **critical** - `wallet '<id>' is group/other-accessible (mode <mode>)`. A local attacker or another account can read your wallet or seed data. The finding includes the exact fix: `chmod 600 '<path>'` for a file, or `chmod 700 '<path>'` for a directory.
- **warn** - `wallet '<id>' data is in a cloud-synced folder`. Your seed material is being uploaded to a cloud provider; a compromised cloud account could exfiltrate it.

Overall verdict: if any wallet has insecure permissions the check returns **critical**; if there are only cloud-sync findings it returns **warn**; otherwise it **passes** with a count of wallets monitored. The summary reports how many wallets have insecure permissions and how many are in cloud-synced folders.

## What's baselined

This check does **not** use baseline drift. It re-evaluates the current state of your wallet files on every run and reports whatever it finds. Nothing is recorded on a first run, and there is no "changed since last time" trigger.

(The config exposes a `detect_offline_changes` key, but the current implementation does not read it; the check performs no offline-change or drift detection today.)

## Permissions

For desktop wallets and browser extensions in the standard locations listed above, this check needs **nothing** - all of those paths are inside your own home folder. It reads file metadata and folder listings only.

It does not require Full Disk Access or any TCC permission. If a wallet path simply does not exist, that wallet is silently skipped. If either lookup table is missing, that half of the check is skipped and logged in debug output.

## Configuration

Config lives under `checks.security.wallet_guard` in `~/.config/oh-my-safety/config.yaml`:

- `enabled` (default `true`) - turn the check on or off.
- `detect_offline_changes` (default `daemon_only`) - reserved; not consumed by the current implementation.

This check depends on no `tools.*` entries. Enable or disable it with:

    oh-my-safety disable wallet-guard
    oh-my-safety enable  wallet-guard

## Handling findings

For a **permissions** finding, apply the suggested `chmod` (e.g. `chmod 600 '<path>'` for a file or `chmod 700 '<path>'` for a directory) so only your account can read the wallet data, then confirm with:

    oh-my-safety recheck wallet-guard

For a **cloud-sync** finding, move the wallet's data out of the synced folder (iCloud Drive, Dropbox, Google Drive) into a local-only location and re-point the wallet if needed, then recheck.

If a finding is expected and you want to accept it permanently, ignore that specific item by its finding-id:

    oh-my-safety ignore wallet-guard '<finding-id>'

This check uses stable, path/id-based finding-ids (no process IDs):

- `wallet:<id>` - inventory of a present desktop wallet (info).
- `wallet:<id>:perms` - insecure group/other permissions on that wallet's data (critical).
- `wallet:<id>:cloud` - that wallet's data is in a cloud-synced folder (warn).
- `walletext:<extid>` - inventory of an installed browser wallet extension (info).

For example, `oh-my-safety ignore wallet-guard 'wallet:exodus:cloud'` stops flagging Exodus's cloud-sync warning. Since this check has no baseline, `oh-my-safety accept wallet-guard` does not apply here - use `ignore` for individual items instead.

## Limitations

- **Known wallets only.** It detects the wallets and browser extensions listed in the bundled TSV tables. A wallet, browser, or extension not on those lists (or installed in a non-standard path) is invisible to this check.
- **Chromium browsers only for extensions.** It scans Chrome, Brave, Edge, and Arc profiles. Firefox, Safari, and other browsers are not covered for extension inventory.
- **Permissions are a proxy, not a guarantee.** A mode-600 file is still readable by anything running as your own user - including malware that has already compromised your account. This check catches sloppy configuration, not an active intruder who already has your privileges.
- **Extensions are inventory only.** Detecting MetaMask or Phantom does not mean it is compromised; the check does not assess the extension's stored data.
- **Userspace check.** Everything relies on standard file metadata and directory listings. Root-level malware can hide files, fake permissions, or tamper with the tool itself, so a clean result is not proof of safety on an already-rooted machine.
