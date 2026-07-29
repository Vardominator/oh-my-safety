# Signed APT repository

The production archive for installing and upgrading oh-my-safety with `apt` is
published at `https://Vardominator.github.io/oh-my-safety/apt`. Its dedicated
signing-key fingerprint is:

```text
C409801C769AE605678AC763F667FC021600FE36
```

Verify that exact value from this reviewed document or the immutable v0.3.0
release notes before trusting the downloaded key.

APT authenticates an archive by verifying the signed `Release`/`InRelease`
metadata, which in turn authenticates the package indexes and package
checksums. It does not rely on deprecated global `apt-key` trust. See Debian's
official [`apt-secure(8)` documentation](https://manpages.debian.org/unstable/apt/apt-secure.8.en.html)
and [`sources.list(5)` documentation](https://manpages.debian.org/unstable/apt/sources.list.5.en.html).

## Install from APT

The commands require `curl`, `gpg`, and a Debian/Ubuntu system using `apt`.
Do not copy the expected fingerprint from the same Pages download you are about
to trust.

```bash
(
set -eu
repository_url='https://Vardominator.github.io/oh-my-safety/apt'
EXPECTED_FINGERPRINT='C409801C769AE605678AC763F667FC021600FE36'
key_file="$(mktemp)"
key_home="$(mktemp -d)"
clean_up() {
  rm -f "$key_file"
  rm -f "$key_file.exported"
  rm -rf "$key_home"
}
trap clean_up EXIT

printf '%s\n' "$EXPECTED_FINGERPRINT" |
  grep -Eq '^[0-9A-F]{40}$' || {
    echo "EXPECTED_FINGERPRINT must be 40 uppercase hex characters" >&2
    exit 1
  }

curl --proto '=https' --tlsv1.2 -fsSL \
  "$repository_url/oh-my-safety-archive-keyring.gpg" \
  -o "$key_file"

chmod 700 "$key_home"
gpg --batch --homedir "$key_home" --import "$key_file"
primary_fingerprints="$(
  gpg --batch --homedir "$key_home" --with-colons --list-keys |
    awk -F: '
      $1 == "pub" { want_fingerprint = 1; next }
      want_fingerprint && $1 == "fpr" {
        print toupper($10)
        want_fingerprint = 0
      }
    '
)"
test "$(printf '%s\n' "$primary_fingerprints" | sed '/^$/d' | wc -l)" -eq 1 &&
  test "$primary_fingerprints" = "$EXPECTED_FINGERPRINT" || {
  echo "Archive key must contain exactly the published primary key" >&2
  exit 1
}

gpg --batch --homedir "$key_home" --export "$EXPECTED_FINGERPRINT" \
  >"$key_file.exported"
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$key_file.exported" \
  /etc/apt/keyrings/oh-my-safety-archive-keyring.gpg

# Create trust policy locally. Never download a sources or preferences file
# from the same origin whose signing key is being bootstrapped.
sudo tee /etc/apt/sources.list.d/oh-my-safety.sources >/dev/null <<EOF
Types: deb
URIs: https://Vardominator.github.io/oh-my-safety/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/oh-my-safety-archive-keyring.gpg $EXPECTED_FINGERPRINT
EOF

# Optional: keep this third-party origin at priority 100 while allowing
# an explicit install and subsequent upgrades of its uniquely named package.
sudo tee /etc/apt/preferences.d/oh-my-safety.pref >/dev/null <<'EOF'
Package: oh-my-safety
Pin: release o=oh-my-safety
Pin-Priority: 100
EOF

sudo apt-get update
sudo apt-get install oh-my-safety
oh-my-safety version
)
```

The package deliberately does not start the user monitor before you review the
machine. Configure it, establish an offline first scan, inspect persistence,
then enable continuous monitoring as the protected user:

```bash
oh-my-safety doctor
oh-my-safety scan --offline
oh-my-safety status
oh-my-safety baseline show linux-persistence-scan
systemctl --user daemon-reload
systemctl --user enable --now oh-my-safety.service
```

Normal package updates then use:

```bash
sudo apt-get update
sudo apt-get install --only-upgrade oh-my-safety
systemctl --user daemon-reload
systemctl --user restart oh-my-safety.service
```

The downloaded deb822 source is equivalent to:

```text
Types: deb
URIs: https://Vardominator.github.io/oh-my-safety/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/oh-my-safety-archive-keyring.gpg PUBLISHED_40_HEX_FINGERPRINT
```

Pinning the reviewed fingerprint after the keyring path prevents any additional
key accidentally present in that file from authorizing the repository.

To remove the package and repository configuration:

```bash
systemctl --user disable --now oh-my-safety.service
sudo apt-get remove oh-my-safety
sudo rm -f \
  /etc/apt/sources.list.d/oh-my-safety.sources \
  /etc/apt/preferences.d/oh-my-safety.pref \
  /etc/apt/keyrings/oh-my-safety-archive-keyring.gpg
sudo apt-get update
systemctl --user daemon-reload
```

User configuration and state under the user's XDG directories are preserved.

## Maintainer setup

The workflow is [`.github/workflows/apt-repository.yml`](../.github/workflows/apt-repository.yml).
Its validation job runs on pull requests and forks without secrets. It builds
both `.deb` architectures, creates a one-day ephemeral OpenPGP key, signs the
repository, verifies every signature and digest, and performs an actual
`apt-get install` from the result.

Before the first production publication:

1. Enable [immutable releases](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes).
   The publisher runs `gh release verify` and `gh release verify-asset` and
   refuses mutable releases. Create releases as drafts, attach every package
   and `checksums.txt`, and then publish the completed draft.
2. Generate a dedicated archive signing certificate. Keep its primary key
   offline and export only the CI signing subkey where practical. Publish and
   review the full primary fingerprint separately from the Pages site.
3. Create a protected `apt-signing` GitHub environment with required reviewers.
   Add `APT_SIGNING_KEY` as an ASCII-armored secret-key export and, if used,
   `APT_SIGNING_KEY_PASSPHRASE` as an environment secret.
4. Add repository variable `APT_SIGNING_FINGERPRINT` with the full 40-hex
   primary fingerprint. Set `APT_REPOSITORY_URL` only when using a custom HTTPS
   location; otherwise the repository's GitHub Pages `/apt` URL is used.
5. Configure Pages to deploy from GitHub Actions. The workflow publishes the
   complete Pages artifact, so combine it with any existing site before
   enabling this workflow or use a dedicated repository for the APT site.
6. Add the reviewed fingerprint to the user-facing install documentation and
   signed release notes. Then set repository variable
   `APT_REPOSITORY_ENABLED=true`.
7. For the first deployment only, set protected environment variable
   `APT_ALLOW_INITIAL_PUBLISH=true` and keep
   `APT_REPOSITORY_INITIALIZED` absent. Run **APT Repository** from `main`,
   select an immutable release tag, and set `publish=true`. Initialization is
   accepted only when the old `InRelease` request returns an exact HTTP 404;
   DNS, TLS, timeout, and server failures remain fatal, and the selected tag
   must be the latest published release.
8. Confirm the live repository and a clean-host install, set protected
   `APT_REPOSITORY_INITIALIZED=true`, then remove
   `APT_ALLOW_INITIAL_PUBLISH`. Future runs fail closed if the previous signed
   repository cannot be retrieved.

Production secrets are referenced only by the `build-production` job. That job
requires the canonical repository, `main`, the opt-in variable, a successful
secret-free validation job, and the protected environment. Pull requests and
forks can never enter it. The deploy job separately receives only the
short-lived Pages OIDC permissions described by
[GitHub's Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

## Publication and rollback protections

The publisher:

- downloads only `.deb` files and `checksums.txt` from a published immutable
  GitHub release and verifies both the release attestation and each asset;
- refuses a version older than the currently signed repository;
- refuses a changed package digest at the same version;
- emits `InRelease`, `Release.gpg`, `Valid-Until`, and
  `Acquire-By-Hash: yes`;
- creates regular SHA-256 `by-hash` copies and verifies their contents;
- carries all previously published content-addressed index objects forward
  through a bounded, path-validated manifest to avoid CDN metadata/index
  rollover races; and
- refreshes its 45-day `Valid-Until` on days 1 and 15 of every month while the
  explicit repository opt-in remains enabled.

The build and verification scripts are:

```bash
./scripts/build-apt-repository.sh --help
./scripts/verify-apt-repository.sh --help
```

`apt-ftparchive` is the Debian-provided index generator. Its official
documentation describes both `Release` generation and supported metadata:
[`apt-ftparchive(1)`](https://manpages.debian.org/unstable/apt-utils/apt-ftparchive.1.en.html).
