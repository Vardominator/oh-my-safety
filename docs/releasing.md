# Release maintenance

This page is for maintainers. Users should follow
[Getting started](getting-started.md).

## Repository setup

Protect `main` and require the `CI` and `Distribution` workflow checks. GitHub
Actions should have read-only repository permissions by default.

Enable release immutability in repository settings before publishing v0.3 or
later. The release workflow requires a signed annotated tag, creates the
release through `gh release create`, attaches every package and checksum while
the release is an internal draft, and publishes only after the uploads
complete. GitHub then locks the tag/assets and generates the release
attestation consumed by the APT publisher.

Formula automation is disabled unless the repository variable
`FORMULA_AUTOMATION_ENABLED` is exactly `true`. When enabled, the release
workflow uses a dedicated GitHub App because a push made with the built-in
`GITHUB_TOKEN` does not trigger pull-request validation, and repository
settings can prevent that token from opening pull requests. Install a
single-repository App with only:

- Contents: read and write
- Pull requests: read and write

Store its App ID as the Actions secret `FORMULA_APP_ID` and its private key as
`FORMULA_APP_PRIVATE_KEY`. Do not reuse a personal access token or a maintainer's
credentials. If the App is not configured, leave the variable unset and open
the formula PR manually after the immutable release is verified.

## Prepare a release

1. Update `OMS_VERSION` in `lib/core.sh`, documentation, and the curated
   `docs/releases/vMAJOR.MINOR.PATCH.md` release note in a normal pull request.
2. Keep `Formula/oh-my-safety.rb` on the last valid stable tag and checksum. A
   placeholder checksum is forbidden and CI will reject it.
3. Run `bats test`, `go test -race ./...`,
   `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`,
   `./scripts/gen-docs.sh --check`, and `python3 scripts/check-docs.py`.
4. Merge only after both the CI and Distribution checks pass.
5. Create and push a signed, annotated `vMAJOR.MINOR.PATCH` tag that exactly
   matches `OMS_VERSION`. The signing identity must be configured on GitHub so
   the tag object's `verification.verified` result is true; lightweight,
   unsigned, unknown-key, or differently targeted tags fail closed.

The tag workflow reuses the full CI, distribution, and native Snap suites
before publishing the release. It hashes GitHub's tag archive, publishes the
complete immutable release with the curated notes, and, when explicitly
enabled, opens a `formula-bump-vMAJOR.MINOR.PATCH` pull request using the
release App. An interrupted draft is resumable; a rerun verifies an existing
immutable release instead of attempting to mutate it.

Linux repository publishing is a separate, credential-gated operation:

- [Signed APT repository](apt-repository.md) covers the archive key, protected
  environments, one-time bootstrap, Pages, key fingerprint, and rollback
  controls.
- [Snap packaging](../packaging/snap/README.md) is experimental. Canonical
  Store approval is uncertain; CI may publish canonical `main` to `edge` only,
  and no workflow promotes it to candidate or stable.

## Publish Homebrew

Review the automated formula pull request and require its normal CI and
Distribution checks. The checksum must match the `checksums.txt` asset attached
to the GitHub release. Merge the PR, then verify from a clean shell:

```bash
brew update
brew tap vardominator/oh-my-safety https://github.com/Vardominator/oh-my-safety
brew install vardominator/oh-my-safety/oh-my-safety
brew test vardominator/oh-my-safety/oh-my-safety
oh-my-safety version
```

Never publish a formula whose archive is unavailable, whose checksum is a
placeholder, or whose Homebrew service and SwiftBar smoke tests have not passed.
