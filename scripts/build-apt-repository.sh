#!/bin/bash
# Build a minimal, signed APT repository from release .deb packages.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  build-apt-repository.sh --packages DIR --output DIR [options]

Required:
  --packages DIR             Directory containing only release .deb files
  --output DIR               New directory to create as the repository root

Signing (choose exactly one):
  --signing-key FINGERPRINT  Primary fingerprint of a secret archive key
  --unsigned                 Build an explicitly marked test repository

Options:
  --version VERSION          Require every package to have this version
  --suite NAME               Suite and codename (default: stable)
  --component NAME           Repository component (default: main)
  --valid-days DAYS          Release metadata lifetime (default: 45)
  --passphrase-file FILE     Mode-0600 file used to unlock the signing key
  --origin TEXT              Release Origin (default: oh-my-safety)
  --label TEXT               Release Label (default: oh-my-safety)
  --description TEXT         Release description

The output directory must not already exist. Set GNUPGHOME to select the
signing keyring. Production publication must never use --unsigned.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

PACKAGES_DIR=""
OUTPUT_DIR=""
EXPECTED_VERSION=""
SUITE="stable"
COMPONENT="main"
VALID_DAYS="45"
ORIGIN="oh-my-safety"
LABEL="oh-my-safety"
DESCRIPTION="Local-first safety and privacy monitor"
SIGNING_KEY=""
PASSPHRASE_FILE=""
UNSIGNED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --packages)
            [[ $# -ge 2 ]] || die "--packages requires a directory"
            PACKAGES_DIR="$2"
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || die "--output requires a directory"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --version)
            [[ $# -ge 2 ]] || die "--version requires a value"
            EXPECTED_VERSION="$2"
            shift 2
            ;;
        --suite)
            [[ $# -ge 2 ]] || die "--suite requires a value"
            SUITE="$2"
            shift 2
            ;;
        --component)
            [[ $# -ge 2 ]] || die "--component requires a value"
            COMPONENT="$2"
            shift 2
            ;;
        --valid-days)
            [[ $# -ge 2 ]] || die "--valid-days requires a value"
            VALID_DAYS="$2"
            shift 2
            ;;
        --origin)
            [[ $# -ge 2 ]] || die "--origin requires a value"
            ORIGIN="$2"
            shift 2
            ;;
        --label)
            [[ $# -ge 2 ]] || die "--label requires a value"
            LABEL="$2"
            shift 2
            ;;
        --description)
            [[ $# -ge 2 ]] || die "--description requires a value"
            DESCRIPTION="$2"
            shift 2
            ;;
        --signing-key)
            [[ $# -ge 2 ]] || die "--signing-key requires a fingerprint"
            SIGNING_KEY="$2"
            shift 2
            ;;
        --passphrase-file)
            [[ $# -ge 2 ]] || die "--passphrase-file requires a file"
            PASSPHRASE_FILE="$2"
            shift 2
            ;;
        --unsigned)
            UNSIGNED=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -n "$PACKAGES_DIR" ]] || die "--packages is required"
[[ -n "$OUTPUT_DIR" ]] || die "--output is required"
[[ -d "$PACKAGES_DIR" ]] || die "package directory does not exist: $PACKAGES_DIR"
[[ ! -e "$OUTPUT_DIR" ]] || die "output path already exists: $OUTPUT_DIR"
[[ "$SUITE" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "invalid suite: $SUITE"
[[ "$COMPONENT" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "invalid component: $COMPONENT"
[[ "$VALID_DAYS" =~ ^[1-9][0-9]*$ ]] || die "--valid-days must be a positive integer"
[[ "$VALID_DAYS" -le 365 ]] || die "--valid-days cannot exceed 365"

if [[ "$UNSIGNED" -eq 1 && -n "$SIGNING_KEY" ]]; then
    die "--unsigned and --signing-key are mutually exclusive"
fi
if [[ "$UNSIGNED" -eq 0 && -z "$SIGNING_KEY" ]]; then
    die "choose --signing-key or the test-only --unsigned mode"
fi
if [[ -n "$PASSPHRASE_FILE" ]]; then
    [[ "$UNSIGNED" -eq 0 ]] || die "--passphrase-file cannot be used with --unsigned"
    [[ -f "$PASSPHRASE_FILE" && ! -L "$PASSPHRASE_FILE" ]] ||
        die "passphrase file must be a regular, non-symlink file"
    passphrase_mode="$(stat -c '%a' "$PASSPHRASE_FILE" 2>/dev/null || true)"
    [[ "$passphrase_mode" = "600" || "$passphrase_mode" = "400" ]] ||
        die "passphrase file must have mode 0600 or 0400"
fi

require_command apt-ftparchive
require_command dpkg-deb
require_command gzip
require_command sha256sum
if [[ "$UNSIGNED" -eq 0 ]]; then
    require_command gpg
fi

PACKAGES_DIR="$(cd "$PACKAGES_DIR" && pwd -P)"
output_parent="$(dirname "$OUTPUT_DIR")"
output_name="$(basename "$OUTPUT_DIR")"
[[ "$output_name" != "." && "$output_name" != "/" ]] || die "unsafe output path"
mkdir -p "$output_parent"
output_parent="$(cd "$output_parent" && pwd -P)"
OUTPUT_DIR="$output_parent/$output_name"

work_dir="$(mktemp -d "$output_parent/.oh-my-safety-apt.XXXXXX")"
cleanup() {
    if [[ -n "${work_dir:-}" && -d "$work_dir" ]]; then
        rm -rf "$work_dir"
    fi
}
trap cleanup EXIT HUP INT TERM

repository="$work_dir/repository"
pool="$repository/pool/$COMPONENT/o/oh-my-safety"
mkdir -p "$pool"

package_count=0
architectures=""
repository_version="$EXPECTED_VERSION"

for package_path in "$PACKAGES_DIR"/*.deb; do
    [[ -e "$package_path" ]] || continue
    [[ -f "$package_path" && ! -L "$package_path" ]] ||
        die "package must be a regular, non-symlink file: $package_path"

    package_name="$(dpkg-deb --field "$package_path" Package)"
    package_version="$(dpkg-deb --field "$package_path" Version)"
    package_arch="$(dpkg-deb --field "$package_path" Architecture)"

    [[ "$package_name" = "oh-my-safety" ]] ||
        die "unexpected package '$package_name' in $package_path"
    [[ "$package_version" =~ ^[0-9A-Za-z.+:~_-]+$ ]] ||
        die "unsafe package version '$package_version'"
    case "$package_arch" in
        amd64|arm64) ;;
        *) die "unsupported Debian architecture '$package_arch'" ;;
    esac

    if [[ -z "$repository_version" ]]; then
        repository_version="$package_version"
    fi
    [[ "$package_version" = "$repository_version" ]] ||
        die "package version $package_version does not match $repository_version"
    case " $architectures " in
        *" $package_arch "*)
            die "duplicate package architecture: $package_arch"
            ;;
        *)
            architectures="${architectures:+$architectures }$package_arch"
            ;;
    esac

    canonical_name="oh-my-safety_${package_version}_${package_arch}.deb"
    cp "$package_path" "$pool/$canonical_name"
    chmod 0644 "$pool/$canonical_name"
    package_count=$((package_count + 1))
done

[[ "$package_count" -gt 0 ]] || die "no .deb packages found in $PACKAGES_DIR"

ordered_architectures=""
for package_arch in amd64 arm64; do
    case " $architectures " in
        *" $package_arch "*)
            ordered_architectures="${ordered_architectures:+$ordered_architectures }$package_arch"
            ;;
    esac
done
architectures="$ordered_architectures"

for package_arch in $architectures; do
    binary_dir="$repository/dists/$SUITE/$COMPONENT/binary-$package_arch"
    mkdir -p "$binary_dir"
    (
        cd "$repository"
        LC_ALL=C apt-ftparchive -a "$package_arch" packages \
            "pool/$COMPONENT/o/oh-my-safety"
    ) >"$binary_dir/Packages"
    gzip -9n -c "$binary_dir/Packages" >"$binary_dir/Packages.gz"
    cat >"$binary_dir/Release" <<EOF
Archive: $SUITE
Component: $COMPONENT
Origin: $ORIGIN
Label: $LABEL
Architecture: $package_arch
EOF
done

release_epoch="$(date -u '+%s')"
valid_seconds=$((VALID_DAYS * 86400))
release_date="$(date -u --date="@$release_epoch" -R)"
release_file="$repository/dists/$SUITE/Release"
release_temp="$work_dir/Release"

(
    cd "$repository"
    LC_ALL=C apt-ftparchive \
        -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
        -o "APT::FTPArchive::Release::Label=$LABEL" \
        -o "APT::FTPArchive::Release::Suite=$SUITE" \
        -o "APT::FTPArchive::Release::Codename=$SUITE" \
        -o "APT::FTPArchive::Release::Architectures=$architectures" \
        -o "APT::FTPArchive::Release::Components=$COMPONENT" \
        -o "APT::FTPArchive::Release::Description=$DESCRIPTION" \
        -o "APT::FTPArchive::Release::Date=$release_date" \
        -o "APT::FTPArchive::Release::ValidTime=$valid_seconds" \
        -o "APT::FTPArchive::DoByHash=true" \
        release "dists/$SUITE"
) >"$release_temp"
mv "$release_temp" "$release_file"
valid_until="$(sed -n 's/^Valid-Until: //p' "$release_file")"
[[ -n "$valid_until" ]] || die "apt-ftparchive did not emit Valid-Until"

if [[ "$UNSIGNED" -eq 1 ]]; then
    cat >"$repository/UNSIGNED-TEST-REPOSITORY" <<'EOF'
This repository was built with --unsigned and must never be published.
EOF
else
    normalized_key="$(printf '%s' "$SIGNING_KEY" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
    [[ "$normalized_key" =~ ^[0-9A-F]{40}$ ]] ||
        die "--signing-key must be a full 40-hex primary fingerprint"

    actual_key="$(
        gpg --batch --with-colons --list-secret-keys "$normalized_key" 2>/dev/null |
            awk -F: '$1 == "fpr" { print toupper($10); exit }'
    )"
    [[ "$actual_key" = "$normalized_key" ]] ||
        die "the configured primary fingerprint is not available as a secret key"

    gpg_args=(--batch --yes --no-tty --local-user "$normalized_key")
    if [[ -n "$PASSPHRASE_FILE" ]]; then
        gpg_args+=(--pinentry-mode loopback --passphrase-file "$PASSPHRASE_FILE")
    fi

    gpg "${gpg_args[@]}" --clearsign \
        --output "$repository/dists/$SUITE/InRelease" "$release_file"
    gpg "${gpg_args[@]}" --armor --detach-sign \
        --output "$repository/dists/$SUITE/Release.gpg" "$release_file"
    gpg --batch --export-options export-minimal --export "$normalized_key" \
        >"$repository/oh-my-safety-archive-keyring.gpg"
    [[ -s "$repository/oh-my-safety-archive-keyring.gpg" ]] ||
        die "failed to export the archive public key"
    printf '%s\n' "$normalized_key" \
        >"$repository/oh-my-safety-archive-keyring.fingerprint"
    chmod 0644 \
        "$repository/oh-my-safety-archive-keyring.gpg" \
        "$repository/oh-my-safety-archive-keyring.fingerprint"
fi

mv "$repository" "$OUTPUT_DIR"
work_dir=""
printf 'Built APT repository: %s\n' "$OUTPUT_DIR"
printf 'Version: %s\nArchitectures: %s\nValid until: %s\n' \
    "$repository_version" "$architectures" "$valid_until"
