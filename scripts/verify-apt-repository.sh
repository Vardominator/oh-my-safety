#!/bin/bash
# Verify an APT repository's signatures, indexes, and package checksums.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  verify-apt-repository.sh --repository DIR [options]

Options:
  --keyring FILE           Public archive keyring (required for signed repos)
  --suite NAME             Suite to verify (default: stable)
  --component NAME         Component to verify (default: main)
  --architectures "LIST"   Expected architectures (default: "amd64 arm64")
  --allow-unsigned         Accept an explicitly marked test-only repository
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

REPOSITORY=""
KEYRING=""
SUITE="stable"
COMPONENT="main"
ARCHITECTURES="amd64 arm64"
ALLOW_UNSIGNED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repository)
            [[ $# -ge 2 ]] || die "--repository requires a directory"
            REPOSITORY="$2"
            shift 2
            ;;
        --keyring)
            [[ $# -ge 2 ]] || die "--keyring requires a file"
            KEYRING="$2"
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
        --architectures)
            [[ $# -ge 2 ]] || die "--architectures requires a value"
            ARCHITECTURES="$2"
            shift 2
            ;;
        --allow-unsigned)
            ALLOW_UNSIGNED=1
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

[[ -n "$REPOSITORY" ]] || die "--repository is required"
[[ -d "$REPOSITORY" ]] || die "repository does not exist: $REPOSITORY"
REPOSITORY="$(cd "$REPOSITORY" && pwd -P)"

symlink="$(find "$REPOSITORY" -type l -print -quit)"
[[ -z "$symlink" ]] || die "repository must not contain symlinks: $symlink"

release_dir="$REPOSITORY/dists/$SUITE"
release_file="$release_dir/Release"
[[ -s "$release_file" ]] || die "missing Release file"

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/oh-my-safety-apt-verify.XXXXXX")"
cleanup() { rm -rf "$temporary_dir"; }
trap cleanup EXIT HUP INT TERM

if [[ -f "$REPOSITORY/UNSIGNED-TEST-REPOSITORY" ]]; then
    [[ "$ALLOW_UNSIGNED" -eq 1 ]] ||
        die "unsigned test repository rejected"
    [[ ! -e "$release_dir/InRelease" && ! -e "$release_dir/Release.gpg" ]] ||
        die "unsigned marker cannot be combined with signature files"
else
    [[ "$ALLOW_UNSIGNED" -eq 0 ]] ||
        die "--allow-unsigned is valid only for an explicitly marked test repository"
    [[ -n "$KEYRING" ]] || die "--keyring is required for a signed repository"
    [[ -f "$KEYRING" && ! -L "$KEYRING" ]] ||
        die "keyring must be a regular, non-symlink file"
    [[ -s "$release_dir/InRelease" ]] || die "missing InRelease signature"
    [[ -s "$release_dir/Release.gpg" ]] || die "missing Release.gpg signature"
    command -v gpgv >/dev/null 2>&1 || die "required command not found: gpgv"

    chmod 0700 "$temporary_dir"
    GNUPGHOME="$temporary_dir" gpgv --keyring "$KEYRING" \
        --output "$temporary_dir/inrelease.txt" "$release_dir/InRelease"
    GNUPGHOME="$temporary_dir" gpgv --keyring "$KEYRING" \
        "$release_dir/Release.gpg" "$release_file"
    cmp -s "$temporary_dir/inrelease.txt" "$release_file" ||
        die "InRelease content does not match Release"
fi

grep -Fx "Origin: oh-my-safety" "$release_file" >/dev/null ||
    die "unexpected or missing Release Origin"
grep -Fx "Suite: $SUITE" "$release_file" >/dev/null ||
    die "unexpected or missing Release Suite"
grep -Fx "Codename: $SUITE" "$release_file" >/dev/null ||
    die "unexpected or missing Release Codename"
grep -Fx "Architectures: $ARCHITECTURES" "$release_file" >/dev/null ||
    die "unexpected Release architectures"
grep -Fx "Components: $COMPONENT" "$release_file" >/dev/null ||
    die "unexpected Release component"
grep -Fx "Acquire-By-Hash: yes" "$release_file" >/dev/null ||
    die "Release does not enable Acquire-By-Hash"
grep -E '^Date: .+' "$release_file" >/dev/null || die "Release Date is missing"
grep -E '^Valid-Until: .+' "$release_file" >/dev/null ||
    die "Release Valid-Until is missing"

release_checksums="$temporary_dir/release-sha256"
awk '
    $0 == "SHA256:" { in_sha256 = 1; next }
    in_sha256 && /^[^ ]/ { exit }
    in_sha256 { print $1 "\t" $2 "\t" $3 }
' "$release_file" >"$release_checksums"
[[ -s "$release_checksums" ]] || die "Release contains no SHA256 index"

while IFS=$'\t' read -r expected_sha expected_size relative_path; do
    [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] ||
        die "invalid SHA256 entry in Release"
    [[ "$expected_size" =~ ^[0-9]+$ ]] ||
        die "invalid size entry in Release"
    case "$relative_path" in
        ""|/*|*".."*) die "unsafe Release path: $relative_path" ;;
    esac
    indexed_file="$release_dir/$relative_path"
    [[ -f "$indexed_file" && ! -L "$indexed_file" ]] ||
        die "Release references missing file: $relative_path"
    actual_sha="$(sha256sum "$indexed_file" | awk '{ print $1 }')"
    actual_size="$(wc -c <"$indexed_file" | tr -d '[:space:]')"
    [[ "$actual_sha" = "$expected_sha" ]] ||
        die "Release checksum mismatch: $relative_path"
    [[ "$actual_size" = "$expected_size" ]] ||
        die "Release size mismatch: $relative_path"

    case "$relative_path" in
        */Packages|*/Packages.*)
            by_hash_file="$release_dir/$(dirname "$relative_path")/by-hash/SHA256/$expected_sha"
            [[ -f "$by_hash_file" && ! -L "$by_hash_file" ]] ||
                die "missing SHA256 by-hash copy: $relative_path"
            cmp -s "$indexed_file" "$by_hash_file" ||
                die "by-hash content mismatch: $relative_path"
            ;;
    esac
done <"$release_checksums"

while IFS= read -r by_hash_file; do
    by_hash_name="$(basename "$by_hash_file")"
    [[ "$by_hash_name" =~ ^[0-9a-f]{64}$ ]] ||
        die "invalid SHA256 by-hash filename: $by_hash_file"
    [[ "$(sha256sum "$by_hash_file" | awk '{ print $1 }')" = "$by_hash_name" ]] ||
        die "stale or corrupt SHA256 by-hash object: $by_hash_file"
done < <(find "$release_dir" -type f -path '*/by-hash/SHA256/*' -print)

package_record_count=0
for package_arch in $ARCHITECTURES; do
    binary_dir="$release_dir/$COMPONENT/binary-$package_arch"
    packages_file="$binary_dir/Packages"
    compressed_file="$binary_dir/Packages.gz"
    [[ -s "$packages_file" ]] || die "missing Packages index for $package_arch"
    [[ -s "$compressed_file" ]] || die "missing Packages.gz index for $package_arch"
    gzip -cd "$compressed_file" | cmp -s - "$packages_file" ||
        die "Packages.gz does not match Packages for $package_arch"

    records="$temporary_dir/packages-$package_arch"
    awk '
        function emit() {
            if (filename != "") {
                print package "\t" architecture "\t" filename "\t" size "\t" sha256
            }
            package = architecture = filename = size = sha256 = ""
        }
        /^Package: / { package = substr($0, 10) }
        /^Architecture: / { architecture = substr($0, 15) }
        /^Filename: / { filename = substr($0, 11) }
        /^Size: / { size = substr($0, 7) }
        /^SHA256: / { sha256 = substr($0, 9) }
        /^$/ { emit() }
        END { emit() }
    ' "$packages_file" >"$records"
    [[ -s "$records" ]] || die "Packages index is empty for $package_arch"

    while IFS=$'\t' read -r package_name record_arch filename expected_size expected_sha; do
        [[ "$package_name" = "oh-my-safety" ]] ||
            die "unexpected package in index: $package_name"
        [[ "$record_arch" = "$package_arch" ]] ||
            die "package architecture mismatch for $filename"
        case "$filename" in
            "pool/$COMPONENT/o/oh-my-safety/"*.deb) ;;
            *) die "unsafe or unexpected package path: $filename" ;;
        esac
        package_file="$REPOSITORY/$filename"
        [[ -f "$package_file" && ! -L "$package_file" ]] ||
            die "indexed package is missing: $filename"
        actual_size="$(wc -c <"$package_file" | tr -d '[:space:]')"
        actual_sha="$(sha256sum "$package_file" | awk '{ print $1 }')"
        [[ "$expected_size" = "$actual_size" ]] ||
            die "package size mismatch: $filename"
        [[ "$expected_sha" = "$actual_sha" ]] ||
            die "package checksum mismatch: $filename"
        [[ "$(dpkg-deb --field "$package_file" Package)" = "$package_name" ]] ||
            die "package metadata mismatch: $filename"
        [[ "$(dpkg-deb --field "$package_file" Architecture)" = "$record_arch" ]] ||
            die "package architecture metadata mismatch: $filename"
        package_record_count=$((package_record_count + 1))
    done <"$records"
done

pool_package_count="$(
    find "$REPOSITORY/pool" -type f -name '*.deb' -print | wc -l | tr -d '[:space:]'
)"
[[ "$package_record_count" = "$pool_package_count" ]] ||
    die "not every pool package is represented exactly once in the indexes"

printf 'Verified APT repository: %s\n' "$REPOSITORY"
printf 'Architectures: %s\nPackages: %s\n' \
    "$ARCHITECTURES" "$package_record_count"
