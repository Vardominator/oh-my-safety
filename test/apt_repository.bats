#!/usr/bin/env bats

setup() {
    OMS_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
}

@test "APT repository builder requires an explicit signing mode" {
    mkdir -p "$BATS_TEST_TMPDIR/packages"

    run "$OMS_ROOT/scripts/build-apt-repository.sh" \
        --packages "$BATS_TEST_TMPDIR/packages" \
        --output "$BATS_TEST_TMPDIR/repository"

    [ "$status" -eq 2 ]
    [[ "$output" == *"choose --signing-key or the test-only --unsigned mode"* ]]
}

@test "unsigned test repository has verified indexes and by-hash copies" {
    for command_name in apt-ftparchive dpkg-deb gzip sha256sum; do
        command -v "$command_name" >/dev/null 2>&1 ||
            skip "$command_name is not installed"
    done

    package_root="$BATS_TEST_TMPDIR/package"
    packages_dir="$BATS_TEST_TMPDIR/packages"
    repository="$BATS_TEST_TMPDIR/repository"
    mkdir -p "$package_root/DEBIAN" "$package_root/usr/bin" "$packages_dir"
    printf '%s\n' \
        'Package: oh-my-safety' \
        'Version: 9.9.9' \
        'Architecture: amd64' \
        'Maintainer: test <test@example.invalid>' \
        'Description: APT repository fixture' \
        >"$package_root/DEBIAN/control"
    printf '#!/bin/sh\nexit 0\n' >"$package_root/usr/bin/oh-my-safety"
    chmod 0755 "$package_root/usr/bin/oh-my-safety"
    dpkg-deb --build --root-owner-group \
        "$package_root" "$packages_dir/fixture.deb" >/dev/null

    run "$OMS_ROOT/scripts/build-apt-repository.sh" \
        --packages "$packages_dir" \
        --output "$repository" \
        --version 9.9.9 \
        --unsigned
    [ "$status" -eq 0 ]

    run "$OMS_ROOT/scripts/verify-apt-repository.sh" \
        --repository "$repository" \
        --architectures amd64 \
        --allow-unsigned
    [ "$status" -eq 0 ]
    grep -Fx 'Acquire-By-Hash: yes' "$repository/dists/stable/Release"

    by_hash="$(
        find "$repository/dists/stable" \
            -type f -path '*/by-hash/SHA256/*' -print -quit
    )"
    [ -n "$by_hash" ]
    printf 'tampered\n' >>"$by_hash"

    run "$OMS_ROOT/scripts/verify-apt-repository.sh" \
        --repository "$repository" \
        --architectures amd64 \
        --allow-unsigned
    [ "$status" -eq 2 ]
    [[ "$output" == *"by-hash"* ]]
}
