#!/bin/bash
# Build .deb and .rpm packages with nFPM.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^OMS_VERSION="\([^"]*\)".*/\1/p' "$ROOT/lib/core.sh" | head -1)"
OUT="${OMS_PACKAGE_OUT:-$ROOT/dist}"
TARGET_ARCH="${OMS_PACKAGE_ARCH:-$(uname -m)}"

case "$TARGET_ARCH" in
    x86_64|amd64) PACKAGE_ARCH="amd64" ;;
    aarch64|arm64) PACKAGE_ARCH="arm64" ;;
    *)
        echo "Unsupported package architecture: $TARGET_ARCH" >&2
        exit 2
        ;;
esac

if [[ -z "$VERSION" ]]; then
    echo "Unable to read OMS_VERSION from lib/core.sh" >&2
    exit 2
fi

if ! command -v nfpm >/dev/null 2>&1; then
    echo "nFPM is required to build Linux packages: https://nfpm.goreleaser.com/" >&2
    exit 2
fi

mkdir -p "$OUT"
cd "$ROOT"

export PACKAGE_ARCH
export PACKAGE_VERSION="$VERSION"
export PACKAGE_AGENT_PATH="$OUT/oh-my-safety-agent"
export PACKAGE_INTEL_PATH="$OUT/oh-my-safety-intel"
export CGO_ENABLED=0
case "$PACKAGE_ARCH" in
    amd64) export GOARCH=amd64 ;;
    arm64) export GOARCH=arm64 ;;
esac
export GOOS=linux

go build -trimpath -ldflags "-X main.agentVersion=$VERSION" \
    -o "$PACKAGE_AGENT_PATH" ./cmd/oh-my-safety-agent
go build -trimpath -o "$PACKAGE_INTEL_PATH" ./cmd/oh-my-safety-intel

nfpm package \
    --config "$ROOT/packaging/nfpm.yaml" \
    --packager deb \
    --target "$OUT/oh-my-safety_${VERSION}_${PACKAGE_ARCH}.deb"

nfpm package \
    --config "$ROOT/packaging/nfpm.yaml" \
    --packager rpm \
    --target "$OUT/oh-my-safety-${VERSION}.${PACKAGE_ARCH}.rpm"

archive_root="$(mktemp -d "${TMPDIR:-/tmp}/oh-my-safety-package.XXXXXX")"
cleanup_archive() { rm -rf "$archive_root"; }
trap cleanup_archive EXIT
mkdir -p "$archive_root/oh-my-safety-$VERSION"
cp -R bin lib config docs plugins "$archive_root/oh-my-safety-$VERSION/"
cp "$PACKAGE_AGENT_PATH" "$archive_root/oh-my-safety-$VERSION/bin/"
cp "$PACKAGE_INTEL_PATH" "$archive_root/oh-my-safety-$VERSION/bin/"
tar -C "$archive_root" -czf \
    "$OUT/oh-my-safety_${VERSION}_${PACKAGE_ARCH}.tar.gz" \
    "oh-my-safety-$VERSION"

echo "Built Linux packages in: $OUT"
