#!/bin/bash
# Build portable, pure-Go Linux controller archives.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^OMS_VERSION="\([^"]*\)".*/\1/p' "$ROOT/lib/core.sh" | head -1)"
OUT="${OMS_PACKAGE_OUT:-$ROOT/dist}"
ARCHES="${OMS_CONTROLLER_ARCHES:-amd64 arm64}"

if [[ -z "$VERSION" ]]; then
    echo "Unable to read OMS_VERSION from lib/core.sh" >&2
    exit 2
fi

mkdir -p "$OUT"
work="$(mktemp -d "${TMPDIR:-/tmp}/oh-my-safety-controller.XXXXXX")"
cleanup_controller_build() { rm -rf "$work"; }
trap cleanup_controller_build EXIT

for arch in $ARCHES; do
    case "$arch" in
        amd64|arm64) ;;
        *)
            echo "Unsupported controller architecture: $arch" >&2
            exit 2
            ;;
    esac
    root="$work/oh-my-safety-controller-$VERSION-linux-$arch"
    mkdir -p "$root/docs"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -trimpath -o "$root/oh-my-safety-controller" \
        "$ROOT/cmd/oh-my-safety-controller"
    cp "$ROOT/LICENSE" "$root/"
    if [[ -f "$ROOT/docs/organization.md" ]]; then
        cp "$ROOT/docs/organization.md" "$root/docs/"
    fi
    tar -C "$work" -czf \
        "$OUT/oh-my-safety-controller_${VERSION}_linux_${arch}.tar.gz" \
        "$(basename "$root")"
done

echo "Built controller archives in: $OUT"
