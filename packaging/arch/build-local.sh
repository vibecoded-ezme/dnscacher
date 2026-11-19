#!/usr/bin/env bash
# Build an Arch Linux package from the current working tree.
#
# Usage:
#   ./packaging/arch/build-local.sh              # makepkg -si (build and install)
#   ./packaging/arch/build-local.sh -f           # build only
#
# Any arguments are passed straight to makepkg instead of the default -si.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_DIR/target/archpkg"
PKGBUILD="$SCRIPT_DIR/PKGBUILD"

pkgver="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_DIR/Cargo.toml" | head -n1)"
pkgbuild_ver="$(sed -n 's/^pkgver=\(.*\)$/\1/p' "$PKGBUILD" | head -n1)"

if [[ -z "$pkgver" || "$pkgver" != "$pkgbuild_ver" ]]; then
    echo "error: Cargo.toml version '$pkgver' does not match PKGBUILD pkgver '$pkgbuild_ver'" >&2
    echo "       bump pkgver in packaging/arch/PKGBUILD" >&2
    exit 1
fi

if ! command -v makepkg >/dev/null 2>&1; then
    echo "error: makepkg not found (install base-devel)" >&2
    exit 1
fi

echo "staging dnscacher $pkgver in $BUILD_DIR"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/dnscacher-$pkgver"

tar -C "$REPO_DIR" \
    --exclude='./target' \
    --exclude='./.git' \
    -cf - . |
    tar -C "$BUILD_DIR/dnscacher-$pkgver" -xf -

tar -C "$BUILD_DIR" -czf "$BUILD_DIR/dnscacher-$pkgver.tar.gz" "dnscacher-$pkgver"
cp "$PKGBUILD" "$SCRIPT_DIR/dnscacher.install" "$BUILD_DIR/"

cd "$BUILD_DIR"
if (($# == 0)); then
    set -- -si
fi
makepkg "$@"

echo
echo "package directory: $BUILD_DIR"
ls -1 "$BUILD_DIR"/*.pkg.tar.* 2>/dev/null || true
