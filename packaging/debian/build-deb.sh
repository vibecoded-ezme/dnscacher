#!/usr/bin/env bash
# Build a Debian binary package from the current working tree.
#
# Usage:
#   ./packaging/debian/build-deb.sh                 # build and run tests
#   ./packaging/debian/build-deb.sh --skip-tests    # build only
#
# The resulting package is written to target/debian/.  This script deliberately
# uses only ar, tar and md5sum so it also works on non-Debian systems; install
# it with `sudo apt install ./target/debian/dnscacher_*.deb`.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_DIR/target/debian"
STAGE_DIR="$BUILD_DIR/pkgroot"
CONTROL_DIR="$BUILD_DIR/control"
PKG=dnscacher

skip_tests=0
for arg in "$@"; do
    case "$arg" in
        --skip-tests) skip_tests=1 ;;
        -h | --help)
            sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

pkgver="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_DIR/Cargo.toml" | head -n1)"
if [[ -z "$pkgver" ]]; then
    echo "error: could not read the version from Cargo.toml" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
        echo "error: unsupported architecture $(uname -m); only 64-bit x86_64 and aarch64 are supported" >&2
        exit 1
        ;;
esac

for tool in ar tar md5sum gzip cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required" >&2
        exit 1
    fi
done

echo "building $PKG $pkgver for $arch"
cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml"
if [[ $skip_tests -eq 0 ]]; then
    cargo test --release --locked --manifest-path "$REPO_DIR/Cargo.toml"
fi

rm -rf "$BUILD_DIR"
mkdir -p \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/etc" \
    "$STAGE_DIR/usr/lib/systemd/system" \
    "$STAGE_DIR/usr/share/doc/$PKG" \
    "$CONTROL_DIR"

install -Dm755 "$REPO_DIR/target/release/dnscacher" "$STAGE_DIR/usr/bin/dnscacher"
install -Dm644 "$REPO_DIR/deploy/dnscacher.toml" "$STAGE_DIR/etc/dnscacher.toml"
install -Dm644 "$REPO_DIR/README.md" "$STAGE_DIR/usr/share/doc/$PKG/README.md"
install -Dm644 "$SCRIPT_DIR/copyright" "$STAGE_DIR/usr/share/doc/$PKG/copyright"
gzip -9n -c "$SCRIPT_DIR/changelog" > "$STAGE_DIR/usr/share/doc/$PKG/changelog.gz"
chmod 644 "$STAGE_DIR/usr/share/doc/$PKG/changelog.gz"

# The source unit targets a /usr/local install; adjust it for the package.
sed -e 's#/usr/local/bin/#/usr/bin/#' \
    -e 's#/usr/local/share/#/usr/share/#' \
    "$REPO_DIR/deploy/dnscacher.service" |
    install -Dm644 /dev/stdin "$STAGE_DIR/usr/lib/systemd/system/dnscacher.service"

# Control metadata.
installed_size="$(du -sk "$STAGE_DIR" | cut -f1)"
cat > "$CONTROL_DIR/control" <<EOF
Package: $PKG
Version: $pkgver
Architecture: $arch
Maintainer: ez-me <66479626+ez-me@users.noreply.github.com>
Installed-Size: $installed_size
Depends: libc6, libgcc-s1
Section: net
Priority: optional
Homepage: https://github.com/vibecoded-ezme/dnscacher
Description: caching DNS forwarder with DoT and DoH support
 dnscacher is a small caching DNS forwarder.  It serves plain DNS over UDP and
 TCP as well as DNS over TLS (DoT) and DNS over HTTPS (DoH), forwards misses to
 plain, DoT or DoH upstreams, and keeps a persistent cache.
 .
 It supports per-domain upstream routing, fixed-lifetime positive and negative
 caching, hosts-file records and deny lists, AdGuard-style \$dnsrewrite rules,
 DNSSEC pass-through modes, and live cache purging through a Unix socket.
EOF

printf '/etc/dnscacher.toml\n' > "$CONTROL_DIR/conffiles"
install -m755 "$SCRIPT_DIR/dnscacher.postinst" "$CONTROL_DIR/postinst"
install -m755 "$SCRIPT_DIR/dnscacher.prerm" "$CONTROL_DIR/prerm"
install -m755 "$SCRIPT_DIR/dnscacher.postrm" "$CONTROL_DIR/postrm"

(
    cd "$STAGE_DIR"
    find . -type f -printf '%P\n' | sort | xargs -r md5sum > "$CONTROL_DIR/md5sums"
)

printf '2.0\n' > "$BUILD_DIR/debian-binary"

# Deterministic archives with root-owned metadata.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
    -C "$STAGE_DIR" -czf "$BUILD_DIR/data.tar.gz" .
(
    cd "$CONTROL_DIR"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
        -czf "$BUILD_DIR/control.tar.gz" \
        control md5sums conffiles postinst prerm postrm
)

DEB="$BUILD_DIR/${PKG}_${pkgver}_${arch}.deb"
rm -f "$DEB"
(cd "$BUILD_DIR" && ar rcD "$DEB" debian-binary control.tar.gz data.tar.gz)

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --info "$DEB" >/dev/null
    echo "dpkg-deb: metadata OK"
fi

echo
echo "package: $DEB"
echo "install with: sudo apt install $DEB"
