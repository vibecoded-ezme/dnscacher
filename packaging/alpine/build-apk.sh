#!/usr/bin/env bash
# Build Alpine .apk packages from the current tree.
#
# The prebuilt package contains the static musl binary, so it has no runtime
# library dependencies.  It is created with "apk mkpkg" (apk-tools 3) and is
# therefore intended for Alpine 3.23 and newer.  For older Alpine releases use
# packaging/alpine/APKBUILD with abuild on the target release.
#
# Usage:
#   ./packaging/alpine/build-apk.sh              # build the static binary if needed
#   ./packaging/alpine/build-apk.sh --skip-build # reuse an existing binary
#   ./packaging/alpine/build-apk.sh --release 1  # set the Alpine pkgrel
#
# Requirements:
#   - apk-tools 3: "apk" on Alpine, or set APK=/path/to/apk.static
#   - the static musl binary, or a way to build it (see below)
#   - unshare -r when running as a normal user, so packaged files are root-owned
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_DIR/target/alpine"
PKG=dnscacher
PKGDESC="Caching DNS forwarder with UDP, TCP, DoT and DoH support"
URL="https://github.com/vibecoded-ezme/dnscacher"
MAINTAINER="ez-me <66479626+ez-me@users.noreply.github.com>"

skip_build=0
pkgrel=0

usage() {
    cat <<'EOF'
Build Alpine .apk packages from the current tree.

Usage:
  ./packaging/alpine/build-apk.sh              build the static binary if needed
  ./packaging/alpine/build-apk.sh --skip-build reuse an existing binary
  ./packaging/alpine/build-apk.sh --release N set the Alpine pkgrel (default 0)

Environment:
  APK=/path/to/apk.static   apk-tools 3 binary to use for "apk mkpkg"

Requirements:
  apk-tools 3, a static musl binary, and (for non-root builds) unshare -r.
  Building the binary needs cargo plus the Rust musl target and musl-gcc.
EOF
}

while (($#)); do
    case $1 in
        --skip-build) skip_build=1 ;;
        --release)
            if (($# < 2)); then
                echo "error: --release needs a number" >&2
                exit 2
            fi
            pkgrel=$2
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

pkgver="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_DIR/Cargo.toml" | head -n1)"
if [[ -z $pkgver ]]; then
    echo "error: could not read the version from Cargo.toml" >&2
    exit 1
fi
fullver="$pkgver-r$pkgrel"

case "$(uname -m)" in
    x86_64 | amd64)
        apk_arch=x86_64
        musl_triple=x86_64-unknown-linux-musl
        ;;
    aarch64 | arm64)
        apk_arch=aarch64
        musl_triple=aarch64-unknown-linux-musl
        ;;
    ppc64le)
        apk_arch=ppc64le
        musl_triple=powerpc64le-unknown-linux-musl
        ;;
    s390x)
        apk_arch=s390x
        musl_triple=s390x-unknown-linux-musl
        ;;
    *)
        echo "error: unsupported architecture $(uname -m); only 64-bit targets are supported" >&2
        exit 1
        ;;
esac

APK="${APK:-$(command -v apk || command -v apk.static || true)}"
if [[ -z $APK || ! -x $APK ]]; then
    echo "error: apk-tools 3 is required to create the package" >&2
    echo "       on Alpine: apk add apk-tools" >&2
    echo "       elsewhere: set APK=/path/to/apk.static from apk-tools-static" >&2
    exit 1
fi
if ! "$APK" --version 2>/dev/null | grep -q '^apk-tools 3\.'; then
    echo "error: $APK is not apk-tools 3; 'apk mkpkg' is unavailable" >&2
    echo "       use packaging/alpine/APKBUILD with abuild on this Alpine release" >&2
    exit 1
fi

for tool in file; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required" >&2
        exit 1
    fi
done

musl_bin="$REPO_DIR/target/$musl_triple/release/dnscacher"
host_bin="$REPO_DIR/target/release/dnscacher"

is_static() {
    file -b "$1" 2>/dev/null | grep -q 'static'
}

newer_than_binary() {
    local bin=$1
    [[ -e $bin ]] || return 0
    find "$REPO_DIR/src" "$REPO_DIR/Cargo.toml" "$REPO_DIR/Cargo.lock" \
        -newer "$bin" -print -quit 2>/dev/null | grep -q .
}

has_musl_toolchain() {
    local libdir
    command -v musl-gcc >/dev/null 2>&1 || return 1
    command -v rustc >/dev/null 2>&1 || return 1
    libdir="$(rustc --print target-libdir --target "$musl_triple" 2>/dev/null)" || return 1
    [[ -d $libdir ]]
}

require_cargo() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "error: cargo is required to build the binary" >&2
        exit 1
    fi
}

build_musl() {
    require_cargo
    local cc_var="CC_${musl_triple//-/_}"
    local linker_var="CARGO_TARGET_$(echo "$musl_triple" | tr '[:lower:]-' '[:upper:]_')_LINKER"
    echo "building static $musl_triple binary"
    env "$cc_var=musl-gcc" "$linker_var=cc" \
        cargo build --release --locked --target "$musl_triple" \
        --manifest-path "$REPO_DIR/Cargo.toml"
}

binary=
if [[ -x $musl_bin ]] && is_static "$musl_bin"; then
    if newer_than_binary "$musl_bin" && ((skip_build == 0)); then
        if has_musl_toolchain; then
            build_musl
        else
            echo "warning: $musl_bin is older than the sources; using it anyway" >&2
        fi
    fi
    binary=$musl_bin
elif [[ -x $host_bin ]] && is_static "$host_bin"; then
    if newer_than_binary "$host_bin" && ((skip_build == 0)); then
        require_cargo
        echo "building host release binary"
        cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml"
    fi
    binary=$host_bin
elif ((skip_build)); then
    echo "error: no static binary found" >&2
    exit 1
elif [[ -f /etc/alpine-release ]]; then
    require_cargo
    echo "building host release binary"
    cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml"
    binary=$host_bin
elif has_musl_toolchain; then
    build_musl
    binary=$musl_bin
else
    cat >&2 <<EOF
error: no static musl binary found for $musl_triple.

Build it first, for example on Alpine:
  cargo build --release --locked

Or install the Rust musl target and a musl C compiler:
  Arch:   sudo pacman -S rust-musl musl
  Debian: sudo apt install musl-tools && rustup target add $musl_triple

EOF
    exit 1
fi

if [[ ! -x $binary ]] || ! is_static "$binary"; then
    echo "error: $binary is not a static executable" >&2
    exit 1
fi

echo "packaging static binary: $binary"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/main" "$BUILD_DIR/openrc"
main="$BUILD_DIR/main"
openrc="$BUILD_DIR/openrc"
pre="$BUILD_DIR/pre-install"

install -Dm755 "$binary" "$main/usr/bin/$PKG"
install -Dm644 "$REPO_DIR/deploy/dnscacher.toml" "$main/etc/dnscacher.toml"
install -Dm644 "$REPO_DIR/README.md" "$main/usr/share/doc/$PKG/README.md"
install -Dm644 "$REPO_DIR/LICENSE" "$main/usr/share/licenses/$PKG/LICENSE"

install -Dm755 "$SCRIPT_DIR/$PKG.initd" "$openrc/etc/init.d/$PKG"
install -Dm644 "$SCRIPT_DIR/$PKG.confd" "$openrc/etc/conf.d/$PKG"

cat > "$pre" <<'EOF'
#!/bin/sh
addgroup -S dnscacher 2>/dev/null
adduser -S -D -H -h /var/lib/dnscacher -s /sbin/nologin \
	-G dnscacher -g "dnscacher service user" dnscacher 2>/dev/null
exit 0
EOF
chmod 755 "$pre"

# apk mkpkg records the ownership of the staged files.  Build them as uid 0 in
# a user namespace so the installed files are owned by root.
make_script="$BUILD_DIR/make-apk.sh"
cat > "$make_script" <<'EOF'
#!/bin/sh
set -eu
main=$1
openrc=$2
pre=$3
apk=$4
ver=$5
arch=$6
out=$7
desc=$8
url=$9
maint=${10}

chown -R 0:0 "$main" "$openrc" "$pre"

"$apk" mkpkg \
	--info "name:dnscacher" \
	--info "version:$ver" \
	--info "description:$desc" \
	--info "url:$url" \
	--info "arch:$arch" \
	--info "license:MIT" \
	--info "origin:dnscacher" \
	--info "maintainer:$maint" \
	--script "pre-install:$pre" \
	--files "$main" \
	--output "$out/dnscacher-$ver.apk"

"$apk" mkpkg \
	--info "name:dnscacher-openrc" \
	--info "version:$ver" \
	--info "description:$desc (OpenRC init scripts)" \
	--info "url:$url" \
	--info "arch:noarch" \
	--info "license:MIT" \
	--info "origin:dnscacher" \
	--info "maintainer:$maint" \
	--info "install-if:openrc dnscacher=$ver" \
	--files "$openrc" \
	--output "$out/dnscacher-openrc-$ver.apk"
EOF
chmod 755 "$make_script"

args=("$main" "$openrc" "$pre" "$APK" "$fullver" "$apk_arch" "$BUILD_DIR" \
    "$PKGDESC" "$URL" "$MAINTAINER")

if [[ ${EUID} -eq 0 ]]; then
    sh "$make_script" "${args[@]}"
elif command -v unshare >/dev/null 2>&1 && unshare -r true 2>/dev/null; then
    unshare -r sh "$make_script" "${args[@]}"
else
    echo "error: cannot create root-owned package files" >&2
    echo "       run this script as root, or enable unprivileged user namespaces" >&2
    exit 1
fi

main_apk="$BUILD_DIR/$PKG-$fullver.apk"
openrc_apk="$BUILD_DIR/$PKG-openrc-$fullver.apk"
for f in "$main_apk" "$openrc_apk"; do
    if [[ ! -f $f ]]; then
        echo "error: apk mkpkg did not create $f" >&2
        exit 1
    fi
done

echo
echo "packages:"
echo "  $main_apk"
echo "  $openrc_apk"
echo
echo "install with:"
echo "  sudo apk add --allow-untrusted $main_apk $openrc_apk"
echo "  sudo rc-update add dnscacher default"
echo "  sudo rc-service dnscacher start"
