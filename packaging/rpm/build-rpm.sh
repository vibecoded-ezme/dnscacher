#!/usr/bin/env bash
# Build a binary RPM for Fedora, CentOS Stream and RHEL from the current tree.
#
# The preferred binary is the static-PIE musl build: it has no glibc version
# dependency, so one package runs on every supported RPM distribution.  By
# default the script builds it if necessary; use --host to package the normal
# glibc binary for the current distribution instead.
#
# Usage:
#   ./packaging/rpm/build-rpm.sh              # static musl (build it if needed)
#   ./packaging/rpm/build-rpm.sh --musl       # require the static musl build
#   ./packaging/rpm/build-rpm.sh --host       # package target/release/dnscacher
#   ./packaging/rpm/build-rpm.sh --skip-build # do not run cargo
#   ./packaging/rpm/build-rpm.sh --release 2  # set the RPM release number
#
# Build requirements:
#   Fedora/RHEL:  sudo dnf install rpm-build file
#   Arch:         rpm-tools
#
# Rebuilding the musl binary additionally needs the Rust musl target and a musl
# C compiler (Arch: rust-musl + musl; Debian: musl-tools).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_DIR/target/rpm"
SPEC="$SCRIPT_DIR/dnscacher.spec"
PKG=dnscacher

mode=auto
skip_build=0
pkgrel=1

usage() {
    cat <<'EOF'
Build a binary RPM for Fedora, CentOS Stream and RHEL from the current tree.

Usage:
  ./packaging/rpm/build-rpm.sh              static musl, building it if needed
  ./packaging/rpm/build-rpm.sh --musl       require the static musl build
  ./packaging/rpm/build-rpm.sh --host       package target/release/dnscacher
  ./packaging/rpm/build-rpm.sh --skip-build do not run cargo
  ./packaging/rpm/build-rpm.sh --release N  set the RPM release number
  ./packaging/rpm/build-rpm.sh --help

Build requirements:
  Fedora/RHEL: sudo dnf install rpm-build file
  Arch:        rpm-tools
  musl build:  Rust musl target and musl-gcc (Arch: rust-musl + musl)
EOF
}

while (($#)); do
    case $1 in
        --musl) mode=musl ;;
        --host | --glibc) mode=host ;;
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

case "$(uname -m)" in
    x86_64 | amd64)
        rpm_arch=x86_64
        musl_triple=x86_64-unknown-linux-musl
        ;;
    aarch64 | arm64)
        rpm_arch=aarch64
        musl_triple=aarch64-unknown-linux-musl
        ;;
    ppc64le)
        rpm_arch=ppc64le
        musl_triple=powerpc64le-unknown-linux-musl
        ;;
    s390x)
        rpm_arch=s390x
        musl_triple=s390x-unknown-linux-musl
        ;;
    *)
        echo "error: unsupported architecture $(uname -m); only 64-bit targets are supported" >&2
        exit 1
        ;;
esac

for tool in rpmbuild tar install sed cp file; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required" >&2
        if [[ $tool == rpmbuild ]]; then
            echo "       Fedora/RHEL: sudo dnf install rpm-build" >&2
            echo "       Arch:        install rpm-tools" >&2
        fi
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
    libdir="$(rustc --print target-libdir --target "$musl_triple" 2>/dev/null)" || return 1
    [[ -d $libdir ]]
}

build_musl() {
    if ! has_musl_toolchain; then
        cat >&2 <<EOF
error: cannot build the $musl_triple target.

Install a musl C compiler and the Rust target, for example:
  Arch:   sudo pacman -S rust-musl musl
  Debian: sudo apt install musl-tools && rustup target add $musl_triple
  Fedora: use --host to package the glibc binary for this distribution

EOF
        return 1
    fi

    local cc_var="CC_${musl_triple//-/_}"
    local linker_var="CARGO_TARGET_$(echo "$musl_triple" | tr '[:lower:]-' '[:upper:]_')_LINKER"
    echo "building static $musl_triple binary"
    env "$cc_var=musl-gcc" "$linker_var=cc" \
        cargo build --release --locked --target "$musl_triple" \
        --manifest-path "$REPO_DIR/Cargo.toml"
}

build_host() {
    echo "building host release binary"
    cargo build --release --locked --manifest-path "$REPO_DIR/Cargo.toml"
}

binary=
case $mode in
    musl)
        if [[ ! -x $musl_bin ]] || newer_than_binary "$musl_bin"; then
            if ((skip_build)); then
                echo "error: $musl_bin is missing or older than the sources" >&2
                exit 1
            fi
            build_musl
        fi
        if ! is_static "$musl_bin"; then
            echo "error: $musl_bin is not statically linked" >&2
            exit 1
        fi
        binary=$musl_bin
        ;;
    host)
        if [[ ! -x $host_bin ]] || newer_than_binary "$host_bin"; then
            if ((skip_build)); then
                echo "error: $host_bin is missing or older than the sources" >&2
                exit 1
            fi
            build_host
        fi
        binary=$host_bin
        ;;
    auto)
        if [[ -x $musl_bin ]] && is_static "$musl_bin"; then
            if newer_than_binary "$musl_bin"; then
                if ((skip_build)); then
                    echo "warning: $musl_bin is older than the sources; using it anyway" >&2
                elif has_musl_toolchain; then
                    build_musl
                else
                    echo "error: $musl_bin is older than the sources and the musl toolchain is missing" >&2
                    echo "       install it, pass --skip-build to accept the old binary, or use --host" >&2
                    exit 1
                fi
            fi
        else
            if ((skip_build)); then
                echo "error: no static musl binary found" >&2
                echo "       build $musl_bin first or pass --host" >&2
                exit 1
            fi
            if ! build_musl; then
                echo "hint: use --host to package the glibc binary for this distribution" >&2
                exit 1
            fi
            if ! is_static "$musl_bin"; then
                echo "error: $musl_bin is not statically linked" >&2
                exit 1
            fi
        fi
        binary=$musl_bin
        ;;
esac

if [[ ! -x $binary ]]; then
    echo "error: $binary is not executable" >&2
    exit 1
fi

if is_static "$binary"; then
    echo "packaging static binary: $binary"
else
    echo "packaging dynamically linked binary: $binary" >&2
    echo "warning: this RPM inherits the build host's glibc requirement." >&2
    echo "         Build on the oldest distribution you need to support, or use --musl." >&2
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
stage="$BUILD_DIR/$PKG-$pkgver"

install -Dm755 "$binary" "$stage/usr/bin/$PKG"
install -Dm644 "$REPO_DIR/deploy/dnscacher.toml" "$stage/etc/dnscacher.toml"
install -Dm644 "$REPO_DIR/README.md" "$stage/README.md"
install -Dm644 "$REPO_DIR/LICENSE" "$stage/LICENSE"

# The source unit targets a /usr/local install; adjust it for the package.
sed -e 's#/usr/local/bin/#/usr/bin/#' \
    -e 's#/usr/local/share/#/usr/share/#' \
    "$REPO_DIR/deploy/dnscacher.service" |
    install -Dm644 /dev/stdin "$stage/usr/lib/systemd/system/dnscacher.service"

tar --sort=name --owner=0 --group=0 --numeric-owner \
    -C "$BUILD_DIR" -czf "$BUILD_DIR/SOURCES/$PKG-$pkgver.tar.gz" "$PKG-$pkgver"
cp "$SPEC" "$BUILD_DIR/SPECS/"

echo "building RPM $PKG $pkgver-$pkgrel for $rpm_arch"
rpmbuild -bb \
    --define "_topdir $BUILD_DIR" \
    --define "dnscacher_version $pkgver" \
    --define "dnscacher_release $pkgrel" \
    --define "dnscacher_arch $rpm_arch" \
    "$BUILD_DIR/SPECS/dnscacher.spec"

rpmfile="$(find "$BUILD_DIR/RPMS/$rpm_arch" -maxdepth 1 -name '*.rpm' -print -quit)"
if [[ -z $rpmfile ]]; then
    echo "error: rpmbuild did not produce a package" >&2
    exit 1
fi

echo
echo "package: $rpmfile"
echo "install with: sudo dnf install $rpmfile"
