#!/usr/bin/env bash
# Install dnscacher as an s6-rc service.
#
# Works with Artix s6 (service store /etc/s6/sv, s6-frontend) and with a plain
# s6-frontend installation.  The service is a two-stage pipeline: dnscacher-srv
# produces log output and dnscacher-log consumes it with s6-log.
#
# Usage: sudo deploy/install-s6.sh [--build] [--force-config] [--no-start]
#                                  [--service-dir DIR]
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

BIN=/usr/local/bin/dnscacher
CONFIG=/etc/dnscacher.toml
DOCDIR=/usr/local/share/doc/dnscacher
SERVICES=(dnscacher-srv dnscacher-log)

build=0
force_config=0
start=1
service_dir=

usage() {
    cat <<'EOF'
Usage: sudo deploy/install-s6.sh [options]

  --build             run cargo build --release before installing
  --force-config      replace an existing /etc/dnscacher.toml
  --no-start          install the service but do not enable or start it
  --service-dir DIR   install into DIR instead of autodetecting
                      (normally /etc/s6/sv on Artix)
  -h, --help          show this help

Without --build, target/release/dnscacher must already exist.
EOF
}

while (($#)); do
    case $1 in
        --build) build=1 ;;
        --force-config) force_config=1 ;;
        --no-start) start=0 ;;
        --service-dir)
            if (($# < 2)); then
                echo "error: --service-dir needs a path" >&2
                exit 2
            fi
            service_dir=$2
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

if [[ ${EUID} -ne 0 ]]; then
    echo "error: run as root, for example: sudo $0" >&2
    exit 1
fi

if command -v pacman >/dev/null 2>&1 && pacman -Q dnscacher >/dev/null 2>&1; then
    echo "error: dnscacher is installed as a pacman package." >&2
    echo "       use the matching dnscacher-s6 service package instead of this script," >&2
    echo "       or remove the package before installing from a source tree." >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1 &&
    systemctl is-active --quiet dnscacher.service 2>/dev/null; then
    echo "error: the systemd dnscacher.service is active." >&2
    echo "       stop and disable it before installing the s6 service:" >&2
    echo "       sudo systemctl disable --now dnscacher.service" >&2
    exit 1
fi

if [[ $build -eq 1 ]]; then
    cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"
fi

if [[ ! -x $REPO_DIR/target/release/dnscacher ]]; then
    echo "error: $REPO_DIR/target/release/dnscacher not found" >&2
    echo "       run 'cargo build --release' first, or pass --build" >&2
    exit 1
fi

# s6-frontend stores are listed in /etc/s6-frontend.conf (Artix) or
# /etc/s6.conf (upstream).  Prefer the distribution's /etc/s6/sv layout.
detect_store() {
    local conf store s
    local -a stores

    if [[ -d /etc/s6/sv ]]; then
        printf '%s\n' /etc/s6/sv
        return 0
    fi
    if [[ -d /etc/s6/sources ]]; then
        printf '%s\n' /etc/s6/sources
        return 0
    fi
    for conf in /etc/s6-frontend.conf /etc/s6.conf; do
        [[ -r $conf ]] || continue
        store=$(sed -n 's/^[[:space:]]*storelist[[:space:]]*=[[:space:]]*//p' "$conf" | head -n1)
        [[ -n $store ]] || continue
        IFS=: read -r -a stores <<<"$store"
        for s in "${stores[@]}"; do
            s=${s%/}
            case $s in
                /etc/*)
                    printf '%s\n' "$s"
                    return 0
                    ;;
            esac
        done
    done
    return 1
}

if [[ -z $service_dir ]]; then
    if ! service_dir=$(detect_store); then
        echo "error: no s6 service store found" >&2
        echo "       install s6/s6-rc, or pass --service-dir DIR" >&2
        exit 1
    fi
fi

install -Dm755 "$REPO_DIR/target/release/dnscacher" "$BIN"
install -Dm644 "$REPO_DIR/README.md" "$DOCDIR/README.md"
install -Dm644 "$REPO_DIR/LICENSE" "$DOCDIR/LICENSE"
install -d "$DOCDIR/doc"
install -m644 "$REPO_DIR"/doc/*.md "$DOCDIR/doc/"

if [[ -e $CONFIG && $force_config -eq 0 ]]; then
    echo "keeping existing $CONFIG (use --force-config to replace it)"
else
    install -Dm644 "$REPO_DIR/deploy/dnscacher.toml" "$CONFIG"
    echo "installed $CONFIG"
fi

install -d "$service_dir"
for service in "${SERVICES[@]}"; do
    install -d "$service_dir/$service"
    cp -a "$REPO_DIR/deploy/s6/$service/." "$service_dir/$service/"
    chmod 0755 "$service_dir/$service/run"
done
echo "installed s6 services in $service_dir"

echo
echo "validating $CONFIG:"
"$BIN" --check --config "$CONFIG" | sed 's/^/  /'

if ! command -v s6 >/dev/null 2>&1; then
    cat <<EOF

s6-frontend was not found; the service files are installed but not
registered.  Register "$service_dir" with your s6-rc setup, or install
s6-frontend and use:

  s6 repository init
  s6 repository sync
  s6 set enable dnscacher
  s6 set commit
  s6 live install
  s6 live start dnscacher

On Artix, add dnscacher to the boot bundle and rebuild the compiled
database with the distribution's s6-rc procedure.
EOF
    exit 0
fi

# A first s6-frontend installation may not have a repository yet.
if ! s6 repository sync; then
    echo "s6-frontend repository is not initialized; running 's6 repository init'"
    if ! s6 repository init; then
        echo "error: could not initialize the s6-frontend repository" >&2
        exit 1
    fi
    s6 repository sync
fi

if [[ $start -eq 0 ]]; then
    cat <<EOF

installed but not enabled.  Enable and start it with:

  s6 set enable dnscacher
  s6 set commit
  s6 live install
  s6 live start dnscacher
EOF
    exit 0
fi

if ! s6 set enable dnscacher; then
    echo "error: could not enable dnscacher in the current service set" >&2
    exit 1
fi
s6 set commit
s6 live install
s6 live start dnscacher

echo
s6 live status dnscacher-srv dnscacher-log || true
s6 process status dnscacher-srv || true

cat <<'EOF'

Try it:
  dog example.com @127.0.0.1

Follow the logs:
  tail -F /var/log/dnscacher/current
EOF
