#!/usr/bin/env bash
# Install dnscacher as a system-wide systemd service.
#
# Usage: sudo deploy/install.sh [--build] [--force-config] [--no-start]
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

BIN=/usr/local/bin/dnscacher
CONFIG=/etc/dnscacher.toml
UNIT=/etc/systemd/system/dnscacher.service
DOCDIR=/usr/local/share/doc/dnscacher

build=0
force_config=0
start=1

usage() {
    cat <<'EOF'
Usage: sudo deploy/install.sh [options]

  --build         run cargo build --release before installing
  --force-config  replace an existing /etc/dnscacher.toml
  --no-start      install the unit but do not enable or start it
  -h, --help      show this help

Without --build, target/release/dnscacher must already exist.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --build) build=1 ;;
        --force-config) force_config=1 ;;
        --no-start) start=0 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    echo "error: run as root, for example: sudo $0" >&2
    exit 1
fi

if [[ $build -eq 1 ]]; then
    cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"
fi

if [[ ! -x "$REPO_DIR/target/release/dnscacher" ]]; then
    echo "error: $REPO_DIR/target/release/dnscacher not found" >&2
    echo "       run 'cargo build --release' first, or pass --build" >&2
    exit 1
fi

install -Dm755 "$REPO_DIR/target/release/dnscacher" "$BIN"
install -Dm644 "$REPO_DIR/deploy/dnscacher.service" "$UNIT"
install -Dm644 "$REPO_DIR/README.md" "$DOCDIR/README.md"
install -Dm644 "$REPO_DIR/LICENSE" "$DOCDIR/LICENSE"

if [[ -e "$CONFIG" && $force_config -eq 0 ]]; then
    echo "keeping existing $CONFIG (use --force-config to replace it)"
else
    install -Dm644 "$REPO_DIR/deploy/dnscacher.toml" "$CONFIG"
    echo "installed $CONFIG"
fi

echo
echo "validating $CONFIG:"
"$BIN" --check --config "$CONFIG" | sed 's/^/  /'

systemctl daemon-reload

if [[ $start -eq 1 ]]; then
    if ! systemctl is-active --quiet dnscacher.service &&
        ss -H -lntu 'sport = :53' 2>/dev/null |
        grep -Eq '(^|[[:space:]])(0\.0\.0\.0|127\.0\.0\.1|\*|\[::\]):53([[:space:]]|$)'; then
        echo
        echo "warning: another process already listens on port 53:"
        ss -H -lntup 'sport = :53' || true
        echo "dnscacher may fail to start; stop the other listener first."
    fi

    if ! systemctl enable --now dnscacher.service; then
        echo >&2
        echo "error: dnscacher failed to start" >&2
        systemctl --no-pager --full status dnscacher.service || true
        journalctl -u dnscacher.service -n 30 --no-pager || true
        exit 1
    fi

    systemctl --no-pager --full status dnscacher.service || true

    cat <<'EOF'

Try it:
  dog example.com @127.0.0.1

Follow the logs:
  journalctl -u dnscacher -f
EOF
else
    echo
    echo "installed but not started; start it with:"
    echo "  systemctl enable --now dnscacher"
fi
