#!/usr/bin/env bash
# Remove a dnscacher installation created by deploy/install.sh.
#
# Usage: sudo deploy/uninstall.sh [--purge]
set -euo pipefail

BIN=/usr/local/bin/dnscacher
CONFIG=/etc/dnscacher.toml
UNIT=/etc/systemd/system/dnscacher.service
DOCDIR=/usr/local/share/doc/dnscacher
STATE=/var/lib/dnscacher

purge=0

usage() {
    cat <<'EOF'
Usage: sudo deploy/uninstall.sh [options]

  --purge   also remove /etc/dnscacher.toml and /var/lib/dnscacher
  -h, --help
EOF
}

for arg in "$@"; do
    case "$arg" in
        --purge) purge=1 ;;
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

if command -v pacman >/dev/null 2>&1 && pacman -Q dnscacher >/dev/null 2>&1; then
    echo "error: dnscacher is installed as a pacman package" >&2
    echo "       remove it with: sudo pacman -R dnscacher" >&2
    exit 1
fi

# Stop first so the cache is written out cleanly.
systemctl disable --now dnscacher.service 2>/dev/null || true

rm -f "$UNIT"
systemctl daemon-reload 2>/dev/null || true

rm -f "$BIN"
rm -rf "$DOCDIR"

if [[ $purge -eq 1 ]]; then
    rm -f "$CONFIG"
    rm -rf "$STATE"
fi

echo "removed dnscacher"
if [[ $purge -eq 0 ]]; then
    echo "kept $CONFIG and $STATE (use --purge to remove them too)"
fi
