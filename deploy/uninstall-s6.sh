#!/usr/bin/env bash
# Remove an s6 installation created by deploy/install-s6.sh.
#
# Usage: sudo deploy/uninstall-s6.sh [--purge] [--service-dir DIR]
set -euo pipefail

BIN=/usr/local/bin/dnscacher
CONFIG=/etc/dnscacher.toml
DOCDIR=/usr/local/share/doc/dnscacher
STATE=/var/lib/dnscacher
LOGDIR=/var/log/dnscacher
SERVICES=(dnscacher-srv dnscacher-log)

purge=0
service_dir=

usage() {
    cat <<'EOF'
Usage: sudo deploy/uninstall-s6.sh [options]

  --service-dir DIR   remove the services from DIR instead of autodetecting
  --purge             also remove /etc/dnscacher.toml, the cache and the logs
  -h, --help
EOF
}

while (($#)); do
    case $1 in
        --purge) purge=1 ;;
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

if command -v pacman >/dev/null 2>&1; then
    for pkg in dnscacher-s6 dnscacher; do
        if pacman -Q "$pkg" >/dev/null 2>&1; then
            echo "error: $pkg is installed as a pacman package" >&2
            echo "       remove it with pacman instead of this script" >&2
            exit 1
        fi
    done
fi

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
    service_dir=$(detect_store) || service_dir=
fi

if command -v s6 >/dev/null 2>&1; then
    s6 live stop dnscacher-srv dnscacher-log 2>/dev/null || true
    s6 set disable dnscacher dnscacher-srv dnscacher-log 2>/dev/null || true
    s6 set commit 2>/dev/null || true
    s6 live install 2>/dev/null || true
fi

if [[ -n $service_dir ]]; then
    for service in "${SERVICES[@]}"; do
        rm -rf "${service_dir:?}/$service"
    done
fi

if command -v s6 >/dev/null 2>&1; then
    s6 repository sync 2>/dev/null || true
    s6 set check -F 2>/dev/null || true
    s6 set commit 2>/dev/null || true
    s6 live install 2>/dev/null || true
fi

rm -f "$BIN"
rm -rf "$DOCDIR" /run/dnscacher

if [[ $purge -eq 1 ]]; then
    rm -f "$CONFIG"
    rm -rf "$STATE" "$LOGDIR"
fi

echo "removed dnscacher"
if [[ $purge -eq 0 ]]; then
    echo "kept $CONFIG, $STATE and $LOGDIR (use --purge to remove them too)"
fi
