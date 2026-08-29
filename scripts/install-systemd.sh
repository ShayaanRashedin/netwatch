#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer as root (for example, with sudo)." >&2
    exit 1
fi

install_prefix="${NETWATCH_PREFIX:-/usr}"
asset_root="${install_prefix}/share/netwatch"

for required in \
    "${install_prefix}/bin/netwatch" \
    "${install_prefix}/bin/netwatch_api" \
    "${asset_root}/systemd/netwatch.service" \
    "${asset_root}/systemd/netwatch-api.service" \
    "${asset_root}/examples/netwatch.env"; do
    if [[ ! -e "${required}" ]]; then
        echo "Missing installed artifact: ${required}" >&2
        echo "Install NetWatch with CMAKE_INSTALL_PREFIX=${install_prefix} first." >&2
        exit 1
    fi
done

if ! getent group netwatch >/dev/null; then
    groupadd --system netwatch
fi

if ! id netwatch >/dev/null 2>&1; then
    useradd \
        --system \
        --gid netwatch \
        --home-dir /var/lib/netwatch \
        --shell /usr/sbin/nologin \
        netwatch
fi

install -d -o root -g netwatch -m 0770 /var/lib/netwatch
install -d -o root -g root -m 0755 /etc/netwatch

if [[ ! -e /etc/netwatch/netwatch.env ]]; then
    install -o root -g root -m 0644 \
        "${asset_root}/examples/netwatch.env" \
        /etc/netwatch/netwatch.env
else
    echo "Preserving existing /etc/netwatch/netwatch.env"
fi

install -o root -g root -m 0644 \
    "${asset_root}/systemd/netwatch.service" \
    /etc/systemd/system/netwatch.service
install -o root -g root -m 0644 \
    "${asset_root}/systemd/netwatch-api.service" \
    /etc/systemd/system/netwatch-api.service

systemctl daemon-reload

echo "NetWatch systemd assets are installed."
echo "Review /etc/netwatch/netwatch.env, then run:"
echo "  systemctl enable --now netwatch netwatch-api"
