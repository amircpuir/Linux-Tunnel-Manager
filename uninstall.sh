#!/usr/bin/env bash
#
# Linux Tunnel Manager — uninstaller
#
set -euo pipefail

INSTALL_DIR="/opt/Linux-Tunnel-Manager"
BIN_LINK="/usr/local/bin/tunnel"
HOLY_SERVICE="holy-tunnel"
HOLY_BIN="/usr/local/bin/holy"
HOLY_DIR="/etc/holy-tunnel"
HOLY_UNIT="/etc/systemd/system/${HOLY_SERVICE}.service"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: run as root (sudo)."
    exit 1
fi

echo "==> Stopping Holy service (if present)"
systemctl stop "${HOLY_SERVICE}" 2>/dev/null || true
systemctl disable "${HOLY_SERVICE}" 2>/dev/null || true
rm -f "${HOLY_UNIT}" "${HOLY_BIN}"
rm -rf "${HOLY_DIR}"
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing launcher and project"
rm -f "${BIN_LINK}"
rm -rf "${INSTALL_DIR}"

echo "Done. (Active tunnel interfaces, if any, were left untouched —"
echo "run 'sudo tunnel' option 'c' before removing to clean them.)"
