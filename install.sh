#!/usr/bin/env bash
#
# Linux Tunnel Manager — installer
#
#   curl -fsSL https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main/install.sh | sudo bash
#
set -euo pipefail

REPO_URL="https://github.com/amircpuir/Linux-Tunnel-Manager.git"
INSTALL_DIR="/opt/Linux-Tunnel-Manager"
BIN_LINK="/usr/local/bin/tunnel"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: run as root (sudo)."
    exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }

pkg_install() {
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif have dnf; then
        dnf install -y -q "$@"
    elif have yum; then
        yum install -y -q "$@"
    fi
}

echo "==> Checking prerequisites"
have git     || pkg_install git
have python3 || pkg_install python3
have go      || pkg_install golang-go || true   # built on demand if missing

echo "==> Fetching project into ${INSTALL_DIR}"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    git -C "${INSTALL_DIR}" pull --ff-only --quiet
else
    rm -rf "${INSTALL_DIR}"
    git clone --depth 1 --quiet "${REPO_URL}" "${INSTALL_DIR}"
fi

echo "==> Linking launcher to ${BIN_LINK}"
cat > "${BIN_LINK}" <<EOF
#!/usr/bin/env bash
cd "${INSTALL_DIR}" && exec python3 -m ltm "\$@"
EOF
chmod +x "${BIN_LINK}"

echo
echo "Done. Start it with:   sudo tunnel"
echo "or:                    sudo python3 ${INSTALL_DIR}/tunnel.py"
