"""Shared constants and on-disk state locations.

Everything that needs to survive a reboot is written under STATE_DIR so the
manager (and the Holy service) can reload it after the machine comes back up.
"""

import os

# --- Network / benchmark tunables -------------------------------------------
SYNC_PORT = 9876
STREAM_PORT = 5201
TEST_DURATION = 5
SUBNET_LOCAL = "10.99.1.1"
SUBNET_REMOTE = "10.99.1.2"

# --- Install / state layout -------------------------------------------------
INSTALL_DIR = "/opt/Linux-Tunnel-Manager"
STATE_DIR = "/etc/linux-tunnel-manager" if os.path.isdir("/etc") else os.path.expanduser("~/.ltm")
PORT_FWD_FILE = os.path.join(STATE_DIR, "port_forward.json")

# --- Holy endpoint layout ---------------------------------------------------
HOLY_BIN = "/usr/local/bin/holy"
HOLY_DIR = "/etc/holy-tunnel"
HOLY_CONFIG = os.path.join(HOLY_DIR, "config.json")
HOLY_SERVICE = "holy-tunnel"
HOLY_UNIT = f"/etc/systemd/system/{HOLY_SERVICE}.service"

# UDP port used by Holy during a benchmark run (kept separate from any
# installed Holy service so the test never disturbs a live tunnel).
HOLY_BENCH_PORT = 2096

# --- Persistence (restore every tunnel after a reboot) ----------------------
TUNNELS_FILE = os.path.join(STATE_DIR, "tunnels.json")
RESTORE_SERVICE = "ltm-restore"
RESTORE_UNIT = f"/etc/systemd/system/{RESTORE_SERVICE}.service"

# Kernel modules the classic protocols rely on.
MODULES = [
    "ip_gre", "ip_tunnel", "gretap", "ipip", "tunnel4",
    "vxlan", "geneve", "sit", "l2tp_core", "l2tp_netlink",
    "l2tp_ip", "l2tp_eth", "wireguard",
]


def ensure_state_dir():
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except Exception:
        pass
