"""Persist created tunnels and rebuild them automatically after a reboot.

Kernel tunnels (GRE/IPIP/VXLAN/WireGuard/L2TP/...) live only until the next
reboot. Each one created from the menu is recorded here, and a oneshot systemd
service (`ltm-restore`) replays them on boot. Holy keeps its own service.
"""

import os
import sys
import json
from typing import Any, Dict, List

from ..config import (TUNNELS_FILE, RESTORE_SERVICE, RESTORE_UNIT, INSTALL_DIR,
                      ensure_state_dir)
from ..core.system import run_cmd
from ..protocols.drivers import TunnelDriver


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
def load_tunnels() -> List[Dict[str, Any]]:
    if os.path.exists(TUNNELS_FILE):
        try:
            with open(TUNNELS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _write(tunnels: List[Dict[str, Any]]):
    ensure_state_dir()
    try:
        with open(TUNNELS_FILE, "w") as f:
            json.dump(tunnels, f, indent=2)
        os.chmod(TUNNELS_FILE, 0o600)
    except Exception:
        pass


def save_tunnel(defn: Dict[str, Any]):
    """Record (or replace) a tunnel keyed by its interface name."""
    tunnels = [t for t in load_tunnels() if t.get("dev") != defn.get("dev")]
    tunnels.append(defn)
    _write(tunnels)
    install_boot_service()


def remove_tunnel(dev: str):
    tunnels = [t for t in load_tunnels() if t.get("dev") != dev]
    _write(tunnels)


# --------------------------------------------------------------------------- #
# Boot service
# --------------------------------------------------------------------------- #
_UNIT_TEMPLATE = """[Unit]
Description=Linux Tunnel Manager - restore tunnels on boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={workdir}
ExecStart={python} -m ltm --restore

[Install]
WantedBy=multi-user.target
"""


def install_boot_service():
    if os.path.exists(RESTORE_UNIT):
        return
    workdir = INSTALL_DIR if os.path.isdir(INSTALL_DIR) else os.getcwd()
    try:
        with open(RESTORE_UNIT, "w") as f:
            f.write(_UNIT_TEMPLATE.format(workdir=workdir, python=sys.executable or "/usr/bin/python3"))
        run_cmd("systemctl daemon-reload")
        run_cmd(f"systemctl enable {RESTORE_SERVICE} >/dev/null 2>&1")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Rebuild
# --------------------------------------------------------------------------- #
def _build(defn: Dict[str, Any]) -> bool:
    t = defn.get("type")
    dev = defn.get("dev")
    local_bind = defn.get("local_bind", "")
    remote = defn.get("remote", "")
    my_ip = defn.get("my_ip", "10.0.0.1")
    peer_ip = defn.get("peer_ip", "10.0.0.2")
    mtu = int(defn.get("mtu", 1380))
    port = int(defn.get("port", 0) or 0)

    if t == "wireguard":
        return TunnelDriver.setup_wireguard(dev, defn.get("priv_key", ""), defn.get("peer_pub", ""),
                                            remote, port or 51820, my_ip, peer_ip, mtu)
    if t == "vxlan":
        return TunnelDriver.setup_vxlan(dev, remote, my_ip, peer_ip, mtu, port or 4789, local_bind=local_bind)
    if t == "geneve":
        return TunnelDriver.setup_geneve(dev, remote, my_ip, peer_ip, mtu, port or 6081, local_bind=local_bind)
    if t == "l2tp":
        return TunnelDriver.setup_l2tp(dev, local_bind, remote, my_ip, peer_ip, mtu, port or 5000)
    if t == "sit":
        return TunnelDriver.setup_sit(dev, local_bind, remote, my_ip, peer_ip, mtu)
    if t == "gre":
        return TunnelDriver.setup_gre(dev, local_bind, remote, my_ip, peer_ip, mtu)
    if t == "gretap":
        return TunnelDriver.setup_gretap(dev, local_bind, remote, my_ip, peer_ip, mtu)
    if t == "ipip":
        return TunnelDriver.setup_ipip(dev, local_bind, remote, my_ip, peer_ip, mtu)
    if t == "eoip":
        return TunnelDriver.setup_eoip(dev, local_bind, remote, my_ip, peer_ip, mtu)
    return False


def _post(defn: Dict[str, Any]):
    dev = defn.get("dev")
    my_ip = defn.get("my_ip", "10.0.0.1")
    peer_ip = defn.get("peer_ip", "10.0.0.2")
    run_cmd(f"ip route replace {peer_ip}/32 dev {dev} src {my_ip} 2>/dev/null")
    run_cmd(f"sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 "
            f"net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
    run_cmd(f"iptables -I INPUT 1 -i {dev} -j ACCEPT 2>/dev/null")
    run_cmd(f"iptables -I FORWARD 1 -i {dev} -j ACCEPT 2>/dev/null")
    run_cmd(f"iptables -I FORWARD 1 -o {dev} -j ACCEPT 2>/dev/null")


def restore_all():
    """Rebuild every stored tunnel and re-apply saved port-forward rules."""
    from ..core.system import load_modules, optimize_sysctl
    load_modules()
    optimize_sysctl()

    tunnels = load_tunnels()
    for defn in tunnels:
        ok = _build(defn)
        if ok:
            _post(defn)
        print(f"[restore] {defn.get('type')} {defn.get('dev')}: {'OK' if ok else 'FAIL'}")

    # Re-apply persisted NAT port-forwarding rules.
    try:
        from .portfwd import load_port_fwd_rules, apply_port_fwd_rule
        for r in load_port_fwd_rules():
            apply_port_fwd_rule(r["proto"], r["listen_port"], r["dest_ip"], r["dest_port"])
    except Exception:
        pass
