"""Low-level system helpers: privilege checks, shell execution, dependencies."""

import os
import sys
import shutil
import subprocess
from typing import Tuple

from ..config import MODULES


def check_root():
    if os.geteuid() != 0:
        print("Error: Root privileges required. Run with sudo.")
        sys.exit(1)


def run_cmd(command: str) -> Tuple[bool, str]:
    """Run a shell command, returning (ok, combined_output)."""
    try:
        res = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        out = res.stdout.strip() if res.stdout else res.stderr.strip()
        return (res.returncode == 0, out)
    except Exception as e:
        return (False, str(e))


def load_modules():
    for mod in MODULES:
        run_cmd(f"modprobe {mod} 2>/dev/null")


def install_deps():
    """Load kernel modules and install any missing userspace tools."""
    load_modules()

    tools = {
        "iperf3": "iperf3",
        "wg": "wireguard-tools",
        "iptables": "iptables",
        "ip": "iproute2",
    }
    missing = [pkg for bin_name, pkg in tools.items() if not shutil.which(bin_name)]

    if missing:
        print(f"Installing dependencies: {', '.join(missing)}...")
        if shutil.which("apt-get"):
            run_cmd(
                "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " + " ".join(missing)
            )
        elif shutil.which("dnf"):
            run_cmd("dnf install -y -q " + " ".join(missing))
        elif shutil.which("yum"):
            run_cmd("yum install -y -q " + " ".join(missing))
        load_modules()


def optimize_sysctl():
    rules = [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0",
        "net.core.rmem_max=67108864",
        "net.core.wmem_max=67108864",
        "net.ipv4.tcp_rmem=4096 87380 67108864",
        "net.ipv4.tcp_wmem=4096 65536 67108864",
        "net.ipv4.tcp_congestion_control=bbr",
    ]
    for r in rules:
        run_cmd(f"sysctl -w {r} 2>/dev/null")
