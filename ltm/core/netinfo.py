"""Network discovery helpers: local/public IPs, gateway, MTU, formatting."""

import socket
from typing import List, Tuple

from .system import run_cmd


def get_public_ip() -> str:
    providers = [
        "curl -s --max-time 2 https://api.ipify.org",
        "curl -s --max-time 2 https://icanhazip.com",
        "curl -s --max-time 2 https://ifconfig.me/ip",
        "curl -s --max-time 2 http://checkip.amazonaws.com",
    ]
    for cmd in providers:
        ok, out = run_cmd(cmd)
        clean = out.strip()
        if ok and len(clean) >= 7 and "." in clean and not any(c in clean for c in ["<", "html", "error", " "]):
            try:
                socket.inet_aton(clean)
                if clean not in ["0.0.0.0", "127.0.0.1"]:
                    return clean
            except socket.error:
                continue

    ok, out = run_cmd("ip -4 route get 8.8.8.8")
    if ok and "src" in out:
        parts = out.split()
        if "src" in parts:
            idx = parts.index("src")
            if idx + 1 < len(parts):
                cand = parts[idx + 1]
                if cand not in ["0.0.0.0", "127.0.0.1"]:
                    return cand
    return "0.0.0.0"


def get_route_ip(remote_ip: str) -> str:
    target = remote_ip if remote_ip and remote_ip not in ["0.0.0.0", "127.0.0.1"] else "8.8.8.8"
    ok, out = run_cmd(f"ip -4 route get {target}")
    if ok and "src" in out:
        parts = out.split()
        if "src" in parts:
            idx = parts.index("src")
            if idx + 1 < len(parts):
                cand = parts[idx + 1]
                if cand not in ["0.0.0.0", "127.0.0.1"] and not cand.startswith("127."):
                    return cand

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        cand = s.getsockname()[0]
        if cand not in ["0.0.0.0", "127.0.0.1"]:
            return cand
    except Exception:
        pass
    finally:
        s.close()

    return get_public_ip()


def get_all_local_ips() -> List[str]:
    ips: List[str] = []
    ok, out = run_cmd("ip -o -4 addr show")
    if ok and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] != "lo":
                ip_addr = parts[3].split("/")[0]
                if (
                    ip_addr not in ["127.0.0.1", "0.0.0.0"]
                    and not ip_addr.startswith("10.99.1.")
                    and not ip_addr.startswith("10.0.0.")
                    and ip_addr not in ips
                ):
                    ips.append(ip_addr)
    pub = get_public_ip()
    if (
        pub
        and pub not in ["0.0.0.0", "127.0.0.1"]
        and not pub.startswith("10.99.1.")
        and not pub.startswith("10.0.0.")
        and pub not in ips
    ):
        ips.append(pub)
    return ips


def get_default_gw() -> Tuple[str, str]:
    ok, out = run_cmd("ip -4 route show default")
    if ok and out:
        parts = out.split()
        if "via" in parts and "dev" in parts:
            gw = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            return gw, dev
    return "", ""


def get_base_mtu(remote_ip: str) -> int:
    target = remote_ip if remote_ip and remote_ip not in ["0.0.0.0", "127.0.0.1"] else "8.8.8.8"
    ok, out = run_cmd(f"ip -4 route get {target}")
    if ok and "dev" in out:
        parts = out.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                dev_name = parts[idx + 1]
                if dev_name != "lo":
                    ok_link, out_link = run_cmd(f"ip link show dev {dev_name}")
                    if ok_link and "mtu" in out_link:
                        lp = out_link.split()
                        if "mtu" in lp:
                            m_idx = lp.index("mtu")
                            if m_idx + 1 < len(lp):
                                try:
                                    val = int(lp[m_idx + 1])
                                    if 1000 <= val <= 9000:
                                        return val
                                except ValueError:
                                    pass
    return 1450


def get_safe_mtu(base_mtu: int) -> int:
    base = min(base_mtu, 1500)
    return max(1280, min(1380, base - 70))


def format_speed(bps: float) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    return f"{bps:.0f} bps"
