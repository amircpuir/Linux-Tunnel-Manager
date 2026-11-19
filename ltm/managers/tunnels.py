"""List / delete / inspect / re-address existing tunnel interfaces."""

import time
from typing import Dict, List

from ..core.system import run_cmd
from ..protocols.drivers import TunnelDriver
from . import persistence

IGNORE_PREFIXES = ("lo", "eth", "ens", "enp", "wl", "docker", "br-", "veth")


def list_system_tunnels() -> List[Dict[str, str]]:
    tunnels: List[Dict[str, str]] = []
    ok, out = run_cmd("ip -o link show")
    if not ok or not out:
        return tunnels
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            ifname = parts[1].strip().split("@")[0]
            if not any(ifname.startswith(p) for p in IGNORE_PREFIXES):
                ok_ip, out_ip = run_cmd(f"ip -o -4 addr show dev {ifname}")
                ip_addr = "No IP"
                if ok_ip and out_ip:
                    for ip_line in out_ip.splitlines():
                        if "inet " in ip_line:
                            ip_addr = ip_line.split("inet ")[1].split()[0]
                tunnels.append({"dev": ifname, "ip": ip_addr})
    return tunnels


def get_tunnel_details(dev: str) -> Dict[str, str]:
    info = {"dev": dev, "local_outer": "", "remote_outer": "", "local_tunnel_ip": "", "peer_tunnel_ip": ""}
    ok_wg, out_wg = run_cmd(f"wg show {dev} 2>/dev/null")
    if ok_wg and "endpoint:" in out_wg:
        for line in out_wg.splitlines():
            if "endpoint:" in line:
                info["remote_outer"] = line.split("endpoint:")[1].strip().split(":")[0]

    if not info["remote_outer"]:
        ok, out = run_cmd(f"ip -d link show dev {dev} 2>/dev/null")
        if ok and out:
            for line in out.splitlines():
                s = line.strip()
                parts = s.split()
                if "remote" in parts:
                    r_idx = parts.index("remote")
                    if r_idx + 1 < len(parts):
                        info["remote_outer"] = parts[r_idx + 1]
                    if "local" in parts:
                        l_idx = parts.index("local")
                        if l_idx + 1 < len(parts):
                            info["local_outer"] = parts[l_idx + 1]

    ok_ip, out_ip = run_cmd(f"ip -o -4 addr show dev {dev} 2>/dev/null")
    if ok_ip and out_ip:
        for line in out_ip.splitlines():
            if "inet " in line:
                cidr = line.split("inet ")[1].split()[0]
                ip_only = cidr.split("/")[0]
                info["local_tunnel_ip"] = ip_only
                if cidr.endswith("/30"):
                    octs = ip_only.split(".")
                    last = int(octs[3])
                    peer_last = last + 1 if last % 2 == 1 else last - 1
                    info["peer_tunnel_ip"] = f"{octs[0]}.{octs[1]}.{octs[2]}.{peer_last}"
                elif ip_only.endswith(".1"):
                    info["peer_tunnel_ip"] = ip_only[:-1] + "2"
                elif ip_only.endswith(".2"):
                    info["peer_tunnel_ip"] = ip_only[:-1] + "1"
    return info


def delete_tunnel_menu():
    while True:
        print("\n--- Delete Tunnel Interface ---")
        tunnels = list_system_tunnels()
        if tunnels:
            for i, tun in enumerate(tunnels, 1):
                print(f"{i}) {tun['dev']} ({tun['ip']})")
        else:
            print("No active custom tunnel interfaces found.")
        print("m) Enter custom interface name manually")
        print("0) Back")

        c = input("Select tunnel to delete: ").strip()
        if c == "0":
            break
        if c.lower() == "m":
            target = input("Enter interface name: ").strip()
            if target:
                TunnelDriver.cleanup_interface(target)
                persistence.remove_tunnel(target)
                print(f"Deleted interface {target}")
                time.sleep(1)
        else:
            try:
                idx = int(c) - 1
                if 0 <= idx < len(tunnels):
                    target = tunnels[idx]["dev"]
                    TunnelDriver.cleanup_interface(target)
                    persistence.remove_tunnel(target)
                    print(f"Deleted interface {target}")
                    time.sleep(1)
            except ValueError:
                pass


def change_tunnel_ip_menu():
    while True:
        print("\n--- Change Tunnel IP ---")
        print("1) Change Remote Endpoint IP (Foreign Server IP)")
        print("2) Change Local Tunnel Internal IP")
        print("0) Back")
        c = input("Select: ").strip()
        if c == "0":
            break
        if c == "1":
            dev = input("Enter tunnel interface name (e.g. gre1, ipip1, wg0): ").strip()
            if not dev:
                continue
            new_remote = input("Enter New Remote Server IP: ").strip()
            if not new_remote:
                continue
            ok_wg, _ = run_cmd(f"wg show {dev} 2>/dev/null")
            if ok_wg:
                port = input("Port [51820]: ").strip() or "51820"
                _, out = run_cmd(f"wg show {dev} peers")
                peer_pub = out.strip().split()[0] if out.strip() else ""
                if peer_pub:
                    run_cmd(f"wg set {dev} peer {peer_pub} endpoint {new_remote}:{port}")
                    print(f"WireGuard endpoint updated to {new_remote}:{port}")
                else:
                    print(f"Peer not found for {dev}")
            else:
                _, out_link = run_cmd(f"ip -d link show dev {dev}")
                if "vxlan" in out_link:
                    run_cmd(f"bridge fdb replace 00:00:00:00:00:00 dev {dev} dst {new_remote} 2>/dev/null")
                    run_cmd(f"bridge fdb replace 02:00:00:00:00:02 dev {dev} dst {new_remote} 2>/dev/null")
                    print(f"VXLAN remote destination updated to {new_remote}")
                else:
                    for ptype in ["gre", "gretap", "ipip", "sit"]:
                        ok_chg, _ = run_cmd(f"ip link set dev {dev} type {ptype} remote {new_remote}")
                        if ok_chg:
                            print(f"{dev} ({ptype}) remote endpoint updated to {new_remote}")
                            break
            time.sleep(1.5)
        elif c == "2":
            dev = input("Enter tunnel interface name (e.g. tun1, gre1): ").strip()
            if not dev:
                continue
            new_ip = input("Enter New Tunnel IP (e.g. 10.0.0.1 or 10.0.0.1/30): ").strip()
            if not new_ip:
                continue
            cidr = new_ip if "/" in new_ip else f"{new_ip}/30"
            run_cmd(f"ip addr flush dev {dev}")
            run_cmd(f"ip addr add {cidr} dev {dev}")
            run_cmd(f"ip link set dev {dev} up")
            print(f"Interface {dev} IP changed to {cidr}")
            time.sleep(1.5)
