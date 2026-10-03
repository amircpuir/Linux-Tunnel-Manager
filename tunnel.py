#!/usr/bin/env python3


import os
import sys
import time
import socket
import select
import struct
import json
import threading
import subprocess
import signal
import shutil
import argparse
import atexit
from typing import Dict, Any, List, Optional, Tuple

SYNC_PORT = 9876
STREAM_PORT = 5201
TEST_DURATION = 5
SUBNET_LOCAL = "10.99.1.1"
SUBNET_REMOTE = "10.99.1.2"

PROTOCOLS = [
    {"id": "ipip", "name": "IPIP", "layer": "L3", "port": None},
    {"id": "gre", "name": "GRE", "layer": "L3", "port": None},
    {"id": "gretap", "name": "GRETAP", "layer": "L2", "port": None},
    {"id": "eoip", "name": "EoIP", "layer": "L2", "port": None},
    {"id": "vxlan", "name": "VXLAN", "layer": "L2", "port": 4789},
    {"id": "geneve", "name": "GENEVE", "layer": "L2", "port": 6081},
    {"id": "sit", "name": "SIT-6in4", "layer": "L3", "port": None},
    {"id": "l2tp", "name": "L2TPv3", "layer": "L2", "port": 5000},
    {"id": "wireguard", "name": "WireGuard", "layer": "L3", "port": 51820}
]

MODULES = [
    "ip_gre", "ip_tunnel", "gretap", "ipip", "tunnel4", 
    "vxlan", "geneve", "sit", "l2tp_core", "l2tp_netlink", "l2tp_ip", "l2tp_eth", "wireguard"
]

def check_root():
    if os.geteuid() != 0:
        print("Error: Root privileges required. Run with sudo.")
        sys.exit(1)

def run_cmd(command: str) -> Tuple[bool, str]:
    try:
        res = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        out = res.stdout.strip() if res.stdout else res.stderr.strip()
        return (res.returncode == 0, out)
    except Exception as e:
        return (False, str(e))

def install_deps():
    for mod in MODULES:
        run_cmd(f"modprobe {mod} 2>/dev/null")

    tools = {"iperf3": "iperf3", "wg": "wireguard-tools", "iptables": "iptables", "ip": "iproute2"}
    missing = [pkg for bin_name, pkg in tools.items() if not shutil.which(bin_name)]

    if missing:
        print(f"Installing dependencies: {', '.join(missing)}...")
        if shutil.which("apt-get"):
            run_cmd("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " + " ".join(missing))
        elif shutil.which("dnf"):
            run_cmd("dnf install -y -q " + " ".join(missing))
        elif shutil.which("yum"):
            run_cmd("yum install -y -q " + " ".join(missing))
        for mod in MODULES:
            run_cmd(f"modprobe {mod} 2>/dev/null")

def optimize_sysctl():
    rules = [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0",
        "net.core.rmem_max=67108864",
        "net.core.wmem_max=67108864",
        "net.ipv4.tcp_rmem=4096 87380 67108864",
        "net.ipv4.tcp_wmem=4096 65536 67108864",
        "net.ipv4.tcp_congestion_control=bbr"
    ]
    for r in rules:
        run_cmd(f"sysctl -w {r} 2>/dev/null")

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
    ips = []
    ok, out = run_cmd("ip -o -4 addr show")
    if ok and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] != "lo":
                ip_with_mask = parts[3]
                ip_addr = ip_with_mask.split('/')[0]
                if ip_addr not in ["127.0.0.1", "0.0.0.0"] and not ip_addr.startswith("10.99.1.") and not ip_addr.startswith("10.0.0."):
                    if ip_addr not in ips:
                        ips.append(ip_addr)
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
                        link_parts = out_link.split()
                        if "mtu" in link_parts:
                            m_idx = link_parts.index("mtu")
                            if m_idx + 1 < len(link_parts):
                                try:
                                    val = int(link_parts[m_idx + 1])
                                    if 1000 <= val <= 9000:
                                        return val
                                except ValueError:
                                    pass
    return 1450

def get_safe_mtu(base_mtu: int) -> int:
    base = min(base_mtu, 1500)
    return max(1280, min(1380, base - 70))

def get_public_ip() -> str:
    providers = [
        "curl -s --max-time 2 https://api.ipify.org",
        "curl -s --max-time 2 https://icanhazip.com",
        "curl -s --max-time 2 https://ifconfig.me/ip",
        "curl -s --max-time 2 http://checkip.amazonaws.com"
    ]
    for cmd in providers:
        ok, out = run_cmd(cmd)
        clean = out.strip()
        if ok and len(clean) >= 7 and "." in clean and not any(c in clean for c in ['<', 'html', 'error', ' ']):
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

def format_speed(bps: float) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    return f"{bps:.0f} bps"

def open_firewall(ports: Dict[str, Optional[int]]):
    run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p 4 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p 41 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p 50 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -s 10.99.1.0/30 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I FORWARD 1 -s 10.99.1.0/30 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I FORWARD 1 -d 10.99.1.0/30 -j ACCEPT 2>/dev/null")

    for p_name, p_val in ports.items():
        if p_val:
            run_cmd(f"iptables -I INPUT 1 -p udp --dport {p_val} -j ACCEPT 2>/dev/null")
            run_cmd(f"iptables -I INPUT 1 -p tcp --dport {p_val} -j ACCEPT 2>/dev/null")

def send_msg(sock: socket.socket, data: dict):
    payload = json.dumps(data).encode('utf-8')
    header = struct.pack('!I', len(payload))
    sock.sendall(header + payload)

def recv_msg(sock: socket.socket, timeout: Optional[float] = None) -> Optional[dict]:
    if timeout:
        sock.settimeout(timeout)
    try:
        header = sock.recv(4)
        if not header or len(header) < 4:
            return None
        length = struct.unpack('!I', header)[0]
        data = bytearray()
        while len(data) < length:
            packet = sock.recv(min(4096, length - len(data)))
            if not packet:
                return None
            data.extend(packet)
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None

def gen_wg_keys() -> Tuple[str, str]:
    ok, priv = run_cmd("wg genkey")
    if ok and priv.strip():
        priv_k = priv.strip()
        ok2, pub = run_cmd(f"echo '{priv_k}' | wg pubkey")
        if ok2 and pub.strip():
            return priv_k, pub.strip()
    return "yAnz5TF+lXXJte14tji3nhMNqPrLdNeHQL8pYfWqX28=", "0mFv3l138HjM5cKfZ0Yd/3yX6M8Lp7mQ9tZ5r1k2vXw="

class TunnelDriver:
    @staticmethod
    def cleanup_interface(dev: str):
        if not dev or dev in ["lo", "eth0", "ens3", "ens4", "enp0s3", "eth1"]:
            return
        run_cmd(f"ip link set dev {dev} nomaster 2>/dev/null")
        run_cmd(f"ip addr flush dev {dev} 2>/dev/null")
        run_cmd(f"ip link set dev {dev} down 2>/dev/null")
        run_cmd(f"ip link delete dev {dev} 2>/dev/null")
        run_cmd(f"wg-quick down {dev} 2>/dev/null")
        run_cmd("ip l2tp del session tunnel_id 1000 session_id 1000 2>/dev/null")
        run_cmd("ip l2tp del session tunnel_id 2000 session_id 2000 2>/dev/null")
        run_cmd("ip l2tp del tunnel tunnel_id 1000 2>/dev/null")
        run_cmd("ip l2tp del tunnel tunnel_id 2000 2>/dev/null")
        run_cmd(f"ip route del 10.99.1.0/30 dev {dev} 2>/dev/null")

    @staticmethod
    def setup_wireguard(dev: str, priv_key: str, peer_pub_key: str, remote_ip: str, port: int, my_ip: str, peer_ip: str, mtu: int) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe wireguard 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        ok, _ = run_cmd(f"ip link add dev {dev} type wireguard")
        if not ok:
            return False

        key_file = f"/tmp/{dev}.key"
        try:
            with open(key_file, "w") as f:
                f.write(priv_key.strip())
            run_cmd(f"wg set {dev} private-key {key_file} listen-port {port}")
        finally:
            if os.path.exists(key_file):
                os.remove(key_file)

        endpoint = f"endpoint {remote_ip}:{port}" if remote_ip and remote_ip not in ["0.0.0.0", "127.0.0.1"] else ""
        run_cmd(f"wg set {dev} peer {peer_pub_key} allowed-ips 0.0.0.0/0 {endpoint} persistent-keepalive 5")
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_gre(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe ip_gre 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type gre remote {remote_ip} local {local_bind} ttl 255"
        ok, _ = run_cmd(cmd)
        if not ok:
            ok, _ = run_cmd(f"ip link add {dev} type gre remote {remote_ip} ttl 255")
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_gretap(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe gretap 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type gretap remote {remote_ip} local {local_bind} ttl 255"
        ok, _ = run_cmd(cmd)
        if not ok:
            ok, _ = run_cmd(f"ip link add {dev} type gretap remote {remote_ip} ttl 255")
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_ipip(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe ipip 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 4 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type ipip remote {remote_ip} local {local_bind} ttl 255"
        ok, _ = run_cmd(cmd)
        if not ok:
            ok, _ = run_cmd(f"ip link add {dev} type ipip remote {remote_ip} ttl 255")
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_eoip(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int, tid: int = 10) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe gretap 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type gretap remote {remote_ip} local {local_bind} key {tid}"
        ok, _ = run_cmd(cmd)
        if not ok:
            cmd = f"ip link add {dev} type gretap remote {remote_ip} key {tid}"
            ok, _ = run_cmd(cmd)
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_vxlan(dev: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int, dst_port: int = 4789, vni: int = 100, is_server: bool = False) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe vxlan 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -p udp --dport {dst_port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type vxlan id {vni} remote {remote_ip} dstport {dst_port}"
        ok, _ = run_cmd(cmd)
        if not ok:
            cmd = f"ip link add {dev} type vxlan id {vni} dstport {dst_port}"
            ok, _ = run_cmd(cmd)
        if not ok:
            return False

        my_mac = "02:00:00:00:00:02" if is_server else "02:00:00:00:00:01"
        peer_mac = "02:00:00:00:00:01" if is_server else "02:00:00:00:00:02"

        run_cmd(f"ip link set dev {dev} address {my_mac}")
        run_cmd(f"ip link set {dev} mtu {min(mtu, 1350)} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip neigh replace {peer_ip} lladdr {peer_mac} dev {dev} nud permanent")
        run_cmd(f"bridge fdb replace 00:00:00:00:00:00 dev {dev} dst {remote_ip} 2>/dev/null")
        run_cmd(f"bridge fdb replace {peer_mac} dev {dev} dst {remote_ip} 2>/dev/null")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_geneve(dev: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int, dst_port: int = 6081, vni: int = 100, is_server: bool = False) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe geneve 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -p udp --dport {dst_port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type geneve id {vni} remote {remote_ip} dstport {dst_port}"
        ok, _ = run_cmd(cmd)
        if not ok:
            return False

        my_mac = "02:00:00:00:00:02" if is_server else "02:00:00:00:00:01"
        peer_mac = "02:00:00:00:00:01" if is_server else "02:00:00:00:00:02"

        run_cmd(f"ip link set dev {dev} address {my_mac}")
        run_cmd(f"ip link set {dev} mtu {min(mtu, 1350)} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip neigh replace {peer_ip} lladdr {peer_mac} dev {dev} nud permanent")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_sit(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe sit 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 41 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        cmd = f"ip link add {dev} type sit remote {remote_ip} local {local_bind} ttl 255"
        ok, _ = run_cmd(cmd)
        if not ok:
            cmd = f"ip link add {dev} type sit remote {remote_ip} ttl 255"
            ok, _ = run_cmd(cmd)
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

    @staticmethod
    def setup_l2tp(dev: str, local_bind: str, remote_ip: str, my_ip: str, peer_ip: str, mtu: int, port: int = 5000, is_server: bool = False) -> bool:
        TunnelDriver.cleanup_interface(dev)
        for m in ["l2tp_core", "l2tp_netlink", "l2tp_eth", "l2tp_ip"]:
            run_cmd(f"modprobe {m} 2>/dev/null")

        tid = 2000 if is_server else 1000
        ptid = 1000 if is_server else 2000

        run_cmd(f"iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        run_cmd(f"ip l2tp del session tunnel_id {tid} session_id {tid} 2>/dev/null")
        run_cmd(f"ip l2tp del tunnel tunnel_id {tid} 2>/dev/null")

        cmd = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {ptid} encap udp local any remote {remote_ip} udp_sport {port} udp_dport {port}"
        ok, _ = run_cmd(cmd)
        if not ok:
            cmd = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {ptid} encap udp local {local_bind} remote {remote_ip} udp_sport {port} udp_dport {port}"
            ok, _ = run_cmd(cmd)
        if not ok:
            return False

        cmd_sess = f"ip l2tp add session tunnel_id {tid} session_id {tid} peer_session_id {ptid} name {dev}"
        ok_s, _ = run_cmd(cmd_sess)
        if not ok_s:
            run_cmd(f"ip l2tp del tunnel tunnel_id {tid} 2>/dev/null")
            return False

        my_mac = "02:00:00:00:00:02" if is_server else "02:00:00:00:00:01"
        peer_mac = "02:00:00:00:00:01" if is_server else "02:00:00:00:00:02"

        run_cmd(f"ip link set dev {dev} address {my_mac}")
        run_cmd(f"ip link set {dev} mtu {min(mtu, 1400)} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip neigh replace {peer_ip} lladdr {peer_mac} dev {dev} nud permanent")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
        run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        return True

def auto_cleanup(verbose: bool = False):
    if verbose:
        print("Cleaning up network interfaces...")

    ok, out = run_cmd("ip -o -4 addr show")
    if ok and out:
        for line in out.splitlines():
            if "10.99.1." in line:
                parts = line.split()
                if len(parts) >= 2:
                    dev_name = parts[1].split(":")[0]
                    TunnelDriver.cleanup_interface(dev_name)

    devs = ["tun_bench", "gre_bench", "gt_bench", "ipip_bench", "vx_bench", "eoip_bench", "wg_bench", "gen_bench", "sit_bench", "l2tp_bench"]
    for d in devs:
        TunnelDriver.cleanup_interface(d)

    ok_l, out_l = run_cmd("ip -o link show")
    if ok_l and out_l:
        for line in out_l.splitlines():
            for p in devs:
                if f": {p}" in line:
                    TunnelDriver.cleanup_interface(p)

    run_cmd("ip route del 10.99.1.0/30 2>/dev/null")
    run_cmd("pkill -9 iperf3 2>/dev/null")

    if verbose:
        print("Cleanup completed.")

atexit.register(auto_cleanup)

def sig_handler(sig, frame):
    auto_cleanup(verbose=True)
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

class BenchmarkEngine:
    @staticmethod
    def ping(my_ip: str, target_ip: str, count: int = 6) -> Dict[str, Any]:
        cmd = f"ping -I {my_ip} -c {count} -W 1 -i 0.2 {target_ip}"
        ok, out = run_cmd(cmd)
        if not ok or not out:
            cmd = f"ping -c {count} -W 1 -i 0.2 {target_ip}"
            ok, out = run_cmd(cmd)

        if not ok:
            return {"success": False, "loss_pct": 100.0, "avg_ms": 999.0}

        loss = 100.0
        avg_rtt = 999.0
        for line in out.splitlines():
            if "packet loss" in line:
                try:
                    for p in line.split(","):
                        if "packet loss" in p:
                            loss = float(p.strip().split("%")[0].split()[-1])
                except Exception:
                    pass
            if line.startswith("rtt ") or line.startswith("round-trip "):
                try:
                    avg_rtt = float(line.split("=")[1].strip().split("/")[1])
                except Exception:
                    pass

        return {"success": loss < 100.0, "loss_pct": loss, "avg_ms": avg_rtt}

    @staticmethod
    def start_iperf_server(bind_ip: str, port: int) -> subprocess.Popen:
        run_cmd("pkill -9 -f 'iperf3.*-s' 2>/dev/null")
        cmd = f"iperf3 -s -B {bind_ip} -p {port} -1"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.3)
        return proc

    @staticmethod
    def run_iperf_client(target_ip: str, bind_ip: str, port: int, duration_sec: int) -> Optional[float]:
        cmd = f"iperf3 -c {target_ip} -B {bind_ip} -p {port} -t {duration_sec} -P 4 -J"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        start = time.time()
        while proc.poll() is None:
            elapsed = int(time.time() - start)
            if elapsed > duration_sec + 4:
                proc.kill()
                break
            pct = min(100, int((elapsed / duration_sec) * 100))
            sys.stdout.write(f"\rTesting bandwidth... {pct}% ({elapsed}s/{duration_sec}s)")
            sys.stdout.flush()
            time.sleep(0.3)

        stdout, _ = proc.communicate()
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()

        if proc.returncode == 0 and stdout:
            try:
                data = json.loads(stdout)
                bps = data.get("end", {}).get("sum_sent", {}).get("bits_per_second")
                if not bps:
                    bps = data.get("end", {}).get("sum_received", {}).get("bits_per_second")
                if bps:
                    return float(bps)
            except Exception:
                pass
        return None

    @staticmethod
    def run_tcp_receiver(listen_ip: str, port: int, duration_sec: int, stop_event: threading.Event) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_ip, port))
        server.listen(16)
        server.settimeout(1.0)
        total = [0]

        def worker(conn):
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(2.0)
            chunk = 128 * 1024
            try:
                while not stop_event.is_set():
                    data = conn.recv(chunk)
                    if not data:
                        break
                    total[0] += len(data)
            except Exception:
                pass
            finally:
                conn.close()

        threads = []
        end = time.time() + duration_sec + 1.5
        while time.time() < end and not stop_event.is_set():
            try:
                c, _ = server.accept()
                t = threading.Thread(target=worker, args=(c,))
                t.daemon = True
                t.start()
                threads.append(t)
            except socket.timeout:
                continue
            except Exception:
                break

        server.close()
        for t in threads:
            t.join(timeout=0.3)
        return total[0]

    @staticmethod
    def run_tcp_sender(target_ip: str, port: int, duration_sec: int, streams: int = 4) -> float:
        payload = b"X" * (128 * 1024)
        stop_event = threading.Event()
        total = [0]

        def worker():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(3.0)
                s.connect((target_ip, port))
                while not stop_event.is_set():
                    s.sendall(payload)
                    total[0] += len(payload)
                s.close()
            except Exception:
                pass

        threads = []
        for _ in range(streams):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        start = time.time()
        try:
            while time.time() - start < duration_sec:
                time.sleep(0.3)
                elapsed = int(time.time() - start)
                pct = min(100, int((elapsed / duration_sec) * 100))
                sys.stdout.write(f"\rTesting bandwidth... {pct}% ({elapsed}s/{duration_sec}s)")
                sys.stdout.flush()
        finally:
            stop_event.set()
            for t in threads:
                t.join(timeout=0.5)
            sys.stdout.write("\r" + " " * 40 + "\r")
            sys.stdout.flush()

        elapsed_total = max(0.1, time.time() - start)
        return (total[0] * 8) / elapsed_total

def run_server_mode(port: int = SYNC_PORT):
    check_root()
    install_deps()
    optimize_sysctl()
    pub_ip = get_public_ip()

    print(f"Server mode started. Listening on port {port}...")
    open_firewall({"sync": port, "stream": STREAM_PORT})

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', port))
    server_sock.listen(1)

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
                peer_addr = addr[0]
                print(f"Connection received from {peer_addr}")

                msg = recv_msg(conn, timeout=15.0)
                if not msg or msg.get("action") != "HELLO":
                    conn.close()
                    continue

                peer_pub = msg.get("public_ip")
                if not peer_pub or peer_pub in ["0.0.0.0", "127.0.0.1"]:
                    peer_pub = peer_addr

                configured_ports = msg.get("ports", {
                    "wireguard": 51820,
                    "vxlan": 4789,
                    "geneve": 6081,
                    "l2tp": 5000,
                    "stream": STREAM_PORT
                })

                local_route = get_route_ip(peer_pub)
                base_mtu = get_base_mtu(peer_pub)
                wg_priv, wg_pub = gen_wg_keys()

                open_firewall(configured_ports)

                send_msg(conn, {
                    "status": "READY",
                    "server_pub_ip": pub_ip if pub_ip not in ["0.0.0.0", "127.0.0.1"] else "",
                    "peer_detected_ip": peer_addr,
                    "server_routing_ip": local_route,
                    "base_mtu": base_mtu,
                    "wg_pub_key": wg_pub,
                    "has_iperf3": bool(shutil.which("iperf3"))
                })

                dev = "tun_bench"
                peer_wg_pub = msg.get("wg_pub_key", "")

                try:
                    while True:
                        cmd = recv_msg(conn, timeout=600.0)
                        if not cmd:
                            break

                        act = cmd.get("action")
                        if act == "SETUP_TUNNEL":
                            proto = cmd.get("proto")
                            mtu = cmd.get("mtu", get_safe_mtu(base_mtu))
                            ok = False

                            if proto == "wireguard":
                                ok = TunnelDriver.setup_wireguard(
                                    dev=dev,
                                    priv_key=wg_priv,
                                    peer_pub_key=peer_wg_pub or cmd.get("peer_wg_pub", ""),
                                    remote_ip=peer_pub,
                                    port=configured_ports.get("wireguard", 51820),
                                    my_ip=SUBNET_REMOTE,
                                    peer_ip=SUBNET_LOCAL,
                                    mtu=mtu
                                )
                            elif proto == "gre":
                                ok = TunnelDriver.setup_gre(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
                            elif proto == "gretap":
                                ok = TunnelDriver.setup_gretap(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
                            elif proto == "ipip":
                                ok = TunnelDriver.setup_ipip(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
                            elif proto == "eoip":
                                ok = TunnelDriver.setup_eoip(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
                            elif proto == "vxlan":
                                ok = TunnelDriver.setup_vxlan(
                                    dev=dev,
                                    remote_ip=peer_pub,
                                    my_ip=SUBNET_REMOTE,
                                    peer_ip=SUBNET_LOCAL,
                                    mtu=mtu,
                                    dst_port=configured_ports.get("vxlan", 4789),
                                    is_server=True
                                )
                            elif proto == "geneve":
                                ok = TunnelDriver.setup_geneve(
                                    dev=dev,
                                    remote_ip=peer_pub,
                                    my_ip=SUBNET_REMOTE,
                                    peer_ip=SUBNET_LOCAL,
                                    mtu=mtu,
                                    dst_port=configured_ports.get("geneve", 6081),
                                    is_server=True
                                )
                            elif proto == "sit":
                                ok = TunnelDriver.setup_sit(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
                            elif proto == "l2tp":
                                ok = TunnelDriver.setup_l2tp(
                                    dev=dev,
                                    local_bind=local_route,
                                    remote_ip=peer_pub,
                                    my_ip=SUBNET_REMOTE,
                                    peer_ip=SUBNET_LOCAL,
                                    mtu=mtu,
                                    port=configured_ports.get("l2tp", 5000),
                                    is_server=True
                                )

                            send_msg(conn, {"status": "OK" if ok else "FAIL"})

                        elif act == "START_BANDWIDTH_TEST":
                            dur = cmd.get("duration", TEST_DURATION)
                            s_port = configured_ports.get("stream", STREAM_PORT)
                            use_iperf = cmd.get("use_iperf3", False) and bool(shutil.which("iperf3"))

                            if use_iperf:
                                BenchmarkEngine.start_iperf_server(SUBNET_REMOTE, s_port)
                                send_msg(conn, {"status": "IPERF3_READY"})
                            else:
                                ev = threading.Event()
                                rx = BenchmarkEngine.run_tcp_receiver("0.0.0.0", s_port, dur, ev)
                                send_msg(conn, {"status": "FINISHED", "bytes_rx": rx})

                        elif act == "TEARDOWN_TUNNEL":
                            TunnelDriver.cleanup_interface(dev)
                            send_msg(conn, {"status": "OK"})

                        elif act == "FINISH_SESSION":
                            auto_cleanup()
                            send_msg(conn, {"status": "BYE"})
                            break

                finally:
                    conn.close()
                    auto_cleanup()

            except KeyboardInterrupt:
                raise
            except Exception as e:
                auto_cleanup()

    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server_sock.close()
        auto_cleanup(verbose=True)

def run_client_mode(remote_ip: Optional[str] = None, sync_port: int = SYNC_PORT):
    check_root()
    install_deps()
    optimize_sysctl()

    if not remote_ip:
        remote_ip = input("Enter Remote Server IP: ").strip()

    if not remote_ip:
        print("Error: Remote IP required.")
        return

    print(f"Connecting to {remote_ip}:{sync_port}...")
    local_pub = get_public_ip()
    local_route = get_route_ip(remote_ip)
    local_mtu = get_base_mtu(remote_ip)

    ports = {
        "sync": sync_port,
        "wireguard": 51820,
        "vxlan": 4789,
        "geneve": 6081,
        "l2tp": 5000,
        "stream": STREAM_PORT
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    try:
        sock.connect((remote_ip, sync_port))
    except Exception as e:
        print(f"Error: Unable to connect to {remote_ip}:{sync_port} ({e})")
        return

    wg_priv, wg_pub = gen_wg_keys()

    send_msg(sock, {
        "action": "HELLO",
        "public_ip": local_pub if local_pub not in ["0.0.0.0", "127.0.0.1"] else "",
        "routing_ip": local_route,
        "base_mtu": local_mtu,
        "wg_pub_key": wg_pub,
        "ports": ports
    })

    resp = recv_msg(sock, timeout=12.0)
    if not resp or resp.get("status") != "READY":
        print("Handshake failed with remote server.")
        sock.close()
        return

    remote_mtu = resp.get("base_mtu", 1450)
    remote_wg_pub = resp.get("wg_pub_key", "")
    use_iperf = resp.get("has_iperf3", False) and bool(shutil.which("iperf3"))

    safe_mtu = get_safe_mtu(min(local_mtu, remote_mtu))
    open_firewall(ports)

    results: List[Dict[str, Any]] = []
    dev = "tun_bench"
    stream_port = ports["stream"]

    print(f"\nRunning 5s benchmark per protocol (MTU: {safe_mtu})...\n")

    try:
        for p in PROTOCOLS:
            proto_id = p["id"]
            proto_name = p["name"]

            sys.stdout.write(f"Testing {proto_name:<12} ")
            sys.stdout.flush()

            send_msg(sock, {
                "action": "SETUP_TUNNEL",
                "proto": proto_id,
                "mtu": safe_mtu,
                "peer_wg_pub": wg_pub
            })
            rem_res = recv_msg(sock, timeout=20.0)
            if not rem_res or rem_res.get("status") != "OK":
                print("[FAIL - Remote]")
                continue

            ok = False
            if proto_id == "wireguard":
                ok = TunnelDriver.setup_wireguard(
                    dev=dev,
                    priv_key=wg_priv,
                    peer_pub_key=remote_wg_pub,
                    remote_ip=remote_ip,
                    port=ports["wireguard"],
                    my_ip=SUBNET_LOCAL,
                    peer_ip=SUBNET_REMOTE,
                    mtu=safe_mtu
                )
            elif proto_id == "gre":
                ok = TunnelDriver.setup_gre(dev, local_route, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, safe_mtu)
            elif proto_id == "gretap":
                ok = TunnelDriver.setup_gretap(dev, local_route, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, safe_mtu)
            elif proto_id == "ipip":
                ok = TunnelDriver.setup_ipip(dev, local_route, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, safe_mtu)
            elif proto_id == "eoip":
                ok = TunnelDriver.setup_eoip(dev, local_route, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, safe_mtu)
            elif proto_id == "vxlan":
                ok = TunnelDriver.setup_vxlan(
                    dev=dev,
                    remote_ip=remote_ip,
                    my_ip=SUBNET_LOCAL,
                    peer_ip=SUBNET_REMOTE,
                    mtu=safe_mtu,
                    dst_port=ports["vxlan"],
                    is_server=False
                )
            elif proto_id == "geneve":
                ok = TunnelDriver.setup_geneve(
                    dev=dev,
                    remote_ip=remote_ip,
                    my_ip=SUBNET_LOCAL,
                    peer_ip=SUBNET_REMOTE,
                    mtu=safe_mtu,
                    dst_port=ports["geneve"],
                    is_server=False
                )
            elif proto_id == "sit":
                ok = TunnelDriver.setup_sit(dev, local_route, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, safe_mtu)
            elif proto_id == "l2tp":
                ok = TunnelDriver.setup_l2tp(
                    dev=dev,
                    local_bind=local_route,
                    remote_ip=remote_ip,
                    my_ip=SUBNET_LOCAL,
                    peer_ip=SUBNET_REMOTE,
                    mtu=safe_mtu,
                    port=ports["l2tp"],
                    is_server=False
                )

            if not ok:
                print("[FAIL - Local]")
                TunnelDriver.cleanup_interface(dev)
                send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
                recv_msg(sock, timeout=5.0)
                continue

            time.sleep(0.8)

            ping_res = BenchmarkEngine.ping(SUBNET_LOCAL, SUBNET_REMOTE, count=6)
            if not ping_res["success"]:
                print("[FAIL - Ping Timeout]")
                TunnelDriver.cleanup_interface(dev)
                send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
                recv_msg(sock, timeout=5.0)
                results.append({
                    "id": proto_id,
                    "name": proto_name,
                    "bandwidth": 0,
                    "bandwidth_str": "0 Mbps",
                    "latency": 999.0,
                    "loss": 100.0,
                    "status": "FAIL",
                    "score": 0
                })
                continue

            send_msg(sock, {
                "action": "START_BANDWIDTH_TEST",
                "duration": TEST_DURATION,
                "use_iperf3": use_iperf
            })
            recv_msg(sock, timeout=10.0)

            measured_bps = 0.0
            if use_iperf:
                ibps = BenchmarkEngine.run_iperf_client(SUBNET_REMOTE, SUBNET_LOCAL, stream_port, TEST_DURATION)
                if ibps and ibps > 0:
                    measured_bps = ibps
                else:
                    measured_bps = BenchmarkEngine.run_tcp_sender(SUBNET_REMOTE, stream_port, TEST_DURATION)
            else:
                measured_bps = BenchmarkEngine.run_tcp_sender(SUBNET_REMOTE, stream_port, TEST_DURATION)

            TunnelDriver.cleanup_interface(dev)
            send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
            recv_msg(sock, timeout=5.0)

            mbps = measured_bps / 1_000_000
            lat = max(1.0, ping_res["avg_ms"])
            loss = ping_res["loss_pct"]
            score = (mbps * 100.0) / (lat * (1.0 + (loss / 20.0)))

            results.append({
                "id": proto_id,
                "name": proto_name,
                "bandwidth": measured_bps,
                "bandwidth_str": format_speed(measured_bps),
                "latency": ping_res["avg_ms"],
                "loss": loss,
                "status": "PASS",
                "score": round(score, 1)
            })

            print(f"[PASS] {format_speed(measured_bps):<12} Ping: {ping_res['avg_ms']:.1f}ms  Loss: {loss:.1f}%")

    finally:
        try:
            send_msg(sock, {"action": "FINISH_SESSION"})
            sock.close()
        except Exception:
            pass
        auto_cleanup(verbose=True)

    show_results(results, remote_ip)

def show_results(results: List[Dict[str, Any]], remote_ip: str):
    sorted_res = sorted(results, key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 70)
    print(f"BENCHMARK RESULTS (Target: {remote_ip}, Duration: {TEST_DURATION}s)")
    print("=" * 70)
    header = f"{'RANK':<5} | {'PROTOCOL':<16} | {'THROUGHPUT':<14} | {'PING':<9} | {'LOSS':<7} | {'STATUS'}"
    print(header)
    print("-" * 70)

    for i, r in enumerate(sorted_res, 1):
        rank_str = f"#{i}"
        lat_str = f"{r['latency']:.1f} ms" if r['latency'] < 900 else "TIMEOUT"
        print(f"{rank_str:<5} | {r['name']:<16} | {r['bandwidth_str']:<14} | {lat_str:<9} | {r['loss']:>5.1f}% | {r['status']}")

    print("-" * 70)
    passing = [r for r in sorted_res if r["status"] == "PASS"]
    if passing:
        w = passing[0]
        print(f"\nWinner: {w['name']} ({w['bandwidth_str']}, {w['latency']:.1f} ms)")
        print(f"Deploy command: sudo python3 tunnel.py --create {w['id']} --remote {remote_ip}\n")

    log_path = "/root/benchmark_results.json" if os.path.exists("/root") else "benchmark_results.json"
    try:
        with open(log_path, "w") as f:
            json.dump({"target": remote_ip, "duration": TEST_DURATION, "results": sorted_res}, f, indent=2)
        print(f"Results saved to: {os.path.abspath(log_path)}")
    except Exception:
        pass

def manual_create_interactive(proto_id: str, proto_name: str):
    remote = input("Remote Server IP: ").strip()
    if not remote:
        return

    local_ips = get_all_local_ips()
    default_ip = get_route_ip(remote)
    local_bind = default_ip

    if len(local_ips) > 1:
        print("\nDetected Local IPs on this server:")
        for idx, lip in enumerate(local_ips, 1):
            tag = " (Default route)" if lip == default_ip else ""
            print(f"  {idx}) {lip}{tag}")
        sel = input(f"Select Local IP for tunnel [Default: {default_ip}]: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(local_ips):
            local_bind = local_ips[int(sel) - 1]
        elif sel in local_ips:
            local_bind = sel

    mtu = get_safe_mtu(get_base_mtu(remote))
    gw, phys_dev = get_default_gw()
    if gw and phys_dev and local_bind:
        run_cmd(f"ip route replace {remote} via {gw} dev {phys_dev} src {local_bind} 2>/dev/null")

    my_ip = input("Local Tunnel IP [10.0.0.1]: ").strip() or "10.0.0.1"
    rem_ip = input("Remote Tunnel IP [10.0.0.2]: ").strip() or "10.0.0.2"
    dev = input(f"Interface Name [{proto_id}1]: ").strip() or f"{proto_id}1"

    ok = False
    if proto_id == "wireguard":
        priv, pub = gen_wg_keys()
        print(f"Your WireGuard Public Key: {pub}")
        peer_pub = input("Remote WireGuard Public Key: ").strip()
        port = int(input("Port [51820]: ").strip() or "51820")
        ok = TunnelDriver.setup_wireguard(dev, priv, peer_pub, remote, port, my_ip, rem_ip, mtu)
    elif proto_id == "vxlan":
        port = int(input("Port [4789]: ").strip() or "4789")
        ok = TunnelDriver.setup_vxlan(dev, remote, my_ip, rem_ip, mtu, port)
    elif proto_id == "geneve":
        port = int(input("Port [6081]: ").strip() or "6081")
        ok = TunnelDriver.setup_geneve(dev, remote, my_ip, rem_ip, mtu, port)
    elif proto_id == "sit":
        ok = TunnelDriver.setup_sit(dev, local_bind, remote, my_ip, rem_ip, mtu)
    elif proto_id == "l2tp":
        port = int(input("Port [5000]: ").strip() or "5000")
        ok = TunnelDriver.setup_l2tp(dev, local_bind, remote, my_ip, rem_ip, mtu, port)
    elif proto_id == "gre":
        ok = TunnelDriver.setup_gre(dev, local_bind, remote, my_ip, rem_ip, mtu)
    elif proto_id == "gretap":
        ok = TunnelDriver.setup_gretap(dev, local_bind, remote, my_ip, rem_ip, mtu)
    elif proto_id == "ipip":
        ok = TunnelDriver.setup_ipip(dev, local_bind, remote, my_ip, rem_ip, mtu)
    elif proto_id == "eoip":
        ok = TunnelDriver.setup_eoip(dev, local_bind, remote, my_ip, rem_ip, mtu)

    if ok:
        run_cmd(f"ip route replace {rem_ip}/32 dev {dev} src {my_ip} 2>/dev/null")
        run_cmd(f"sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -i {dev} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -I FORWARD 1 -i {dev} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -I FORWARD 1 -o {dev} -j ACCEPT 2>/dev/null")

        print(f"\n[OK] Interface {dev} configured with routing on THIS server ({local_bind}).")
        print("=" * 70)
        print(f">>> RUN THIS EXACT COMMAND ON THE REMOTE SERVER ({remote}): <<<")
        print("-" * 70)
        
        rem_cmd = ""
        if proto_id == "ipip":
            rem_cmd = (
                f"sudo ip link add {dev} type ipip remote {local_bind} local {remote} ttl 255 && "
                f"sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 && "
                f"sudo iptables -I INPUT 1 -p 4 -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && "
                f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT"
            )
        elif proto_id == "gre":
            rem_cmd = (
                f"sudo ip link add {dev} type gre remote {local_bind} local {remote} ttl 255 && "
                f"sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 && "
                f"sudo iptables -I INPUT 1 -p 47 -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && "
                f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT"
            )
        elif proto_id == "gretap":
            rem_cmd = (
                f"sudo ip link add {dev} type gretap remote {local_bind} local {remote} ttl 255 && "
                f"sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 && "
                f"sudo iptables -I INPUT 1 -p 47 -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && "
                f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT"
            )
        elif proto_id == "vxlan":
            rem_cmd = (
                f"sudo ip link add {dev} type vxlan id 100 remote {local_bind} dstport {port} && "
                f"sudo ip link set dev {dev} address 02:00:00:00:00:02 && "
                f"sudo ip link set {dev} mtu 1350 up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip neigh replace {my_ip} lladdr 02:00:00:00:00:01 dev {dev} nud permanent && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && "
                f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT"
            )
        elif proto_id == "wireguard":
            rem_cmd = (
                f"# Run on remote server:\n"
                f"sudo ip link add dev {dev} type wireguard && "
                f"sudo wg set {dev} listen-port {port} peer {pub} allowed-ips 0.0.0.0/0 endpoint {local_bind}:{port} && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip}"
            )
        elif proto_id == "sit":
            rem_cmd = (
                f"sudo ip link add {dev} type sit remote {local_bind} local {remote} ttl 255 && "
                f"sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo iptables -I INPUT 1 -p 41 -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && "
                f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT"
            )
        else:
            rem_cmd = f"Configure {proto_id} on {remote} with remote {local_bind} and IP {rem_ip}/30"

        print(rem_cmd)
        print("=" * 70)
        
        do_ping = input(f"\nTest ping to {rem_ip} now? [y/N]: ").strip().lower()
        if do_ping == 'y':
            print(f"Pinging {rem_ip}...")
            ok_ping, p_out = run_cmd(f"ping -c 3 -W 2 {rem_ip}")
            print(p_out)
            if not ok_ping:
                print("\n[NOTE] Ping failed. Common causes:")
                print("1. Remote server counterpart tunnel has not been created yet.")
                print("2. Remote server firewall (ufw/iptables) or rp_filter is dropping packets.")
                print(f"3. Protocol ({proto_name}) might be filtered by Iranian ISP/infrastructure.")
    else:
        print(f"Failed to configure {dev}.")
    input("\nPress Enter to return...")

def manual_menu():
    while True:
        print("\n--- Manual Tunnel Creation ---")
        for i, p in enumerate(PROTOCOLS, 1):
            print(f"{i}) {p['name']}")
        print("0) Back")
        c = input("Select: ").strip()
        if c == "0":
            break
        try:
            idx = int(c) - 1
            if 0 <= idx < len(PROTOCOLS):
                manual_create_interactive(PROTOCOLS[idx]["id"], PROTOCOLS[idx]["name"])
        except ValueError:
            pass

def list_system_tunnels() -> List[Dict[str, str]]:
    tunnels = []
    ok, out = run_cmd("ip -o link show")
    if not ok or not out:
        return tunnels

    ignore_prefixes = ("lo", "eth", "ens", "enp", "wl", "docker", "br-", "veth")
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            ifname = parts[1].strip().split("@")[0]
            if not any(ifname.startswith(p) for p in ignore_prefixes):
                ok_ip, out_ip = run_cmd(f"ip -o -4 addr show dev {ifname}")
                ip_addr = "No IP"
                if ok_ip and out_ip:
                    for ip_line in out_ip.splitlines():
                        if "inet " in ip_line:
                            ip_addr = ip_line.split("inet ")[1].split()[0]
                tunnels.append({"dev": ifname, "ip": ip_addr})
    return tunnels

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
        elif c.lower() == "m":
            target = input("Enter interface name: ").strip()
            if target:
                TunnelDriver.cleanup_interface(target)
                print(f"Deleted interface {target}")
                time.sleep(1)
        else:
            try:
                idx = int(c) - 1
                if 0 <= idx < len(tunnels):
                    target = tunnels[idx]["dev"]
                    TunnelDriver.cleanup_interface(target)
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
        elif c == "1":
            dev = input("Enter tunnel interface name (e.g. gre1, ipip1, wg0): ").strip()
            if not dev:
                continue

            new_remote = input("Enter New Remote Server IP: ").strip()
            if not new_remote:
                continue

            ok_wg, _ = run_cmd(f"wg show {dev} 2>/dev/null")
            if ok_wg:
                port = input("Port [51820]: ").strip() or "51820"
                ok, out = run_cmd(f"wg show {dev} peers")
                peer_pub = out.strip().split()[0] if out.strip() else ""
                if peer_pub:
                    run_cmd(f"wg set {dev} peer {peer_pub} endpoint {new_remote}:{port}")
                    print(f"WireGuard endpoint updated to {new_remote}:{port}")
                else:
                    print(f"Peer not found for {dev}")
            else:
                ok_link, out_link = run_cmd(f"ip -d link show dev {dev}")
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

PORT_FWD_FILE = "/etc/tunnel_port_fwd.json" if os.path.exists("/etc") else "tunnel_port_fwd.json"

def load_port_fwd_rules() -> List[Dict[str, Any]]:
    if os.path.exists(PORT_FWD_FILE):
        try:
            with open(PORT_FWD_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_port_fwd_rules(rules: List[Dict[str, Any]]):
    try:
        with open(PORT_FWD_FILE, "w") as f:
            json.dump(rules, f, indent=2)
    except Exception:
        pass

def apply_port_fwd_rule(proto: str, listen_port: str, dest_ip: str, dest_port: str):
    run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
    protos = ["tcp", "udp"] if proto.lower() in ["both", "tcp+udp", "all"] else [proto.lower()]
    to_dest = f"{dest_ip}:{dest_port}"

    for pr in protos:
        run_cmd(f"iptables -t nat -I PREROUTING 1 -p {pr} --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")
        run_cmd(f"iptables -t nat -I POSTROUTING 1 -p {pr} -d {dest_ip} --dport {dest_port} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -I FORWARD 1 -p {pr} -d {dest_ip} --dport {dest_port} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -t nat -I OUTPUT 1 -p {pr} -d 127.0.0.1 --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")

    run_cmd("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
    run_cmd("iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")

def remove_port_fwd_rule(proto: str, listen_port: str, dest_ip: str, dest_port: str):
    protos = ["tcp", "udp"] if proto.lower() in ["both", "tcp+udp", "all"] else [proto.lower()]
    to_dest = f"{dest_ip}:{dest_port}"

    for pr in protos:
        run_cmd(f"iptables -t nat -D PREROUTING -p {pr} --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")
        run_cmd(f"iptables -t nat -D POSTROUTING -p {pr} -d {dest_ip} --dport {dest_port} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -p {pr} -d {dest_ip} --dport {dest_port} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -t nat -D OUTPUT -p {pr} -d 127.0.0.1 --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")

def port_fwd_menu():
    run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
    while True:
        print("\n--- Port Forwarding (NAT Relay) ---")
        print("1) Add Forward Rule (Single / Multi / Range)")
        print("2) List Active Forward Rules")
        print("3) Delete Forward Rule")
        print("4) Flush All Forward Rules")
        print("0) Back")
        c = input("Select [0-4]: ").strip()
        if c == "0":
            break
        elif c == "1":
            print("\nEnter Listen Port (e.g. 443, or 80,443, or 10000:20000):")
            lp = input("Listen Port: ").strip()
            if not lp:
                continue
            dip = input("Destination IP (e.g. 10.0.0.2): ").strip()
            if not dip:
                continue
            dp = input(f"Destination Port [{lp}]: ").strip() or lp
            pr = input("Protocol (tcp / udp / both) [both]: ").strip().lower() or "both"
            if pr not in ["tcp", "udp", "both"]:
                pr = "both"

            ports = [p.strip() for p in lp.split(",")] if "," in lp else [lp]
            dports = [p.strip() for p in dp.split(",")] if "," in dp else [dp]

            rules = load_port_fwd_rules()
            for idx, p in enumerate(ports):
                dest_p = dports[idx] if idx < len(dports) else dports[0]
                apply_port_fwd_rule(pr, p, dip, dest_p)
                rules.append({
                    "id": len(rules) + 1,
                    "proto": pr,
                    "listen_port": p,
                    "dest_ip": dip,
                    "dest_port": dest_p,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                })
            save_port_fwd_rules(rules)
            print(f"\n[OK] Port forwarding applied: {lp} ({pr}) -> {dip}:{dp}")
            print("[INFO] MASQUERADE & TCPMSS Clamping automatically enabled.")
            time.sleep(1)

        elif c == "2":
            rules = load_port_fwd_rules()
            print("\n" + "=" * 65)
            print(f"{'ID':<4} | {'PROTO':<8} | {'LISTEN PORT':<14} | {'FORWARD TO':<25}")
            print("-" * 65)
            if rules:
                for r in rules:
                    print(f"#{r['id']:<3} | {r['proto']:<8} | {r['listen_port']:<14} | {r['dest_ip']}:{r['dest_port']}")
            else:
                print("No stored forwarding rules.")
            print("=" * 65)
            print("\n--- Active PREROUTING iptables rules ---")
            _, out = run_cmd("iptables -t nat -L PREROUTING -n -v --line-numbers")
            print(out or "None")
            input("\nPress Enter to return...")

        elif c == "3":
            rules = load_port_fwd_rules()
            if not rules:
                print("No active rules to delete.")
                time.sleep(1)
                continue
            print("\nSelect Rule ID to delete:")
            for r in rules:
                print(f"  {r['id']}) {r['proto'].upper()} {r['listen_port']} -> {r['dest_ip']}:{r['dest_port']}")
            sel = input("Rule ID: ").strip()
            if sel.isdigit():
                rule_id = int(sel)
                target_rule = next((r for r in rules if r["id"] == rule_id), None)
                if target_rule:
                    remove_port_fwd_rule(target_rule["proto"], target_rule["listen_port"], target_rule["dest_ip"], target_rule["dest_port"])
                    rules = [r for r in rules if r["id"] != rule_id]
                    for idx, r in enumerate(rules, 1):
                        r["id"] = idx
                    save_port_fwd_rules(rules)
                    print(f"[OK] Rule #{rule_id} removed.")
                else:
                    print("Rule not found.")
            time.sleep(1)

        elif c == "4":
            conf = input("Are you sure you want to remove ALL port forward rules? [y/N]: ").strip().lower()
            if conf == 'y':
                rules = load_port_fwd_rules()
                for r in rules:
                    remove_port_fwd_rule(r["proto"], r["listen_port"], r["dest_ip"], r["dest_port"])
                save_port_fwd_rules([])
                run_cmd("iptables -t nat -F PREROUTING 2>/dev/null")
                run_cmd("iptables -t nat -F OUTPUT 2>/dev/null")
                print("[OK] All port forwarding rules flushed.")
                time.sleep(1)

def get_tunnel_details(dev: str) -> Dict[str, str]:
    info = {"dev": dev, "local_outer": "", "remote_outer": "", "local_tunnel_ip": "", "peer_tunnel_ip": ""}
    ok_wg, out_wg = run_cmd(f"wg show {dev} 2>/dev/null")
    if ok_wg and "endpoint:" in out_wg:
        for line in out_wg.splitlines():
            if "endpoint:" in line:
                endpoint = line.split("endpoint:")[1].strip()
                info["remote_outer"] = endpoint.split(":")[0]

    if not info["remote_outer"]:
        ok, out = run_cmd(f"ip -d link show dev {dev} 2>/dev/null")
        if ok and out:
            for line in out.splitlines():
                line_str = line.strip()
                if "peer " in line_str:
                    parts = line_str.split()
                    if "peer" in parts:
                        p_idx = parts.index("peer")
                        if p_idx + 1 < len(parts):
                            info["remote_outer"] = parts[p_idx + 1]
                        if p_idx >= 1:
                            cand_local = parts[p_idx - 1]
                            if cand_local not in ["link/ipip", "link/gre", "link/sit", "type"]:
                                info["local_outer"] = cand_local
                elif "remote " in line_str:
                    parts = line_str.split()
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
                    parts = ip_only.split(".")
                    last = int(parts[3])
                    peer_last = last + 1 if last % 2 == 1 else last - 1
                    info["peer_tunnel_ip"] = f"{parts[0]}.{parts[1]}.{parts[2]}.{peer_last}"
                elif ip_only.endswith(".1"):
                    info["peer_tunnel_ip"] = ip_only[:-1] + "2"
                elif ip_only.endswith(".2"):
                    info["peer_tunnel_ip"] = ip_only[:-1] + "1"

    return info

def tunnel_routing_menu():
    while True:
        print("\n--- Tunnel Routing & Forwarding ---")
        print("1) Configure Peer Routing (Fix Ping & Unreachable)")
        print("2) Route All Traffic through Tunnel (Safe - Keeps SSH)")
        print("3) Remove Default Route from Tunnel")
        print("4) Enable NAT / Internet Sharing (On Foreign Server)")
        print("5) Diagnose & Test Tunnel")
        print("6) Show Current Routing Table")
        print("0) Back")

        c = input("Select [0-6]: ").strip()
        if c == "0":
            break
        elif c == "1":
            tunnels = list_system_tunnels()
            dev = ""
            if tunnels:
                print("\nAvailable tunnel interfaces:")
                for i, tun in enumerate(tunnels, 1):
                    det = get_tunnel_details(tun["dev"])
                    peer_hint = f"-> {det['peer_tunnel_ip']}" if det["peer_tunnel_ip"] else ""
                    print(f"  {i}) {tun['dev']} ({tun['ip']} {peer_hint})")
                sel_dev = input(f"Select interface [1-{len(tunnels)}] or enter name: ").strip()
                if sel_dev.isdigit() and 1 <= int(sel_dev) <= len(tunnels):
                    dev = tunnels[int(sel_dev) - 1]["dev"]
                else:
                    dev = sel_dev
            else:
                dev = input("Enter tunnel interface (e.g. ipip1, gre1): ").strip()

            if not dev:
                continue

            det = get_tunnel_details(dev)
            def_my_ip = det["local_tunnel_ip"] or "10.0.0.1"
            def_peer_ip = det["peer_tunnel_ip"] or "10.0.0.2"
            def_rem_pub = det["remote_outer"] or ""

            my_tunnel_ip = input(f"Local Tunnel IP [{def_my_ip}]: ").strip() or def_my_ip
            peer_tunnel_ip = input(f"Remote Tunnel IP [{def_peer_ip}]: ").strip() or def_peer_ip
            remote_server_ip = input(f"Remote Server Public IP [{def_rem_pub}]: ").strip() or def_rem_pub

            run_cmd(f"ip link set dev {dev} up 2>/dev/null")
            run_cmd(f"ip route replace {peer_tunnel_ip}/32 dev {dev} src {my_tunnel_ip} 2>/dev/null")
            run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
            run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
            run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
            run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
            run_cmd(f"iptables -I INPUT 1 -i {dev} -j ACCEPT 2>/dev/null")
            run_cmd(f"iptables -I FORWARD 1 -i {dev} -j ACCEPT 2>/dev/null")
            run_cmd(f"iptables -I FORWARD 1 -o {dev} -j ACCEPT 2>/dev/null")
            run_cmd("iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
            run_cmd(f"ip neigh flush dev {dev} 2>/dev/null")

            if remote_server_ip:
                gw, pdev = get_default_gw()
                local_bind = get_route_ip(remote_server_ip)
                if gw and pdev and local_bind:
                    run_cmd(f"ip route replace {remote_server_ip} via {gw} dev {pdev} src {local_bind} 2>/dev/null")

            print(f"\n[OK] Peer routing and firewall applied for {dev}!")
            print(f"Testing ping to {peer_tunnel_ip}...")
            ok_p, p_out = run_cmd(f"ping -c 3 -W 2 {peer_tunnel_ip}")
            print(p_out)
            input("\nPress Enter to return...")

        elif c == "2":
            tunnels = list_system_tunnels()
            dev = ""
            if tunnels:
                print("\nAvailable tunnel interfaces:")
                for i, tun in enumerate(tunnels, 1):
                    det = get_tunnel_details(tun["dev"])
                    print(f"  {i}) {tun['dev']} ({tun['ip']})")
                sel_dev = input(f"Select interface [1-{len(tunnels)}] or enter name: ").strip()
                if sel_dev.isdigit() and 1 <= int(sel_dev) <= len(tunnels):
                    dev = tunnels[int(sel_dev) - 1]["dev"]
                else:
                    dev = sel_dev
            else:
                dev = input("Enter tunnel interface (e.g. ipip1, gre1): ").strip()

            if not dev:
                continue

            det = get_tunnel_details(dev)
            def_peer_ip = det["peer_tunnel_ip"] or "10.0.0.2"
            def_rem_pub = det["remote_outer"] or ""

            peer_tunnel_ip = input(f"Remote Tunnel IP (Gateway) [{def_peer_ip}]: ").strip() or def_peer_ip
            remote_outer_ip = input(f"Remote Server Outer Public IP [{def_rem_pub}]: ").strip() or def_rem_pub

            print("\nApplying policy routing...")
            gw, phys_dev = get_default_gw()
            run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
            run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")

            if remote_outer_ip and gw and phys_dev:
                run_cmd(f"ip rule add to {remote_outer_ip} table main pref 500 2>/dev/null")
                run_cmd(f"ip route replace {remote_outer_ip} via {gw} dev {phys_dev} 2>/dev/null")

            run_cmd("ip rule add sport 22 table main pref 600 2>/dev/null")
            run_cmd("ip rule add dport 22 table main pref 600 2>/dev/null")
            for lip in get_all_local_ips():
                run_cmd(f"ip rule add from {lip} table main pref 700 2>/dev/null")

            run_cmd("ip route flush table 100 2>/dev/null")
            run_cmd(f"ip route add {peer_tunnel_ip}/32 dev {dev} table 100 2>/dev/null")
            run_cmd(f"ip route add default via {peer_tunnel_ip} dev {dev} table 100 2>/dev/null")
            run_cmd("ip rule del pref 2000 table 100 2>/dev/null")
            run_cmd("ip rule add pref 2000 table 100 2>/dev/null")
            run_cmd("ip route flush cache 2>/dev/null")

            run_cmd("iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
            run_cmd("iptables -t mangle -I POSTROUTING 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")

            print(f"\n[OK] All internet traffic routed via {dev} ({peer_tunnel_ip}).")
            print("Checking public IP through tunnel...")
            time.sleep(1)
            ok_curl, out_curl = run_cmd("curl -s --max-time 3 https://api.ipify.org")
            if ok_curl and out_curl.strip():
                print(f"Current Public IP: {out_curl.strip()}")
            else:
                print("Could not query public IP. Make sure Foreign Server has NAT/MASQUERADE enabled (Option 4 on foreign server)!")
            input("\nPress Enter to return...")

        elif c == "3":
            run_cmd("ip rule del pref 2000 table 100 2>/dev/null")
            run_cmd("ip rule del pref 500 table main 2>/dev/null")
            run_cmd("ip rule del pref 600 table main 2>/dev/null")
            run_cmd("ip rule del pref 700 table main 2>/dev/null")
            run_cmd("ip route flush table 100 2>/dev/null")
            run_cmd("ip route flush cache 2>/dev/null")
            print("\n[OK] Tunnel default routing removed. Normal routing restored.")
            input("\nPress Enter to return...")

        elif c == "4":
            gw, pdev = get_default_gw()
            pdev_in = input(f"Outgoing Internet Interface [{pdev or 'eth0'}]: ").strip() or (pdev or "eth0")
            subnet = input("Tunnel Subnet [10.0.0.0/24]: ").strip() or "10.0.0.0/24"

            run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
            run_cmd(f"iptables -t nat -I POSTROUTING 1 -s {subnet} -o {pdev_in} -j MASQUERADE 2>/dev/null")
            run_cmd(f"iptables -I FORWARD 1 -s {subnet} -j ACCEPT 2>/dev/null")
            run_cmd(f"iptables -I FORWARD 1 -d {subnet} -j ACCEPT 2>/dev/null")
            run_cmd("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
            run_cmd("iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
            print(f"\n[OK] NAT and MASQUERADE enabled on {pdev_in} for {subnet}!")
            input("\nPress Enter to return...")

        elif c == "5":
            tunnels = list_system_tunnels()
            if not tunnels:
                print("No tunnels found.")
                time.sleep(1)
                continue
            for i, tun in enumerate(tunnels, 1):
                det = get_tunnel_details(tun["dev"])
                print(f"  {i}) {tun['dev']} (IP: {tun['ip']}, Peer: {det['peer_tunnel_ip']}, Endpoint: {det['remote_outer']})")
            sel = input("Select tunnel to diagnose: ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(tunnels):
                t = tunnels[int(sel) - 1]
                det = get_tunnel_details(t["dev"])
                print(f"\n--- Diagnosing {t['dev']} ---")
                ok_link, out_link = run_cmd(f"ip link show dev {t['dev']}")
                print(f"Link Status: {'UP' if 'UP' in out_link else 'DOWN'}")
                print(f"Local IP: {det['local_tunnel_ip']}")
                print(f"Peer IP: {det['peer_tunnel_ip']}")
                print(f"Remote Server Outer IP: {det['remote_outer']}")
                if det["peer_tunnel_ip"]:
                    print(f"\nPinging peer {det['peer_tunnel_ip']}...")
                    _, p_out = run_cmd(f"ping -c 4 -W 2 {det['peer_tunnel_ip']}")
                    print(p_out)
            input("\nPress Enter to return...")

        elif c == "6":
            _, out = run_cmd("ip route show")
            print("\n--- Main Routing Table ---")
            print(out)
            _, out_tbl = run_cmd("ip route show table 100 2>/dev/null")
            if out_tbl.strip():
                print("\n--- Tunnel Routing Table (table 100) ---")
                print(out_tbl)
            _, out_rules = run_cmd("ip rule show")
            print("\n--- IP Routing Policy Rules ---")
            print(out_rules)
            input("\nPress Enter to return...")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["server", "client", "clean", "remote", "local"])
    parser.add_argument("--remote", help="Remote server IP")
    parser.add_argument("--remote-ip", dest="remote_ip_alias", help="Remote server IP")
    parser.add_argument("--port", type=int, default=SYNC_PORT)
    parser.add_argument("--duration", type=int, default=TEST_DURATION)
    parser.add_argument("--create", choices=[p["id"] for p in PROTOCOLS])
    args = parser.parse_args()

    check_root()

    target_ip = args.remote or args.remote_ip_alias

    if args.role in ["server", "remote"]:
        run_server_mode(port=args.port)
        return
    elif args.role in ["client", "local"]:
        run_client_mode(remote_ip=target_ip, sync_port=args.port)
        return
    elif args.role == "clean":
        auto_cleanup(verbose=True)
        return

    while True:
        print("\n==============================")
        print(" Linux Tunnel Manager V2 ")
        print(" Channel : @Telhost1 ")
        print("Buy a Vps : pasargadcloud.ir")
        print("==============================")
        print("1) Run Benchmark (Client)")
        print("2) Start Listener (Server)")
        print("3) Create Tunnel")
        print("4) Tunnel Routing & Forwarding")
        print("5) Delete Tunnel")
        print("6) Change Tunnel IP")
        print("7) Port Forwarding")
        print("8) Optimize Network")
        print("9) Clean Interfaces")
        print("0) Exit")
        print("------------------------------")

        choice = input("Select option [0-9]: ").strip()

        if choice == "1":
            run_client_mode(sync_port=args.port)
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            p_in = input(f"Port [{SYNC_PORT}]: ").strip()
            p = int(p_in) if p_in.isdigit() else SYNC_PORT
            run_server_mode(port=p)
        elif choice == "3":
            manual_menu()
        elif choice == "4":
            tunnel_routing_menu()
        elif choice == "5":
            delete_tunnel_menu()
        elif choice == "6":
            change_tunnel_ip_menu()
        elif choice == "7":
            port_fwd_menu()
        elif choice == "8":
            install_deps()
            optimize_sysctl()
            print("System optimized.")
            time.sleep(1)
        elif choice == "9":
            auto_cleanup(verbose=True)
        elif choice == "0":
            auto_cleanup()
            sys.exit(0)

if __name__ == "__main__":
    main()
