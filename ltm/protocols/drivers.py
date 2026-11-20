"""TunnelDriver: thin wrappers around `ip`/`wg` to build each tunnel type."""

import os
from typing import Optional, Tuple

from ..core.system import run_cmd


def gen_wg_keys() -> Tuple[str, str]:
    ok, priv = run_cmd("wg genkey")
    if ok and priv.strip():
        priv_k = priv.strip()
        ok2, pub = run_cmd(f"echo '{priv_k}' | wg pubkey")
        if ok2 and pub.strip():
            return priv_k, pub.strip()
    return (
        "yAnz5TF+lXXJte14tji3nhMNqPrLdNeHQL8pYfWqX28=",
        "0mFv3l138HjM5cKfZ0Yd/3yX6M8Lp7mQ9tZ5r1k2vXw=",
    )


def _common_sysctl(dev: str):
    run_cmd(f"sysctl -w net.ipv4.conf.{dev}.rp_filter=0 2>/dev/null")
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null")
    run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null")
    run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")


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
    def setup_wireguard(dev, priv_key, peer_pub_key, remote_ip, port, my_ip, peer_ip, mtu) -> bool:
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
        _common_sysctl(dev)
        return True

    @staticmethod
    def _setup_simple(kind, modprobe, iptables_proto, dev, local_bind, remote_ip, my_ip, peer_ip, mtu) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd(f"modprobe {modprobe} 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -p {iptables_proto} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        ok, _ = run_cmd(f"ip link add {dev} type {kind} remote {remote_ip} local {local_bind} ttl 255")
        if not ok:
            ok, _ = run_cmd(f"ip link add {dev} type {kind} remote {remote_ip} ttl 255")
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        _common_sysctl(dev)
        return True

    @staticmethod
    def setup_gre(dev, local_bind, remote_ip, my_ip, peer_ip, mtu) -> bool:
        return TunnelDriver._setup_simple("gre", "ip_gre", "47", dev, local_bind, remote_ip, my_ip, peer_ip, mtu)

    @staticmethod
    def setup_gretap(dev, local_bind, remote_ip, my_ip, peer_ip, mtu) -> bool:
        return TunnelDriver._setup_simple("gretap", "gretap", "47", dev, local_bind, remote_ip, my_ip, peer_ip, mtu)

    @staticmethod
    def setup_ipip(dev, local_bind, remote_ip, my_ip, peer_ip, mtu) -> bool:
        return TunnelDriver._setup_simple("ipip", "ipip", "4", dev, local_bind, remote_ip, my_ip, peer_ip, mtu)

    @staticmethod
    def setup_sit(dev, local_bind, remote_ip, my_ip, peer_ip, mtu) -> bool:
        return TunnelDriver._setup_simple("sit", "sit", "41", dev, local_bind, remote_ip, my_ip, peer_ip, mtu)

    @staticmethod
    def setup_eoip(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, tid: int = 10) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd("modprobe gretap 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        ok, _ = run_cmd(f"ip link add {dev} type gretap remote {remote_ip} local {local_bind} key {tid}")
        if not ok:
            ok, _ = run_cmd(f"ip link add {dev} type gretap remote {remote_ip} key {tid}")
        if not ok:
            return False
        run_cmd(f"ip link set {dev} mtu {mtu} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        _common_sysctl(dev)
        return True

    @staticmethod
    def _setup_udp_l2(kind, modprobe, dev, remote_ip, my_ip, peer_ip, mtu, dst_port, vni, is_server, local_bind, add_fdb) -> bool:
        TunnelDriver.cleanup_interface(dev)
        run_cmd(f"modprobe {modprobe} 2>/dev/null")
        run_cmd(f"iptables -I INPUT 1 -p udp --dport {dst_port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        loc_arg = f"local {local_bind} " if local_bind and local_bind not in ["0.0.0.0", "127.0.0.1"] else ""
        ok, _ = run_cmd(f"ip link add {dev} type {kind} id {vni} remote {remote_ip} {loc_arg}dstport {dst_port}")
        if not ok and loc_arg:
            ok, _ = run_cmd(f"ip link add {dev} type {kind} id {vni} remote {remote_ip} dstport {dst_port}")
        if not ok:
            return False

        my_mac = "02:00:00:00:00:02" if is_server else "02:00:00:00:00:01"
        peer_mac = "02:00:00:00:00:01" if is_server else "02:00:00:00:00:02"

        run_cmd(f"ip link set dev {dev} address {my_mac}")
        run_cmd(f"ip link set {dev} mtu {min(mtu, 1350)} up")
        run_cmd(f"ip addr add {my_ip}/30 dev {dev}")
        run_cmd(f"ip neigh replace {peer_ip} lladdr {peer_mac} dev {dev} nud permanent")
        if add_fdb:
            run_cmd(f"bridge fdb replace 00:00:00:00:00:00 dev {dev} dst {remote_ip} 2>/dev/null")
            run_cmd(f"bridge fdb replace {peer_mac} dev {dev} dst {remote_ip} 2>/dev/null")
        run_cmd(f"ip route replace {peer_ip} dev {dev} src {my_ip} 2>/dev/null")
        _common_sysctl(dev)
        return True

    @staticmethod
    def setup_vxlan(dev, remote_ip, my_ip, peer_ip, mtu, dst_port=4789, vni=100, is_server=False, local_bind=None) -> bool:
        return TunnelDriver._setup_udp_l2("vxlan", "vxlan", dev, remote_ip, my_ip, peer_ip, mtu, dst_port, vni, is_server, local_bind, add_fdb=True)

    @staticmethod
    def setup_geneve(dev, remote_ip, my_ip, peer_ip, mtu, dst_port=6081, vni=100, is_server=False, local_bind=None) -> bool:
        return TunnelDriver._setup_udp_l2("geneve", "geneve", dev, remote_ip, my_ip, peer_ip, mtu, dst_port, vni, is_server, local_bind, add_fdb=False)

    @staticmethod
    def setup_l2tp(dev, local_bind, remote_ip, my_ip, peer_ip, mtu, port=5000, is_server=False) -> bool:
        TunnelDriver.cleanup_interface(dev)
        for m in ["l2tp_core", "l2tp_netlink", "l2tp_eth", "l2tp_ip"]:
            run_cmd(f"modprobe {m} 2>/dev/null")

        tid = 2000 if is_server else 1000
        ptid = 1000 if is_server else 2000

        run_cmd(f"iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT 2>/dev/null")
        run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")
        run_cmd(f"ip l2tp del session tunnel_id {tid} session_id {tid} 2>/dev/null")
        run_cmd(f"ip l2tp del tunnel tunnel_id {tid} 2>/dev/null")

        loc_arg = f"local {local_bind}" if local_bind and local_bind not in ["0.0.0.0", "127.0.0.1"] else "local any"
        cmd = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {ptid} encap udp {loc_arg} remote {remote_ip} udp_sport {port} udp_dport {port}"
        ok, _ = run_cmd(cmd)
        if not ok and loc_arg != "local any":
            ok, _ = run_cmd(f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {ptid} encap udp local any remote {remote_ip} udp_sport {port} udp_dport {port}")
        if not ok:
            return False

        ok_s, _ = run_cmd(f"ip l2tp add session tunnel_id {tid} session_id {tid} peer_session_id {ptid} name {dev}")
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
        _common_sysctl(dev)
        return True
