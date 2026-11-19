"""Interactive creation of a single tunnel on this host, with the exact
counterpart command to paste on the remote server."""

from typing import Optional

from ..core.system import run_cmd
from ..core.netinfo import get_all_local_ips, get_route_ip, get_base_mtu, get_safe_mtu, get_default_gw
from ..protocols.registry import PROTOCOLS
from ..protocols.drivers import TunnelDriver, gen_wg_keys


def _remote_command(proto_id, dev, local_bind, remote, my_ip, rem_ip, mtu, port, pub=""):
    base_fw = (f"sudo iptables -I INPUT 1 -i {dev} -j ACCEPT && "
               f"sudo iptables -I FORWARD 1 -i {dev} -j ACCEPT")
    if proto_id in ("ipip", "gre", "gretap", "sit"):
        proto_num = {"ipip": "4", "gre": "47", "gretap": "47", "sit": "41"}[proto_id]
        return (f"sudo ip link add {dev} type {proto_id} remote {local_bind} local {remote} ttl 255 && "
                f"sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.{dev}.rp_filter=0 && "
                f"sudo iptables -I INPUT 1 -p {proto_num} -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && {base_fw}")
    if proto_id in ("vxlan", "geneve"):
        return (f"sudo ip link add {dev} type {proto_id} id 100 remote {local_bind} local {remote} dstport {port} && "
                f"sudo ip link set dev {dev} address 02:00:00:00:00:02 && "
                f"sudo ip link set {dev} mtu 1350 up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip neigh replace {my_ip} lladdr 02:00:00:00:00:01 dev {dev} nud permanent && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip} && "
                f"sudo iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT && sudo iptables -I INPUT 1 -p icmp -j ACCEPT && {base_fw}")
    if proto_id == "l2tp":
        return (f"sudo ip l2tp add tunnel tunnel_id 2000 peer_tunnel_id 1000 encap udp local {remote} remote {local_bind} udp_sport {port} udp_dport {port} && "
                f"sudo ip l2tp add session tunnel_id 2000 session_id 2000 peer_session_id 1000 name {dev} && "
                f"sudo ip link set dev {dev} address 02:00:00:00:00:02 mtu 1400 up && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip}")
    if proto_id == "wireguard":
        return ("# Run on remote server:\n"
                f"sudo ip link add dev {dev} type wireguard && "
                f"sudo wg set {dev} listen-port {port} peer {pub} allowed-ips 0.0.0.0/0 endpoint {local_bind}:{port} && "
                f"sudo ip addr add {rem_ip}/30 dev {dev} && sudo ip link set {dev} mtu {mtu} up && "
                f"sudo ip route replace {my_ip}/32 dev {dev} src {rem_ip}")
    return f"Configure {proto_id} on {remote} with remote {local_bind} and IP {rem_ip}/30"


def manual_create_interactive(proto_id: str, proto_name: str, preset_remote: Optional[str] = None):
    remote = preset_remote or input("Remote Server IP: ").strip()
    if not remote:
        return

    local_ips = get_all_local_ips()
    default_ip = get_route_ip(remote)
    local_bind = default_ip
    if len(local_ips) > 1:
        print("\n Detected Local IPs on this server:")
        for idx, lip in enumerate(local_ips, 1):
            tag = " (Default route)" if lip == default_ip else ""
            print(f"  {idx}) {lip}{tag}")
        sel = input(f"Select Local IP for tunnel [1-{len(local_ips)}, Default: {default_ip}]: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(local_ips):
            local_bind = local_ips[int(sel) - 1]
        elif sel.strip():
            local_bind = sel.strip()
    elif len(local_ips) == 1:
        sel = input(f"Select Local IP for tunnel [Default: {default_ip}]: ").strip()
        if sel.strip():
            local_bind = sel.strip()

    mtu = get_safe_mtu(get_base_mtu(remote))
    gw, phys_dev = get_default_gw()
    if gw and phys_dev and local_bind:
        run_cmd(f"ip route replace {remote} via {gw} dev {phys_dev} src {local_bind} 2>/dev/null")

    my_ip = input("Local Tunnel IP [10.0.0.1]: ").strip() or "10.0.0.1"
    rem_ip = input("Remote Tunnel IP [10.0.0.2]: ").strip() or "10.0.0.2"
    dev = input(f"Interface Name [{proto_id}1]: ").strip() or f"{proto_id}1"

    ok = False
    port = 0
    pub = ""
    if proto_id == "wireguard":
        priv, pub = gen_wg_keys()
        print(f"Your WireGuard Public Key: {pub}")
        peer_pub = input("Remote WireGuard Public Key: ").strip()
        port = int(input("Port [51820]: ").strip() or "51820")
        ok = TunnelDriver.setup_wireguard(dev, priv, peer_pub, remote, port, my_ip, rem_ip, mtu)
    elif proto_id == "vxlan":
        port = int(input("Port [4789]: ").strip() or "4789")
        ok = TunnelDriver.setup_vxlan(dev, remote, my_ip, rem_ip, mtu, port, local_bind=local_bind)
    elif proto_id == "geneve":
        port = int(input("Port [6081]: ").strip() or "6081")
        ok = TunnelDriver.setup_geneve(dev, remote, my_ip, rem_ip, mtu, port, local_bind=local_bind)
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
        print(_remote_command(proto_id, dev, local_bind, remote, my_ip, rem_ip, mtu, port, pub))
        print("=" * 70)

        if input(f"\nTest ping to {rem_ip} now? [y/N]: ").strip().lower() == "y":
            print(f"Pinging {rem_ip}...")
            ok_ping, p_out = run_cmd(f"ping -c 3 -W 2 {rem_ip}")
            print(p_out)
            if not ok_ping:
                print("\n[NOTE] Ping failed. Common causes:")
                print("1. Remote counterpart tunnel not created yet.")
                print("2. Remote firewall / rp_filter dropping packets.")
                print(f"3. Protocol ({proto_name}) may be filtered upstream.")
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
