"""Tunnel routing / forwarding helpers (peer routing, default route, NAT)."""

import time

from ..core.system import run_cmd
from ..core.netinfo import get_all_local_ips, get_default_gw, get_route_ip
from .tunnels import list_system_tunnels, get_tunnel_details


def _choose_dev(prompt="Enter tunnel interface (e.g. ipip1, gre1): "):
    tunnels = list_system_tunnels()
    if tunnels:
        print("\nAvailable tunnel interfaces:")
        for i, tun in enumerate(tunnels, 1):
            det = get_tunnel_details(tun["dev"])
            hint = f"-> {det['peer_tunnel_ip']}" if det["peer_tunnel_ip"] else ""
            print(f"  {i}) {tun['dev']} ({tun['ip']} {hint})")
        sel = input(f"Select interface [1-{len(tunnels)}] or enter name: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(tunnels):
            return tunnels[int(sel) - 1]["dev"]
        return sel
    return input(prompt).strip()


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
            _peer_routing()
        elif c == "2":
            _route_all()
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
            _enable_nat()
        elif c == "5":
            _diagnose()
        elif c == "6":
            _show_routes()


def _peer_routing():
    dev = _choose_dev()
    if not dev:
        return
    det = get_tunnel_details(dev)
    my_tunnel_ip = input(f"Local Tunnel IP [{det['local_tunnel_ip'] or '10.0.0.1'}]: ").strip() or (det["local_tunnel_ip"] or "10.0.0.1")
    peer_tunnel_ip = input(f"Remote Tunnel IP [{det['peer_tunnel_ip'] or '10.0.0.2'}]: ").strip() or (det["peer_tunnel_ip"] or "10.0.0.2")
    remote_server_ip = input(f"Remote Server Public IP [{det['remote_outer']}]: ").strip() or det["remote_outer"]

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
    _, p_out = run_cmd(f"ping -c 3 -W 2 {peer_tunnel_ip}")
    print(p_out)
    input("\nPress Enter to return...")


def _route_all():
    dev = _choose_dev()
    if not dev:
        return
    det = get_tunnel_details(dev)
    peer_tunnel_ip = input(f"Remote Tunnel IP (Gateway) [{det['peer_tunnel_ip'] or '10.0.0.2'}]: ").strip() or (det["peer_tunnel_ip"] or "10.0.0.2")
    remote_outer_ip = input(f"Remote Server Outer Public IP [{det['remote_outer']}]: ").strip() or det["remote_outer"]

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
    time.sleep(1)
    ok_curl, out_curl = run_cmd("curl -s --max-time 3 https://api.ipify.org")
    if ok_curl and out_curl.strip():
        print(f"Current Public IP: {out_curl.strip()}")
    else:
        print("Could not query public IP. Enable NAT/MASQUERADE on the foreign server (option 4)!")
    input("\nPress Enter to return...")


def _enable_nat():
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


def _diagnose():
    tunnels = list_system_tunnels()
    if not tunnels:
        print("No tunnels found.")
        time.sleep(1)
        return
    for i, tun in enumerate(tunnels, 1):
        det = get_tunnel_details(tun["dev"])
        print(f"  {i}) {tun['dev']} (IP: {tun['ip']}, Peer: {det['peer_tunnel_ip']}, Endpoint: {det['remote_outer']})")
    sel = input("Select tunnel to diagnose: ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(tunnels):
        t = tunnels[int(sel) - 1]
        det = get_tunnel_details(t["dev"])
        print(f"\n--- Diagnosing {t['dev']} ---")
        _, out_link = run_cmd(f"ip link show dev {t['dev']}")
        print(f"Link Status: {'UP' if 'UP' in out_link else 'DOWN'}")
        print(f"Local IP: {det['local_tunnel_ip']}")
        print(f"Peer IP: {det['peer_tunnel_ip']}")
        print(f"Remote Server Outer IP: {det['remote_outer']}")
        if det["peer_tunnel_ip"]:
            print(f"\nPinging peer {det['peer_tunnel_ip']}...")
            _, p_out = run_cmd(f"ping -c 4 -W 2 {det['peer_tunnel_ip']}")
            print(p_out)
    input("\nPress Enter to return...")


def _show_routes():
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
