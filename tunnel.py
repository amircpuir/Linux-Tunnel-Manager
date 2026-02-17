import os
import subprocess
import sys
import time

# UI Colors
COLORS = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(COLORS["CYAN"] + "=" * 55)
    print(COLORS["BOLD"] + "           Channel : @Telhost1           ")
    print("      ALL-IN-ONE Linux Tunnel Manager      ")
    print(COLORS["CYAN"] + "=" * 55 + COLORS["ENDC"])
    print("")

def check_root():
    if os.geteuid() != 0:
        print(COLORS["RED"] + "[!] Error: This script must be run as root." + COLORS["ENDC"])
        sys.exit(1)

def run_cmd(command, silent=False):
    try:
        if silent:
            subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.check_call(command, shell=True)
            print(COLORS["GREEN"] + f"[+] Executed: {command}" + COLORS["ENDC"])
        return True
    except subprocess.CalledProcessError:
        if not silent:
            print(COLORS["RED"] + f"[-] Failed: {command}" + COLORS["ENDC"])
        return False

def enable_ip_forwarding():
    print(COLORS["BLUE"] + "[*] Optimizing System (Forwarding & BBR)..." + COLORS["ENDC"])
    commands = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.core.default_qdisc=fq",
        "sysctl -w net.ipv4.tcp_congestion_control=bbr",
        "iptables -I INPUT -p gre -j ACCEPT",  # Allow GRE Protocol
        "iptables -I FORWARD -j ACCEPT"        # Allow Forwarding
    ]
    for cmd in commands:
        run_cmd(cmd, silent=True)

def configure_firewall_routing(dev_name, remote_tun_ip):
    print(COLORS["BLUE"] + f"\n[*] Fixing Routing & NAT for {dev_name}..." + COLORS["ENDC"])
    
    # 1. Direct Route to Peer (Fixes Host Unreachable)
    # Extracting IP from CIDR if needed
    peer_ip = remote_tun_ip.split('/')[0]
    run_cmd(f"ip route add {peer_ip} dev {dev_name}", silent=True)
    
    # 2. NAT & MSS Clamping
    run_cmd("iptables -t nat -A POSTROUTING -j MASQUERADE")
    run_cmd(f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    
    print(COLORS["GREEN"] + f"[+] Routing set to {peer_ip} via {dev_name}" + COLORS["ENDC"])

def get_inputs():
    print(COLORS["BOLD"] + "Enter Configuration Details:" + COLORS["ENDC"])
    local = input("Local Public IP: ").strip()
    remote = input("Remote Public IP: ").strip()
    tun_ip = input("This Server Tunnel IP (e.g., 10.0.0.2/30): ").strip()
    remote_tun = input("Remote Server Tunnel IP (e.g., 10.0.0.1): ").strip()
    dev_name = input("Interface Name (Default: tun1): ").strip() or "tun1"
    return local, remote, tun_ip, remote_tun, dev_name

# --- Tunnel Setups ---

def setup_gre():
    l, r, tip, rtip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type gre remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev, rtip)

def setup_gretap():
    l, r, tip, rtip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type gretap remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev, rtip)

def setup_ipip():
    l, r, tip, rtip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type ipip remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev, rtip)

def setup_vxlan():
    l, r, tip, rtip, dev = get_inputs()
    vni = input("VNI ID (Default 100): ").strip() or "100"
    if run_cmd(f"ip link add {dev} type vxlan id {vni} local {l} remote {r} dstport 4789"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev, rtip)

def setup_l2tp():
    l, r, tip, rtip, dev = get_inputs()
    run_cmd("modprobe l2tp_eth", silent=True)
    tid, sid = "1000", "1000"
    cmd_t = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {tid} encap udp local {l} remote {r} udp_sport 5000 udp_dport 5000"
    cmd_s = f"ip l2tp add session name {dev} tunnel_id {tid} session_id {sid} peer_session_id {sid}"
    if run_cmd(cmd_t):
        run_cmd(cmd_s)
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev, rtip)

def delete_tunnels():
    dev = input("\nEnter interface name to delete: ").strip()
    if dev:
        run_cmd(f"ip link set {dev} down")
        run_cmd(f"ip link del {dev}")
        print(COLORS["CYAN"] + "[i] Tunnel removed." + COLORS["ENDC"])

def main():
    check_root()
    enable_ip_forwarding()
    while True:
        print_banner()
        print("Select Tunnel Protocol:")
        print("1) GRE      (Layer 3)")
        print("2) GRETAP   (Layer 2)")
        print("3) IPIP")
        print("4) VXLAN")
        print("5) L2TPv2")
        print(COLORS["RED"] + "9) Delete Tunnel" + COLORS["ENDC"])
        print("0) Exit")
        choice = input("\nYour Choice: ").strip()
        if choice == '1': setup_gre()
        elif choice == '2': setup_gretap()
        elif choice == '3': setup_ipip()
        elif choice == '4': setup_vxlan()
        elif choice == '5': setup_l2tp()
        elif choice == '9': delete_tunnels()
        elif choice == '0': break
        else: continue
        print("\n" + COLORS["GREEN"] + "Operation Completed." + COLORS["ENDC"])
        input("Press Enter...")

if __name__ == "__main__":
    main()
