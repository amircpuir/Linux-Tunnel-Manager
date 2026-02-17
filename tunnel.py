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

# --- Automatic Optimization Functions ---

def enable_ip_forwarding():
    print(COLORS["BLUE"] + "[*] Enabling IP Forwarding & BBR..." + COLORS["ENDC"])
    commands = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.core.default_qdisc=fq",
        "sysctl -w net.ipv4.tcp_congestion_control=bbr"
    ]
    for cmd in commands:
        run_cmd(cmd, silent=True)
    
    # Make it persistent
    with open("/etc/sysctl.conf", "a+") as f:
        f.seek(0)
        content = f.read()
        if "net.ipv4.ip_forward=1" not in content:
            f.write("\nnet.ipv4.ip_forward=1\n")
            f.write("net.core.default_qdisc=fq\n")
            f.write("net.ipv4.tcp_congestion_control=bbr\n")

def configure_firewall_routing(dev_name):
    print(COLORS["BLUE"] + f"\n[*] Configuring Firewall & NAT for {dev_name}..." + COLORS["ENDC"])
    
    # 1. Masquerade (NAT) - Allow traffic to exit to internet
    run_cmd("iptables -t nat -A POSTROUTING -j MASQUERADE")
    
    # 2. Allow Forwarding for the interface
    run_cmd(f"iptables -A FORWARD -i {dev_name} -j ACCEPT")
    run_cmd(f"iptables -A FORWARD -o {dev_name} -j ACCEPT")
    
    # 3. MSS Clamping (Fixes 'pages not loading' issues due to MTU)
    run_cmd(f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    
    print(COLORS["GREEN"] + "[+] Network rules applied successfully." + COLORS["ENDC"])

def get_inputs():
    print(COLORS["BOLD"] + "Enter Configuration Details:" + COLORS["ENDC"])
    local = input("Local Server IP: ").strip()
    remote = input("Remote Server IP: ").strip()
    tun_ip = input("Tunnel Interface IP (e.g., 10.0.0.1/30): ").strip()
    dev_name = input("Interface Name (Default: tun1): ").strip() or "tun1"
    return local, remote, tun_ip, dev_name

# --- Tunnel Setups ---

def setup_gre():
    l, r, ip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type gre remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {ip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev)

def setup_gretap():
    l, r, ip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type gretap remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {ip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev)

def setup_ipip():
    l, r, ip, dev = get_inputs()
    if run_cmd(f"ip link add {dev} type ipip remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {ip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev)

def setup_vxlan():
    l, r, ip, dev = get_inputs()
    vni = input("VNI ID (Default 100): ").strip() or "100"
    if run_cmd(f"ip link add {dev} type vxlan id {vni} local {l} remote {r} dstport 4789"):
        run_cmd(f"ip addr add {ip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev)

def setup_l2tp():
    l, r, ip, dev = get_inputs()
    run_cmd("modprobe l2tp_eth", silent=True)
    tid, sid = "1000", "1000"
    
    cmd_t = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {tid} encap udp local {l} remote {r} udp_sport 5000 udp_dport 5000"
    cmd_s = f"ip l2tp add session name {dev} tunnel_id {tid} session_id {sid} peer_session_id {sid}"
    
    if run_cmd(cmd_t):
        run_cmd(cmd_s)
        run_cmd(f"ip addr add {ip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall_routing(dev)

def delete_tunnels():
    print(COLORS["BOLD"] + "\nEnter interface name to delete (e.g., tun1):" + COLORS["ENDC"])
    dev = input("Name: ").strip()
    if dev:
        run_cmd(f"ip link set {dev} down")
        run_cmd(f"ip link del {dev}")
        # Clean up iptables slightly (optional, safer not to flush all)
        print(COLORS["CYAN"] + "[i] Interface deleted. You may want to restart firewall rules if needed." + COLORS["ENDC"])

def main():
    check_root()
    
    # Auto-Optimize on startup
    enable_ip_forwarding()
    
    while True:
        print_banner()
        print("Select Tunnel Protocol:")
        print("1) GRE      (Layer 3 Standard)")
        print("2) GRETAP   (Layer 2 Bridge)")
        print("3) IPIP     (IPv4 in IPv4)")
        print("4) VXLAN    (Cloud Standard)")
        print("5) L2TPv2   (Static L2)")
        print(COLORS["RED"] + "9) Delete a Tunnel" + COLORS["ENDC"])
        print("0) Exit")
        
        choice = input("\nYour Choice: ").strip()
        
        if choice == '1': setup_gre()
        elif choice == '2': setup_gretap()
        elif choice == '3': setup_ipip()
        elif choice == '4': setup_vxlan()
        elif choice == '5': setup_l2tp()
        elif choice == '9': delete_tunnels()
        elif choice == '0': break
        else:
            print("Invalid Option!"); time.sleep(1); continue
        
        print("\n" + COLORS["GREEN"] + "Operation Completed Successfully." + COLORS["ENDC"])
        input("Press Enter to return to menu...")

if __name__ == "__main__":
    main()
