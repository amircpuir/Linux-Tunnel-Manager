import os
import subprocess
import sys
import socket
import time

# UI Colors
COLORS = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "YELLOW": "\033[93m"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(COLORS["CYAN"] + "=" * 60)
    print(COLORS["BOLD"] + "             Channel : @Telhost1             ")
    print("      ULTRA TUNNEL MANAGER (Full Suite + NAT-Fix)      ")
    print(COLORS["CYAN"] + "=" * 60 + COLORS["ENDC"])

def check_root():
    if os.geteuid() != 0:
        print(COLORS["RED"] + "[!] Error: Run as root." + COLORS["ENDC"])
        sys.exit(1)

def run_cmd(command, silent=False):
    try:
        if silent:
            subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.check_call(command, shell=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def optimize_system(dev_name=None, remote_tun_ip=None):
    # تنظیمات سیستمی برای پایداری ۱۰۰٪
    run_cmd("sysctl -w net.ipv4.ip_forward=1", True)
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0", True)
    run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0", True)
    run_cmd("iptables -P FORWARD ACCEPT", True)
    run_cmd("iptables -t nat -A POSTROUTING -j MASQUERADE", True)
    run_cmd("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", True)
    
    if dev_name and remote_tun_ip:
        peer_ip = remote_tun_ip.split('/')[0]
        run_cmd(f"ip route replace {peer_ip} dev {dev_name}", True)

def get_inputs(is_l2=False):
    print(COLORS["YELLOW"] + f"[*] Local (Internal) IP detected: {get_local_ip()}" + COLORS["ENDC"])
    r_pub = input("Remote PUBLIC IP: ").strip()
    my_tun = input("My Tunnel IP (e.g. 10.0.0.1): ").strip()
    rem_tun = input("Remote Tunnel IP (e.g. 10.0.0.2): ").strip()
    dev = input("Interface Name (default: tun1): ").strip() or "tun1"
    return r_pub, my_tun, rem_tun, dev

# --- Protocols ---

def setup_gre():
    r_pub, my_tun, rem_tun, dev = get_inputs()
    run_cmd(f"ip link del {dev}", True)
    if run_cmd(f"ip link add {dev} type gre remote {r_pub} local {get_local_ip()} ttl 255"):
        run_cmd(f"ip addr add {my_tun} peer {rem_tun} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        optimize_system(dev, rem_tun)
        print(COLORS["GREEN"] + f"[+] GRE Tunnel {dev} is UP!" + COLORS["ENDC"])

def setup_gretap():
    r_pub, my_tun, rem_tun, dev = get_inputs()
    run_cmd(f"ip link del {dev}", True)
    if run_cmd(f"ip link add {dev} type gretap remote {r_pub} local {get_local_ip()} ttl 255"):
        run_cmd(f"ip addr add {my_tun}/30 dev {dev}")
        run_cmd(f"ip link set {dev} up")
        optimize_system(dev, rem_tun)
        print(COLORS["GREEN"] + f"[+] GRETAP (L2) Tunnel {dev} is UP!" + COLORS["ENDC"])

def setup_ipip():
    r_pub, my_tun, rem_tun, dev = get_inputs()
    run_cmd(f"ip link del {dev}", True)
    if run_cmd(f"ip link add {dev} type ipip remote {r_pub} local {get_local_ip()} ttl 255"):
        run_cmd(f"ip addr add {my_tun} peer {rem_tun} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        optimize_system(dev, rem_tun)
        print(COLORS["GREEN"] + f"[+] IPIP Tunnel {dev} is UP!" + COLORS["ENDC"])

def setup_vxlan():
    r_pub, my_tun, rem_tun, dev = get_inputs()
    vni = input("VNI ID (default 100): ").strip() or "100"
    run_cmd(f"ip link del {dev}", True)
    if run_cmd(f"ip link add {dev} type vxlan id {vni} remote {r_pub} local {get_local_ip()} dstport 4789"):
        run_cmd(f"ip addr add {my_tun}/30 dev {dev}")
        run_cmd(f"ip link set {dev} up")
        optimize_system(dev, rem_tun)
        print(COLORS["GREEN"] + f"[+] VXLAN Tunnel {dev} is UP!" + COLORS["ENDC"])

def setup_l2tp():
    r_pub, my_tun, rem_tun, dev = get_inputs()
    run_cmd("modprobe l2tp_eth", True)
    tid, sid = "1000", "1000"
    run_cmd(f"ip l2tp del session tunnel_id {tid} session_id {sid}", True)
    run_cmd(f"ip l2tp del tunnel tunnel_id {tid}", True)
    
    if run_cmd(f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {tid} encap udp local {get_local_ip()} remote {r_pub} udp_sport 5000 udp_dport 5000"):
        run_cmd(f"ip l2tp add session name {dev} tunnel_id {tid} session_id {sid} peer_session_id {sid}")
        run_cmd(f"ip addr add {my_tun} peer {rem_tun} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        optimize_system(dev, rem_tun)
        print(COLORS["GREEN"] + f"[+] L2TPv2 Tunnel {dev} is UP!" + COLORS["ENDC"])

def delete_all():
    dev = input("Interface to delete: ").strip()
    run_cmd(f"ip link set {dev} down", True)
    run_cmd(f"ip link del {dev}", True)
    print(COLORS["CYAN"] + "[!] Deleted." + COLORS["ENDC"])

def main():
    check_root()
    while True:
        print_banner()
        print(f"{COLORS['YELLOW']}Current Local IP: {get_local_ip()}{COLORS['ENDC']}\n")
        print("1) GRE (Standard L3)")
        print("2) GRETAP (Bridge L2)")
        print("3) IPIP (IPv4 in IPv4)")
        print("4) VXLAN (UDP Encap - Best for Cloud)")
        print("5) L2TPv2 (Static UDP)")
        print(f"{COLORS['RED']}9) Delete Tunnel{COLORS['ENDC']}")
        print("0) Exit")
        
        choice = input("\nSelect: ").strip()
        if choice == '1': setup_gre()
        elif choice == '2': setup_gretap()
        elif choice == '3': setup_ipip()
        elif choice == '4': setup_vxlan()
        elif choice == '5': setup_l2tp()
        elif choice == '9': delete_all()
        elif choice == '0': break
        input("\nPress Enter to return...")

if __name__ == "__main__":
    main()
