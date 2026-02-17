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
    "BOLD": "\033[1m",
    "YELLOW": "\033[93m"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(COLORS["CYAN"] + "=" * 60)
    print(COLORS["BOLD"] + "             Channel : @Telhost1             ")
    print("      ULTRA LINUX TUNNEL MANAGER (Auto-Fixer)      ")
    print(COLORS["CYAN"] + "=" * 60 + COLORS["ENDC"])
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
            print(COLORS["YELLOW"] + f"[!] Warning/Skip: {command}" + COLORS["ENDC"])
        return False

# --- SYSTEM OPTIMIZATION (The Magic Fix) ---
def force_kernel_settings():
    print(COLORS["BLUE"] + "[*] Applying Kernel Patches (Fixing Packet Loss)..." + COLORS["ENDC"])
    
    # 1. Disable Reverse Path Filter (قاتل تانل ها را غیرفعال میکنیم)
    # این گزینه باعث میشود پکت های تانل دراپ نشوند
    cmds = [
        "sysctl -w net.ipv4.conf.all.rp_filter=0",
        "sysctl -w net.ipv4.conf.default.rp_filter=0",
        "sysctl -w net.ipv4.conf.all.accept_source_route=0",
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv4.tcp_congestion_control=bbr",
        "sysctl -w net.core.default_qdisc=fq"
    ]
    
    for cmd in cmds:
        run_cmd(cmd, silent=True)
        
    # ذخیره دائمی
    with open("/etc/sysctl.d/99-tunnel-fix.conf", "w") as f:
        f.write("net.ipv4.conf.all.rp_filter=0\n")
        f.write("net.ipv4.conf.default.rp_filter=0\n")
        f.write("net.ipv4.ip_forward=1\n")

def configure_firewall(dev_name, remote_tun_ip):
    print(COLORS["BLUE"] + f"\n[*] Smashing Firewall Rules for {dev_name}..." + COLORS["ENDC"])
    
    # 1. Allow GRE Protocol (Protocol 47) - حیاتی برای تانل
    run_cmd("iptables -I INPUT -p gre -j ACCEPT", silent=True)
    run_cmd("iptables -I OUTPUT -p gre -j ACCEPT", silent=True)
    
    # 2. Allow UDP (VXLAN/L2TP)
    run_cmd("iptables -I INPUT -p udp -j ACCEPT", silent=True)
    
    # 3. Allow Forwarding Everything
    run_cmd(f"iptables -I FORWARD -i {dev_name} -j ACCEPT", silent=True)
    run_cmd(f"iptables -I FORWARD -o {dev_name} -j ACCEPT", silent=True)
    run_cmd("iptables -P FORWARD ACCEPT", silent=True) # Force policy
    
    # 4. NAT & Masquerade (برای عبور اینترنت)
    run_cmd("iptables -t nat -A POSTROUTING -j MASQUERADE", silent=True)
    
    # 5. Fix MTU Issues (حل مشکل باز نشدن سایت ها)
    run_cmd("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", silent=True)
    
    # 6. Force Route (حل مشکل Host Unreachable)
    peer_ip = remote_tun_ip.split('/')[0]
    print(COLORS["CYAN"] + f"[*] Adding forced route to {peer_ip}..." + COLORS["ENDC"])
    run_cmd(f"ip route replace {peer_ip} dev {dev_name}", silent=True)

def get_inputs():
    print(COLORS["BOLD"] + "Enter Configuration Details:" + COLORS["ENDC"])
    print(COLORS["YELLOW"] + "Note: If server is behind NAT (like Arvan/AWS), enter Local PRIVATE IP." + COLORS["ENDC"])
    
    local = input("Local IP (Source): ").strip()
    remote = input("Remote IP (Destination): ").strip()
    tun_ip = input("My Tunnel IP (e.g. 10.0.0.1/30): ").strip()
    remote_tun_ip = input("Peer Tunnel IP (e.g. 10.0.0.2): ").strip()
    dev_name = input("Interface Name (default: tun1): ").strip() or "tun1"
    
    return local, remote, tun_ip, remote_tun_ip, dev_name

# --- Setup Functions ---

def setup_gre():
    l, r, tip, rtip, dev = get_inputs()
    # حذف اینترفیس قدیمی اگر وجود دارد
    run_cmd(f"ip link del {dev}", silent=True)
    
    if run_cmd(f"ip link add {dev} type gre remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall(dev, rtip)

def setup_gretap():
    l, r, tip, rtip, dev = get_inputs()
    run_cmd(f"ip link del {dev}", silent=True)
    
    if run_cmd(f"ip link add {dev} type gretap remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall(dev, rtip)

def setup_ipip():
    l, r, tip, rtip, dev = get_inputs()
    run_cmd(f"ip link del {dev}", silent=True)
    
    if run_cmd(f"ip link add {dev} type ipip remote {r} local {l} ttl 255"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall(dev, rtip)

def setup_vxlan():
    l, r, tip, rtip, dev = get_inputs()
    vni = input("VNI ID (Default 100): ").strip() or "100"
    run_cmd(f"ip link del {dev}", silent=True)
    
    if run_cmd(f"ip link add {dev} type vxlan id {vni} local {l} remote {r} dstport 4789"):
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall(dev, rtip)

def setup_l2tp():
    l, r, tip, rtip, dev = get_inputs()
    run_cmd("modprobe l2tp_eth", silent=True)
    
    tid, sid = "1000", "1000"
    
    # Clean up old sessions
    run_cmd(f"ip l2tp del session tunnel_id {tid} session_id {sid}", silent=True)
    run_cmd(f"ip l2tp del tunnel tunnel_id {tid}", silent=True)
    
    cmd_t = f"ip l2tp add tunnel tunnel_id {tid} peer_tunnel_id {tid} encap udp local {l} remote {r} udp_sport 5000 udp_dport 5000"
    cmd_s = f"ip l2tp add session name {dev} tunnel_id {tid} session_id {sid} peer_session_id {sid}"
    
    if run_cmd(cmd_t):
        run_cmd(cmd_s)
        run_cmd(f"ip addr add {tip} dev {dev}")
        run_cmd(f"ip link set {dev} up")
        configure_firewall(dev, rtip)

def delete_tunnels():
    dev = input("\nEnter interface name to delete: ").strip()
    if dev:
        run_cmd(f"ip link set {dev} down")
        run_cmd(f"ip link del {dev}")
        print(COLORS["CYAN"] + "[i] Tunnel removed." + COLORS["ENDC"])

def main():
    check_root()
    force_kernel_settings() # Apply fixes immediately
    
    while True:
        print_banner()
        print("Select Tunnel Protocol:")
        print("1) GRE      (Best for most servers)")
        print("2) GRETAP   (Layer 2 / Bridge)")
        print("3) IPIP     (Low overhead)")
        print("4) VXLAN    (Best for NAT/Cloud)")
        print("5) L2TPv2   (Static UDP)")
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
        
        print("\n" + COLORS["GREEN"] + "Done! Try pinging the remote IP now." + COLORS["ENDC"])
        input("Press Enter...")

if __name__ == "__main__":
    main()
