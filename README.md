# Linux Tunnel & Benchmark Manager 🛡️

An advanced, enterprise-grade Python CLI suite to benchmark, deploy, and manage synchronized network tunnels between Linux servers (e.g., Iran and Abroad / VPS to VPS). This tool completely automates complex kernel tunneling, policy routing (`ip rule`), firewall rules (`iptables`), and asymmetric NAT port forwarding into a clean, intuitive terminal interface.

**GitHub Repository:** [amircpuir/Linux-Tunnel-Manager](https://github.com/amircpuir/Linux-Tunnel-Manager)  
**Official Channel:** [@Telhost1](https://t.me/Telhost1)

---

## 🚀 Key Features

### 1. 🌐 9 Supported Tunneling Protocols
* **IPIP:** Lightweight IPv4-in-IPv4 point-to-point tunnel (Layer 3).
* **GRE:** Standard Generic Routing Encapsulation for flexible IP transport (Layer 3).
* **GRETAP:** Ethernet over GRE with full Layer 2 framing and MAC support.
* **EoIP:** Ethernet over IP (MikroTik compatible Layer 2 tunnel).
* **VXLAN:** Scalable UDP-based tunnel (Port 4789) that easily traverses NAT and bypasses raw protocol filtering (Layer 2).
* **GENEVE:** Modern SDN encapsulation over UDP (Port 6081) with zero DPI footprint (Layer 2).
* **SIT (6in4):** Simple Internet Transition protocol (Layer 3).
* **L2TPv3:** High-performance static kernel L2TP tunnel over UDP (Port 5000) without external daemons (Layer 2).
* **WireGuard:** Ultra-fast, state-of-the-art modern encrypted tunnel (Layer 3).

### 2. ⚡ 5-Second Synchronized Fast Benchmark
* Accurately tests throughput, ping latency, and packet loss across all supported protocols in just 5 seconds per protocol.
* Client-Server handshake with dynamic MTU clamping and automated interface teardown (zero residual network junk left on your system).
* Automatic ranking leaderboard displaying the best protocol and a 1-click deployment command.

### 3. 🎯 Multi-IP & Cloud NAT Auto-Detection
* Automatically detects all public and failover IP addresses on the machine (essential for cloud providers like OVH, Hetzner, AWS, etc.).
* Allows explicit selection of the outgoing source IP to completely eliminate mismatched tunnel endpoint errors (`Destination Host Unreachable`).
* Automatically generates the exact counterpart bash command to run on the remote peer server.

### 4. 🔀 Advanced Tunnel Routing & Policy Routing (Menu Option 4)
* **Fix Peer Routing:** Automatically adds peer host routes (`/32`), enables IP forwarding, disables `rp_filter`, opens firewall rules, and tests live ping latency.
* **Route All Internet Traffic via Tunnel:** Safely redirects entire server traffic through the foreign tunnel gateway using policy routing table `100`.
* **Zero SSH Disconnection:** Protects SSH port 22 and local public IPs with high-priority routing rules so your remote management session never drops.
* **Routing Loop Prevention:** Automatically pins tunnel outer traffic to the physical gateway (Rule pref 500) to prevent recursive routing loops.
* **Foreign Server NAT & Internet Sharing:** 1-click setup for `MASQUERADE`, connection tracking, and `TCPMSS` clamping on the foreign server.

### 5. 🔄 High-Performance NAT Port Forwarding (Menu Option 7)
* Forwards ports from the local server (e.g., Iran) to any destination IP/port across the tunnel (e.g., Foreign VPS).
* **Solves Asymmetric Routing:** Automatically injects `POSTROUTING MASQUERADE` so the foreign server returns TCP packets through the tunnel rather than its default gateway (preventing handshake timeouts).
* **Port Range & Multi-Port Support:** Forward single ports (`443`), multiple comma-separated ports (`80,443,2083,8443`), or port ranges (`10000:20000`).
* **TCPMSS Clamping:** Automatically clamps MSS to path MTU to prevent packet fragmentation hangs on web traffic.
* **Rule Management:** Rules are saved in JSON, listed with IDs, and can be cleanly deleted or flushed without leaving orphaned iptables entries.

### 6. 🛠️ Dynamic Tunnel Management
* **Change Remote Endpoint IP:** Dynamically update foreign server IP on existing tunnels without recreation (great for dynamic IPs).
* **Change Internal Tunnel IP:** Quickly modify internal subnets and assign new IPs.
* **Delete Tunnel Interface:** 1-click list and delete for all active tunnel interfaces.
* **Kernel Network Optimization:** Automatically enables BBR congestion control, maximizes network buffers (`rmem`/`wmem`), and sets optimal sysctl parameters.

---

## 📦 Installation & Usage

### Method 1: Quick One-Liner (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main/tunnel.py -o tunnel.py && chmod +x tunnel.py && sudo python3 tunnel.py
```

حل مشکل بازگشت پکت‌ها با فعال‌سازی خودکار POSTROUTING MASQUERADE.
ذخیره دائمی قوانین در فایل JSON و امکان حذف بر اساس شماره رول.
</div>
📄 License
This project is licensed under the MIT License. Feel free to use and contribute.
Created with ❤️ by Ultra Tunnel Team (@Telhost1)
