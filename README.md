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

Method 2: Git Clone
code
Bash
# Update package list and install dependencies
sudo apt update && sudo apt install -y git python3 iptables iproute2

# Clone repository
git clone https://github.com/amircpuir/Linux-Tunnel-Manager.git

# Navigate into directory
cd Linux-Tunnel-Manager

# Run script with root privileges
sudo python3 tunnel.py
🎮 CLI Arguments & Fast Execution
You can run the script interactively or pass command-line arguments:
code
Bash
# Start Server Listener (Run on Foreign / Destination Server):
sudo python3 tunnel.py --role server --port 9876

# Run Synchronized Benchmark (Run on Local / Iran Server):
sudo python3 tunnel.py --role client --remote <REMOTE_SERVER_IP>

# Clean all virtual test interfaces:
sudo python3 tunnel.py --role clean
📋 Interactive Menu Overview
code
Text
==============================
 Tunnel Manager & Benchmark
==============================
1) Run Benchmark (Client)
2) Start Listener (Server)
3) Create Tunnel
4) Tunnel Routing & Forwarding
5) Delete Tunnel
6) Change Tunnel IP
7) Port Forwarding
8) Optimize Network
9) Clean Interfaces
0) Exit
------------------------------
<div dir="rtl">
🇮🇷 راهنمای فارسی (توضیحات و امکانات نسخه جدید)
اسکریپت Linux Tunnel & Benchmark Manager یک ابزار حرفه‌ای و جامع برای تست، ساخت، روتینگ و مدیریت انواع تانل‌های شبکه بین سرورهای لینوکسی (به ویژه سرور ایران و خارج) است.
قابلیت‌های کلیدی نسخه جدید:
پشتیبانی از ۹ پروتکل تانل لینوکس:
IPIP: تانل لایه ۳ سبک و مستقیم.
GRE & GRETAP: پروتکل‌های استاندارد با پشتیبانی از لایه ۲ (مک‌آدرس) و لایه ۳.
EoIP: اترنت روی آی‌پی، سازگار با میکروتیک (لایه ۲).
VXLAN & GENEVE: تانل‌های مدرن ابری روی پورت‌های UDP (4789 و 6081) با قابلیت عبور آسان از فیلترینگ و فایروال به دلیل کپسوله‌سازی داخل بسته‌های استاندارد UDP.
SIT (6in4): تانل پایدار با هدر سبک.
L2TPv3: تانل لایه ۲ مستقیم کرنل روی پورت UDP 5000 بدون نیاز به دیمن‌های سنگین.
WireGuard: تانل فوق‌سریع و رمزنگاری‌شده مدرن.
تست همگام ۵ ثانیه‌ای پهنای باند و پینگ (Synchronized Benchmark):
تست خودکار تمام پروتکل‌ها بین دو سرور در عرض ۵ ثانیه به ازای هر تانل.
نمایش رتبه‌بندی بر اساس سرعت، تاخیر (Ping)، پکت‌لاس و امتیاز کلی.
پاکسازی ۱۰۰٪ کارت‌های شبکه تستی پس از پایان تست بدون باقی ماندن اینترفیس اضافه.
تشخیص هوشمند سرورهای چند آی‌پی (Multi-IP Support):
شناسایی تمام آی‌پی‌های سرور (مناسب برای OVH، هتزنر و دیتاسنترهایی با Failover IP).
جلوگیری کامل از خطای Destination Host Unreachable با اتصال دقیق سورس آی‌پی به مقصد.
چاپ دستور آماده برای کپی و اجرا روی سرور مقابل.
بخش تخصصی روتینگ و هدایت ترافیک (گزینه ۴ منو):
حل مشکل Destination Unreachable: ثبت خودکار روت‌های نظیر (/32)، غیرفعال کردن rp_filter و تست پینگ زنده.
انتقال کل اینترنت از تانل: هدایت ترافیک سرور به خارج بدون قطع شدن SSH (از طریق جدول روتینگ مجزای ۱۰۰ و حفاظت از پورت ۲۲).
جلوگیری از لوپ روتینگ: اتصال پکت‌های اصلی تانل به گیت‌وی فیزیکی با اولویت ۵۰۰ تا تانل قطع نشود.
اشتراک اینترنت سرور خارج (NAT): فعال‌سازی یک‌کلیکه MASQUERADE، فورواردینگ و TCPMSS Clamping روی سرور خارج.
پورت فورواردینگ پیشرفته (گزینه ۷ منو):
پشتیبانی از پورت تکی (443)، چند پورت (80,443,2083) و رنج پورت (10000:20000).
حل مشکل بازگشت پکت‌ها با فعال‌سازی خودکار POSTROUTING MASQUERADE.
ذخیره دائمی قوانین در فایل JSON و امکان حذف بر اساس شماره رول.
</div>
📄 License
This project is licensed under the MIT License. Feel free to use and contribute.
Created with ❤️ by Ultra Tunnel Team (@Telhost1)
