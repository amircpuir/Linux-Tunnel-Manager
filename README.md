# Linux Tunnel Manager 🛡️

A professional Python-based CLI tool to establish various network tunnels between Linux servers (e.g., Iran and Abroad). This script automates the complex `ip route` and `ip link` commands into a simple, user-friendly interface.

**Official Channel:** [@Telhost1](https://t.me/Telhost1)

---

## 🚀 Features
This manager supports 5 major tunneling protocols:
* **GRE:** Standard Generic Routing Encapsulation (Layer 3).
* **GRETAP:** Ethernet over GRE (Layer 2) for bridging.
* **IPIP:** Minimalist IPv4 in IPv4 tunneling.
* **VXLAN:** Industry-standard Virtual Extensible LAN.
* **L2TPv2:** Static Layer 2 Tunneling without complex daemons.

## 🛠️ Installation

First, update your system and ensure `git` and `python3` are installed:

```bash
sudo apt update && sudo apt install git python3 -y

git clone https://github.com/amircpuir/Linux-Tunnel-Manager.git

cd Linux-Tunnel-Manager

sudo python3 tunnel.py
