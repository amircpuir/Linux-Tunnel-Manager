# Linux Tunnel Manager

A modular toolkit for creating, benchmarking and managing network tunnels
between two Linux servers. It benchmarks the common kernel tunnel types,
builds any of them with one command, handles routing / NAT / port-forwarding,
and ships **Holy Tunnel** — an encrypted, high-performance UDP tunnel with a
native Go core that runs as a service and comes back automatically after a
reboot.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main/tunnel.py -o tunnel.py && chmod +x tunnel.py && sudo python3 tunnel.py
```

`tunnel.py` is a small bootstrapper: on first run it installs the project
under `/opt/Linux-Tunnel-Manager`, then opens the menu. Running it again
updates the project and launches it.

Alternative (one-shot installer that also adds a `tunnel` command):

```bash
curl -fsSL https://raw.githubusercontent.com/amircpuir/Linux-Tunnel-Manager/main/install.sh | sudo bash
```

Then just:

```bash
sudo tunnel
```

---

## Features

- **Benchmark** — measures throughput, latency and loss for IPIP, GRE, GRETAP,
  EoIP, VXLAN, GENEVE, SIT/6in4, L2TPv3 and WireGuard, then ranks them.
- **Create tunnel** — builds any supported type on this host and prints the
  exact command to paste on the remote server.
- **Routing & forwarding** — peer routing, full-traffic routing (keeps SSH
  alive), NAT / internet sharing, diagnostics.
- **Port forwarding** — DNAT/MASQUERADE relay rules with persistence.
- **Holy Tunnel** — encrypted UDP tunnel, native Go core, managed by systemd.
- **Optimize** — sane sysctl tuning (BBR, buffers, forwarding) and dependency
  installation.

---

## Holy Tunnel

A lightweight encrypted UDP tunnel built on a TUN interface with a static Go
binary as its data plane (AES-256-GCM, per-datagram authentication).

- Configuration is saved to `/etc/holy-tunnel/config.json`.
- It runs under the `holy-tunnel` systemd service with `Restart=always` and is
  enabled on boot, so the link is re-established automatically after a reboot —
  nothing needs to be re-entered.

Set it up from the menu: **8) Holy Tunnel** → configure as *Server* on the
foreign/exit side and as *Client* on the local side, using the same shared key
on both ends.

Manual service control:

```bash
systemctl status holy-tunnel
systemctl restart holy-tunnel
journalctl -u holy-tunnel -f
```

---

## Project layout

```
tunnel.py              bootstrap launcher (the install target)
install.sh             one-shot installer
uninstall.sh           remove everything
ltm/                   Python package
  app.py               entry point (args, signals, dispatch)
  config.py            constants + state paths
  core/                system / network / firewall / messaging helpers
  protocols/           tunnel registry, drivers, cleanup
  benchmark/           throughput & latency engine
  managers/            server, client, manual, routing, portfwd, holy
  ui/                  top-level menu
holy/                  native UDP tunnel core (Go)
```

Run directly from a checkout without installing:

```bash
sudo python3 -m ltm            # interactive menu
sudo python3 -m ltm --role server
sudo python3 -m ltm --role client --remote 1.2.3.4
sudo python3 -m ltm --create gre --remote 1.2.3.4
```

---

## Requirements

- Linux with `iproute2`, `iptables`, root access.
- `python3` (standard library only).
- `go` is installed automatically the first time the Holy core is built.
- Optional: `iperf3`, `wireguard-tools` (installed on demand).

---
telegram: @Telhost1
