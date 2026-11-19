"""Holy Tunnel integration: build the native core, persist its configuration,
and run it under systemd so the link is restored automatically after a reboot.

Holy is a high-performance, encrypted UDP tunnel with a native (Go) data plane.
Its endpoint settings are written to a JSON file and loaded by a systemd
service on every (re)start; nothing has to be re-entered after a reboot.
"""

import os
import json
import base64
import shutil
import secrets
import time

from ..config import HOLY_BIN, HOLY_DIR, HOLY_CONFIG, HOLY_SERVICE, HOLY_UNIT
from ..core.system import run_cmd
from ..core.netinfo import get_default_gw, get_route_ip

# Repo root = .../Linux-Tunnel-Manager ; native source lives in ./holy
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC_DIR = os.path.join(_REPO_ROOT, "holy")


# --------------------------------------------------------------------------- #
# Core build / install
# --------------------------------------------------------------------------- #
def _ensure_go() -> bool:
    if shutil.which("go"):
        return True
    print("\n[*] Go toolchain not found — installing...")
    if shutil.which("apt-get"):
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go")
    elif shutil.which("dnf"):
        run_cmd("dnf install -y -q golang")
    elif shutil.which("yum"):
        run_cmd("yum install -y -q golang")
    return bool(shutil.which("go"))


def build_core(force: bool = False) -> bool:
    if os.path.exists(HOLY_BIN) and not force:
        return True
    if not os.path.isdir(_SRC_DIR):
        print(f"[!] Source directory not found: {_SRC_DIR}")
        return False
    if not _ensure_go():
        print("[!] Could not install the Go toolchain. Install it manually and retry.")
        return False

    print("[*] Building Holy core (this may take a moment)...")
    ok, out = run_cmd(
        f"cd '{_SRC_DIR}' && CGO_ENABLED=0 go build -trimpath "
        f"-ldflags '-s -w -X main.version=3.0.0' -o '{HOLY_BIN}' . && chmod +x '{HOLY_BIN}'"
    )
    if ok and os.path.exists(HOLY_BIN):
        print(f"[OK] Core installed at {HOLY_BIN}")
        return True
    print(f"[!] Build failed:\n{out}")
    return False


# --------------------------------------------------------------------------- #
# Config persistence
# --------------------------------------------------------------------------- #
def _gen_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")


def save_config(cfg: dict):
    os.makedirs(HOLY_DIR, exist_ok=True)
    with open(HOLY_CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(HOLY_CONFIG, 0o600)


def load_config() -> dict:
    if os.path.exists(HOLY_CONFIG):
        try:
            with open(HOLY_CONFIG, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


# --------------------------------------------------------------------------- #
# systemd service (reboot persistence)
# --------------------------------------------------------------------------- #
_UNIT_TEMPLATE = """[Unit]
Description=Holy Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} --config {config}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""


def install_service() -> bool:
    if not os.path.exists(HOLY_BIN):
        print("[!] Core binary is missing — build it first.")
        return False
    with open(HOLY_UNIT, "w") as f:
        f.write(_UNIT_TEMPLATE.format(bin=HOLY_BIN, config=HOLY_CONFIG))
    run_cmd("systemctl daemon-reload")
    run_cmd(f"systemctl enable {HOLY_SERVICE} >/dev/null 2>&1")
    ok, out = run_cmd(f"systemctl restart {HOLY_SERVICE}")
    time.sleep(1.0)
    if ok:
        print(f"[OK] Service '{HOLY_SERVICE}' enabled and started (auto-starts on reboot).")
    else:
        print(f"[!] Failed to start service:\n{out}")
    return ok


def _open_udp(port: int):
    run_cmd(f"iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p icmp -j ACCEPT 2>/dev/null")


# --------------------------------------------------------------------------- #
# Interactive configuration
# --------------------------------------------------------------------------- #
def _configure(role: str):
    if not build_core():
        input("\nPress Enter to return...")
        return

    existing = load_config()
    tun_name = input("Interface name [holy0]: ").strip() or "holy0"
    mtu = input("MTU [1300]: ").strip() or "1300"

    if role == "server":
        port = input("Listen UDP port [2096]: ").strip() or "2096"
        secret = input("Shared key (blank = auto-generate): ").strip() or _gen_secret()
        my_ip = input("Local inner IP [10.200.0.1]: ").strip() or "10.200.0.1"
        peer_ip = input("Remote inner IP [10.200.0.2]: ").strip() or "10.200.0.2"
        cfg = {
            "role": "server",
            "listen": f"0.0.0.0:{port}",
            "secret": secret,
            "tun_name": tun_name,
            "tun_ip": my_ip,
            "peer_ip": peer_ip,
            "prefix": 30,
            "mtu": int(mtu),
            "keepalive": 15,
        }
        _open_udp(int(port))
    else:  # client
        remote_host = input("Remote server IP/host: ").strip()
        if not remote_host:
            print("Remote host is required.")
            input("\nPress Enter to return...")
            return
        port = input("Remote UDP port [2096]: ").strip() or "2096"
        default_secret = existing.get("secret", "")
        prompt = f"Shared key [{'<stored>' if default_secret else 'required'}]: "
        secret = input(prompt).strip() or default_secret
        if not secret:
            print("Shared key is required (must match the server).")
            input("\nPress Enter to return...")
            return
        my_ip = input("Local inner IP [10.200.0.2]: ").strip() or "10.200.0.2"
        peer_ip = input("Remote inner IP [10.200.0.1]: ").strip() or "10.200.0.1"
        cfg = {
            "role": "client",
            "remote": f"{remote_host}:{port}",
            "secret": secret,
            "tun_name": tun_name,
            "tun_ip": my_ip,
            "peer_ip": peer_ip,
            "prefix": 30,
            "mtu": int(mtu),
            "keepalive": 15,
        }
        # Keep the path to the server off the tunnel.
        gw, pdev = get_default_gw()
        lb = get_route_ip(remote_host)
        if gw and pdev and lb:
            run_cmd(f"ip route replace {remote_host} via {gw} dev {pdev} src {lb} 2>/dev/null")

    save_config(cfg)
    print(f"\n[OK] Configuration saved to {HOLY_CONFIG}")
    if role == "server":
        print("\n" + "=" * 60)
        print(" Share these with the client side:")
        print(f"   Server IP   : <this server's public IP>")
        print(f"   UDP Port    : {cfg['listen'].split(':')[1]}")
        print(f"   Shared key  : {cfg['secret']}")
        print(f"   Inner IPs   : server {cfg['tun_ip']} / client {cfg['peer_ip']}")
        print("=" * 60)

    install_service()
    input("\nPress Enter to return...")


# --------------------------------------------------------------------------- #
# Menu
# --------------------------------------------------------------------------- #
def holy_menu():
    while True:
        running = run_cmd(f"systemctl is-active {HOLY_SERVICE}")[1].strip()
        state = running if running in ("active", "inactive", "failed") else "not-installed"
        print("\n--- Holy Tunnel ---")
        print(f"    status: {state}")
        print("1) Build / update core")
        print("2) Configure as Server  (foreign / exit side)")
        print("3) Configure as Client  (local side)")
        print("4) Service status")
        print("5) View live logs")
        print("6) Restart service")
        print("7) Stop & disable service")
        print("8) Uninstall Holy completely")
        print("0) Back")
        c = input("Select [0-8]: ").strip()
        if c == "0":
            break
        elif c == "1":
            build_core(force=True)
            input("\nPress Enter to return...")
        elif c == "2":
            _configure("server")
        elif c == "3":
            _configure("client")
        elif c == "4":
            _, out = run_cmd(f"systemctl status {HOLY_SERVICE} --no-pager -l")
            print(out)
            input("\nPress Enter to return...")
        elif c == "5":
            print("(Ctrl+C to stop following)")
            os.system(f"journalctl -u {HOLY_SERVICE} -n 50 -f")
        elif c == "6":
            run_cmd(f"systemctl restart {HOLY_SERVICE}")
            print("[OK] Restarted.")
            time.sleep(1)
        elif c == "7":
            run_cmd(f"systemctl stop {HOLY_SERVICE}")
            run_cmd(f"systemctl disable {HOLY_SERVICE} >/dev/null 2>&1")
            print("[OK] Stopped and disabled.")
            time.sleep(1)
        elif c == "8":
            _uninstall()


def _uninstall():
    if input("Remove Holy service, binary and config? [y/N]: ").strip().lower() != "y":
        return
    run_cmd(f"systemctl stop {HOLY_SERVICE} 2>/dev/null")
    run_cmd(f"systemctl disable {HOLY_SERVICE} >/dev/null 2>&1")
    for path in (HOLY_UNIT, HOLY_BIN, HOLY_CONFIG):
        try:
            os.remove(path)
        except Exception:
            pass
    run_cmd("systemctl daemon-reload")
    print("[OK] Holy removed.")
    time.sleep(1)
