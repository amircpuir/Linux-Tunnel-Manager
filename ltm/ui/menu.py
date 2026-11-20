"""Top-level interactive menu."""

import sys
import time

from .. import __version__
from ..config import SYNC_PORT
from ..core.system import install_deps, optimize_sysctl
from ..protocols.cleanup import auto_cleanup
from ..managers.server import run_server_mode
from ..managers.client import run_client_mode
from ..managers.manual import manual_menu
from ..managers.routing import tunnel_routing_menu
from ..managers.tunnels import delete_tunnel_menu, change_tunnel_ip_menu
from ..managers.portfwd import port_fwd_menu
from ..managers.holy import holy_menu


def _banner():
    print("\n==================================")
    print(f" Linux Tunnel Manager  v{__version__}")
    print("==================================")
    print("1) Run Benchmark (Client)")
    print("2) Start Listener (Server)")
    print("3) Create Tunnel")
    print("4) Tunnel Routing & Forwarding")
    print("5) Delete Tunnel")
    print("6) Change Tunnel IP")
    print("7) Port Forwarding")
    print("8) Holy Tunnel")
    print("9) Optimize Network")
    print("c) Clean Interfaces")
    print("0) Exit")
    print("----------------------------------")


def main_menu(sync_port: int = SYNC_PORT):
    while True:
        _banner()
        choice = input("Select option: ").strip().lower()

        if choice == "1":
            run_client_mode(sync_port=sync_port)
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            p_in = input(f"Port [{SYNC_PORT}]: ").strip()
            p = int(p_in) if p_in.isdigit() else SYNC_PORT
            run_server_mode(port=p)
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            manual_menu()
        elif choice == "4":
            tunnel_routing_menu()
        elif choice == "5":
            delete_tunnel_menu()
        elif choice == "6":
            change_tunnel_ip_menu()
        elif choice == "7":
            port_fwd_menu()
        elif choice == "8":
            holy_menu()
        elif choice == "9":
            install_deps()
            optimize_sysctl()
            print("System optimized.")
            time.sleep(1)
        elif choice == "c":
            auto_cleanup(verbose=True)
        elif choice == "0":
            auto_cleanup()
            sys.exit(0)
