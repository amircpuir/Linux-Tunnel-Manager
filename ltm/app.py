"""Entry point: argument parsing, signal handling, menu dispatch."""

import sys
import atexit
import signal
import argparse

from .config import SYNC_PORT, TEST_DURATION, ensure_state_dir
from .core.system import check_root
from .protocols.registry import PROTOCOLS
from .protocols.cleanup import auto_cleanup
from .managers.server import run_server_mode
from .managers.client import run_client_mode
from .managers.manual import manual_create_interactive
from .ui.menu import main_menu


def _install_signal_handlers():
    atexit.register(auto_cleanup)

    def _sig(_sig, _frame):
        auto_cleanup(verbose=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)


def main():
    parser = argparse.ArgumentParser(description="Linux Tunnel Manager")
    parser.add_argument("--role", choices=["server", "client", "clean", "remote", "local"])
    parser.add_argument("--remote", help="Remote server IP")
    parser.add_argument("--remote-ip", dest="remote_ip_alias", help="Remote server IP")
    parser.add_argument("--local-ip", dest="local_ip", help="Local IP to bind/test with")
    parser.add_argument("--port", type=int, default=SYNC_PORT)
    parser.add_argument("--duration", type=int, default=TEST_DURATION)
    parser.add_argument("--create", choices=[p["id"] for p in PROTOCOLS])
    args = parser.parse_args()

    check_root()
    ensure_state_dir()
    _install_signal_handlers()

    target_ip = args.remote or args.remote_ip_alias

    if args.role in ["server", "remote"]:
        run_server_mode(port=args.port, preset_ip=args.local_ip)
    elif args.role in ["client", "local"]:
        run_client_mode(remote_ip=target_ip, sync_port=args.port, local_ip_choice=args.local_ip)
    elif args.create:
        proto_name = next((p["name"] for p in PROTOCOLS if p["id"] == args.create), args.create.upper())
        manual_create_interactive(args.create, proto_name, preset_remote=target_ip)
    elif args.role == "clean":
        auto_cleanup(verbose=True)
    else:
        main_menu(sync_port=args.port)


if __name__ == "__main__":
    main()
