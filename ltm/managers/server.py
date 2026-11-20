"""Server (listener) role: accepts a client, builds tunnels on demand, measures."""

import shutil
import socket

from ..config import SYNC_PORT, STREAM_PORT, TEST_DURATION, SUBNET_LOCAL, SUBNET_REMOTE, HOLY_BENCH_PORT
from ..core.system import check_root, install_deps, optimize_sysctl
from ..core.netinfo import (get_public_ip, get_route_ip, get_all_local_ips,
                            get_default_gw, get_base_mtu, get_safe_mtu)
from ..core.firewall import open_firewall
from ..core.wire import send_msg, recv_msg
from ..protocols.drivers import TunnelDriver, gen_wg_keys
from ..protocols.cleanup import auto_cleanup
from ..benchmark.engine import TcpReceiverThread, BenchmarkEngine
from . import holy_runtime


def _select_server_ip(preset_ip, local_ips, default_ip, pub_ip):
    if preset_ip:
        return preset_ip
    if len(local_ips) > 1:
        print("\n==========================================")
        print(" Detected Local IPs on this server:")
        print("==========================================")
        for idx, lip in enumerate(local_ips, 1):
            tag = " (Default route / Public)" if lip in [default_ip, pub_ip] else ""
            print(f"  {idx}) {lip}{tag}")
        print("  0) All interfaces (0.0.0.0)")
        sel = input(f"\nSelect Local IP for server listener & test [1-{len(local_ips)}, Default: {default_ip}]: ").strip()
        if sel.isdigit():
            val = int(sel)
            if 1 <= val <= len(local_ips):
                return local_ips[val - 1]
            if val == 0:
                return "0.0.0.0"
        elif sel:
            return sel
        return default_ip
    if len(local_ips) == 1:
        print(f"\nDetected Local IP on this server: {default_ip}")
        sel = input(f"Select Local IP for server listener & test [Default: {default_ip}]: ").strip()
        return sel if sel else default_ip
    return default_ip


def _build_tunnel(proto, dev, peer_pub, local_route, mtu, configured_ports, wg_priv, peer_wg_pub, cmd, holder=None):
    if proto == "holy":
        if not holy_runtime.ensure_core():
            return False
        proc = holy_runtime.start_transient(
            "server", dev, local_route, peer_pub,
            cmd.get("holy_port", HOLY_BENCH_PORT), cmd.get("holy_key", ""),
            SUBNET_REMOTE, SUBNET_LOCAL, mtu)
        if proc is None:
            return False
        if holder is not None:
            holder["proc"] = proc
        return True
    if proto == "wireguard":
        return TunnelDriver.setup_wireguard(dev, wg_priv, peer_wg_pub or cmd.get("peer_wg_pub", ""),
                                            peer_pub, configured_ports.get("wireguard", 51820),
                                            SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "gre":
        return TunnelDriver.setup_gre(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "gretap":
        return TunnelDriver.setup_gretap(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "ipip":
        return TunnelDriver.setup_ipip(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "eoip":
        return TunnelDriver.setup_eoip(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "vxlan":
        return TunnelDriver.setup_vxlan(dev, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu,
                                        configured_ports.get("vxlan", 4789), is_server=True, local_bind=local_route)
    if proto == "geneve":
        return TunnelDriver.setup_geneve(dev, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu,
                                         configured_ports.get("geneve", 6081), is_server=True, local_bind=local_route)
    if proto == "sit":
        return TunnelDriver.setup_sit(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu)
    if proto == "l2tp":
        return TunnelDriver.setup_l2tp(dev, local_route, peer_pub, SUBNET_REMOTE, SUBNET_LOCAL, mtu,
                                       configured_ports.get("l2tp", 5000), is_server=True)
    return False


def run_server_mode(port: int = SYNC_PORT, bind_ip: str = "0.0.0.0", preset_ip=None):
    check_root()
    install_deps()
    optimize_sysctl()
    pub_ip = get_public_ip()

    local_ips = get_all_local_ips()
    default_ip = get_route_ip("8.8.8.8")
    if (not default_ip or default_ip in ["0.0.0.0", "127.0.0.1"]) and pub_ip not in ["0.0.0.0", "127.0.0.1"]:
        default_ip = pub_ip

    selected_ip = _select_server_ip(preset_ip, local_ips, default_ip, pub_ip)
    bind_ip = selected_ip or "0.0.0.0"
    listen_ip = bind_ip if bind_ip != "0.0.0.0" else "0.0.0.0"

    print(f"\nServer mode started. Listening on {listen_ip}:{port} (Active IP: {bind_ip})...")
    open_firewall({"sync": port, "stream": STREAM_PORT})

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((listen_ip, port))
    except Exception as e:
        print(f"Warning: Could not bind to {listen_ip}:{port} ({e}), using 0.0.0.0")
        server_sock.bind(("0.0.0.0", port))
    server_sock.listen(5)

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
                _serve_one(conn, addr, bind_ip, pub_ip)
            except KeyboardInterrupt:
                raise
            except Exception:
                auto_cleanup()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server_sock.close()
        auto_cleanup(verbose=True)


def _serve_one(conn, addr, bind_ip, pub_ip):
    peer_addr = addr[0]
    sock_local_ip = conn.getsockname()[0]

    msg = recv_msg(conn, timeout=15.0)
    if not msg or msg.get("action") != "HELLO":
        conn.close()
        return

    peer_pub = msg.get("public_ip") or peer_addr
    if peer_pub in ["0.0.0.0", "127.0.0.1"]:
        peer_pub = peer_addr

    target_server_ip = msg.get("target_server_ip")
    if bind_ip and bind_ip not in ["0.0.0.0", "127.0.0.1"]:
        server_ip = bind_ip
    elif target_server_ip and target_server_ip not in ["0.0.0.0", "127.0.0.1"]:
        server_ip = target_server_ip
    elif sock_local_ip not in ["0.0.0.0", "127.0.0.1"]:
        server_ip = sock_local_ip
    else:
        server_ip = pub_ip

    print(f"\nConnection from {peer_addr} (Client IP: {peer_pub}) on local server IP {server_ip}")

    configured_ports = msg.get("ports", {"wireguard": 51820, "vxlan": 4789, "geneve": 6081,
                                         "l2tp": 5000, "stream": STREAM_PORT})
    local_route = server_ip
    gw, phys_dev = get_default_gw()
    if gw and phys_dev and local_route and local_route not in ["0.0.0.0", "127.0.0.1"]:
        from ..core.system import run_cmd
        run_cmd(f"ip route replace {peer_pub} via {gw} dev {phys_dev} src {local_route} 2>/dev/null")

    base_mtu = get_base_mtu(peer_pub)
    wg_priv, wg_pub = gen_wg_keys()
    open_firewall(configured_ports)

    send_msg(conn, {
        "status": "READY",
        "server_pub_ip": server_ip if server_ip not in ["0.0.0.0", "127.0.0.1"] else pub_ip,
        "peer_detected_ip": peer_addr,
        "server_routing_ip": local_route,
        "base_mtu": base_mtu,
        "wg_pub_key": wg_pub,
        "has_iperf3": bool(shutil.which("iperf3")),
    })

    dev = "tun_bench"
    peer_wg_pub = msg.get("wg_pub_key", "")
    active_rx = None
    holder = {}

    def _teardown_local():
        proc = holder.pop("proc", None)
        if proc is not None:
            holy_runtime.stop_transient(proc, dev)
        else:
            TunnelDriver.cleanup_interface(dev)

    try:
        while True:
            cmd = recv_msg(conn, timeout=600.0)
            if not cmd:
                break
            act = cmd.get("action")

            if act == "SETUP_TUNNEL":
                mtu = cmd.get("mtu", get_safe_mtu(base_mtu))
                _teardown_local()  # drop any previous protocol's state first
                ok = _build_tunnel(cmd.get("proto"), dev, peer_pub, local_route, mtu,
                                   configured_ports, wg_priv, peer_wg_pub, cmd, holder=holder)
                send_msg(conn, {"status": "OK" if ok else "FAIL"})

            elif act == "START_BANDWIDTH_TEST":
                dur = cmd.get("duration", TEST_DURATION)
                s_port = configured_ports.get("stream", STREAM_PORT)
                use_iperf = cmd.get("use_iperf3", False) and bool(shutil.which("iperf3"))
                if use_iperf:
                    BenchmarkEngine.start_iperf_server(s_port)
                    send_msg(conn, {"status": "IPERF3_READY"})
                else:
                    if active_rx:
                        active_rx.stop()
                    active_rx = TcpReceiverThread(s_port, dur + 2)
                    active_rx.start()
                    active_rx.ready_event.wait(timeout=1.0)
                    send_msg(conn, {"status": "TCP_READY"})

            elif act == "STOP_BANDWIDTH_TEST":
                from ..core.system import run_cmd
                run_cmd("pkill -9 iperf3 2>/dev/null")
                rx_b = 0
                if active_rx:
                    rx_b = active_rx.stop()
                    active_rx = None
                send_msg(conn, {"status": "OK", "bytes_rx": rx_b})

            elif act == "TEARDOWN_TUNNEL":
                if active_rx:
                    active_rx.stop()
                    active_rx = None
                from ..core.system import run_cmd
                run_cmd("pkill -9 iperf3 2>/dev/null")
                _teardown_local()
                send_msg(conn, {"status": "OK"})

            elif act == "FINISH_SESSION":
                _teardown_local()
                auto_cleanup()
                send_msg(conn, {"status": "BYE"})
                break
    finally:
        _teardown_local()
        conn.close()
        auto_cleanup()
