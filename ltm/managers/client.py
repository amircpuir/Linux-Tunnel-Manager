"""Client (benchmark) role: iterates every protocol and reports a ranking."""

import os
import sys
import time
import json
import shutil
import socket
from typing import Any, Dict, List, Optional

from ..config import SYNC_PORT, STREAM_PORT, TEST_DURATION, SUBNET_LOCAL, SUBNET_REMOTE
from ..core.system import check_root, install_deps, optimize_sysctl, run_cmd
from ..core.netinfo import get_route_ip, get_all_local_ips, get_default_gw, get_base_mtu, get_safe_mtu, format_speed
from ..core.firewall import open_firewall
from ..core.wire import send_msg, recv_msg
from ..protocols.registry import PROTOCOLS
from ..protocols.drivers import TunnelDriver, gen_wg_keys
from ..protocols.cleanup import auto_cleanup
from ..benchmark.engine import BenchmarkEngine


def _pick_local_bind(local_ips, default_ip, remote_ip):
    local_bind = default_ip
    if len(local_ips) > 1:
        print("\n==========================================")
        print(" Detected Local IPs on this server:")
        print("==========================================")
        for idx, lip in enumerate(local_ips, 1):
            tag = " (Default route)" if lip == default_ip else ""
            print(f"  {idx}) {lip}{tag}")
        sel = input(f"\nSelect Local IP to test with [1-{len(local_ips)}, Default: {default_ip}]: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(local_ips):
            local_bind = local_ips[int(sel) - 1]
        elif sel.strip():
            local_bind = sel.strip()
    elif len(local_ips) == 1:
        print(f"\nDetected Local IP on this server: {default_ip}")
        sel = input(f"Select Local IP to test with [Default: {default_ip}]: ").strip()
        if sel.strip():
            local_bind = sel.strip()
    return local_bind


def _setup_local(proto_id, dev, local_bind, remote_ip, mtu, ports, wg_priv, remote_wg_pub):
    if proto_id == "wireguard":
        return TunnelDriver.setup_wireguard(dev, wg_priv, remote_wg_pub, remote_ip, ports["wireguard"],
                                            SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "gre":
        return TunnelDriver.setup_gre(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "gretap":
        return TunnelDriver.setup_gretap(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "ipip":
        return TunnelDriver.setup_ipip(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "eoip":
        return TunnelDriver.setup_eoip(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "vxlan":
        return TunnelDriver.setup_vxlan(dev, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu,
                                        ports["vxlan"], is_server=False, local_bind=local_bind)
    if proto_id == "geneve":
        return TunnelDriver.setup_geneve(dev, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu,
                                         ports["geneve"], is_server=False, local_bind=local_bind)
    if proto_id == "sit":
        return TunnelDriver.setup_sit(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu)
    if proto_id == "l2tp":
        return TunnelDriver.setup_l2tp(dev, local_bind, remote_ip, SUBNET_LOCAL, SUBNET_REMOTE, mtu, ports["l2tp"])
    return False


def run_client_mode(remote_ip: Optional[str] = None, sync_port: int = SYNC_PORT, local_ip_choice: Optional[str] = None):
    check_root()
    install_deps()
    optimize_sysctl()

    if not remote_ip:
        remote_ip = input("Enter Remote Server IP: ").strip()
    if not remote_ip:
        print("Error: Remote IP required.")
        return

    local_ips = get_all_local_ips()
    default_ip = get_route_ip(remote_ip)
    local_bind = local_ip_choice or _pick_local_bind(local_ips, default_ip, remote_ip)

    gw, phys_dev = get_default_gw()
    if gw and phys_dev and local_bind and local_bind not in ["0.0.0.0", "127.0.0.1"]:
        run_cmd(f"ip route replace {remote_ip} via {gw} dev {phys_dev} src {local_bind} 2>/dev/null")

    print(f"\nConnecting from {local_bind} to {remote_ip}:{sync_port}...")
    local_mtu = get_base_mtu(remote_ip)

    ports = {"sync": sync_port, "wireguard": 51820, "vxlan": 4789,
             "geneve": 6081, "l2tp": 5000, "stream": STREAM_PORT}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if local_bind and local_bind not in ["0.0.0.0", "127.0.0.1"]:
        try:
            sock.bind((local_bind, 0))
        except Exception:
            pass
    sock.settimeout(10.0)
    try:
        sock.connect((remote_ip, sync_port))
    except Exception as e:
        print(f"Error: Unable to connect to {remote_ip}:{sync_port} ({e})")
        return

    wg_priv, wg_pub = gen_wg_keys()
    send_msg(sock, {
        "action": "HELLO",
        "public_ip": local_bind if local_bind not in ["0.0.0.0", "127.0.0.1"] else "",
        "routing_ip": local_bind,
        "target_server_ip": remote_ip,
        "base_mtu": local_mtu,
        "wg_pub_key": wg_pub,
        "ports": ports,
    })

    resp = recv_msg(sock, timeout=12.0)
    if not resp or resp.get("status") != "READY":
        print("Handshake failed with remote server.")
        sock.close()
        return

    remote_mtu = resp.get("base_mtu", 1450)
    remote_wg_pub = resp.get("wg_pub_key", "")
    use_iperf = resp.get("has_iperf3", False) and bool(shutil.which("iperf3"))
    safe_mtu = get_safe_mtu(min(local_mtu, remote_mtu))
    open_firewall(ports)

    results: List[Dict[str, Any]] = []
    dev = "tun_bench"
    stream_port = ports["stream"]

    print(f"\nRunning {TEST_DURATION}s benchmark per protocol "
          f"(Local IP: {local_bind}, Remote IP: {remote_ip}, MTU: {safe_mtu})...\n")

    try:
        for p in PROTOCOLS:
            proto_id, proto_name = p["id"], p["name"]
            sys.stdout.write(f"Testing {proto_name:<12} ")
            sys.stdout.flush()

            send_msg(sock, {"action": "SETUP_TUNNEL", "proto": proto_id, "mtu": safe_mtu, "peer_wg_pub": wg_pub})
            rem_res = recv_msg(sock, timeout=20.0)
            if not rem_res or rem_res.get("status") != "OK":
                print("[FAIL - Remote]")
                continue

            if not _setup_local(proto_id, dev, local_bind, remote_ip, safe_mtu, ports, wg_priv, remote_wg_pub):
                print("[FAIL - Local]")
                TunnelDriver.cleanup_interface(dev)
                send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
                recv_msg(sock, timeout=5.0)
                continue

            time.sleep(0.8)
            ping_res = BenchmarkEngine.ping(SUBNET_LOCAL, SUBNET_REMOTE, count=6)
            if not ping_res["success"]:
                print("[FAIL - Ping Timeout]")
                TunnelDriver.cleanup_interface(dev)
                send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
                recv_msg(sock, timeout=5.0)
                results.append({"id": proto_id, "name": proto_name, "bandwidth": 0,
                                "bandwidth_str": "0 Mbps", "latency": 999.0, "loss": 100.0,
                                "status": "FAIL", "score": 0})
                continue

            send_msg(sock, {"action": "START_BANDWIDTH_TEST", "duration": TEST_DURATION, "use_iperf3": use_iperf})
            bw_ready = recv_msg(sock, timeout=5.0)
            server_bw_mode = bw_ready.get("status") if bw_ready else ""

            if server_bw_mode == "IPERF3_READY":
                ibps = BenchmarkEngine.run_iperf_client(SUBNET_REMOTE, stream_port, TEST_DURATION)
                measured_bps = ibps if ibps and ibps > 0 else BenchmarkEngine.run_tcp_sender(SUBNET_REMOTE, stream_port, TEST_DURATION)
            else:
                measured_bps = BenchmarkEngine.run_tcp_sender(SUBNET_REMOTE, stream_port, TEST_DURATION)

            send_msg(sock, {"action": "STOP_BANDWIDTH_TEST"})
            recv_msg(sock, timeout=3.0)
            TunnelDriver.cleanup_interface(dev)
            send_msg(sock, {"action": "TEARDOWN_TUNNEL"})
            recv_msg(sock, timeout=5.0)

            mbps = measured_bps / 1_000_000
            lat = max(1.0, ping_res["avg_ms"])
            loss = ping_res["loss_pct"]
            score = (mbps * 100.0) / (lat * (1.0 + (loss / 20.0)))

            results.append({"id": proto_id, "name": proto_name, "bandwidth": measured_bps,
                            "bandwidth_str": format_speed(measured_bps), "latency": ping_res["avg_ms"],
                            "loss": loss, "status": "PASS", "score": round(score, 1)})
            print(f"[PASS] {format_speed(measured_bps):<12} Ping: {ping_res['avg_ms']:.1f}ms  Loss: {loss:.1f}%")
    finally:
        try:
            send_msg(sock, {"action": "FINISH_SESSION"})
            sock.close()
        except Exception:
            pass
        auto_cleanup(verbose=True)

    show_results(results, remote_ip)


def show_results(results: List[Dict[str, Any]], remote_ip: str):
    sorted_res = sorted(results, key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 70)
    print(f"BENCHMARK RESULTS (Target: {remote_ip}, Duration: {TEST_DURATION}s)")
    print("=" * 70)
    print(f"{'RANK':<5} | {'PROTOCOL':<16} | {'THROUGHPUT':<14} | {'PING':<9} | {'LOSS':<7} | {'STATUS'}")
    print("-" * 70)
    for i, r in enumerate(sorted_res, 1):
        lat_str = f"{r['latency']:.1f} ms" if r["latency"] < 900 else "TIMEOUT"
        print(f"{'#' + str(i):<5} | {r['name']:<16} | {r['bandwidth_str']:<14} | {lat_str:<9} | {r['loss']:>5.1f}% | {r['status']}")
    print("-" * 70)

    passing = [r for r in sorted_res if r["status"] == "PASS"]
    if passing:
        w = passing[0]
        print(f"\nWinner: {w['name']} ({w['bandwidth_str']}, {w['latency']:.1f} ms)")
        print(f"Deploy command: sudo python3 tunnel.py --create {w['id']} --remote {remote_ip}\n")

    log_path = "/root/benchmark_results.json" if os.path.exists("/root") else "benchmark_results.json"
    try:
        with open(log_path, "w") as f:
            json.dump({"target": remote_ip, "duration": TEST_DURATION, "results": sorted_res}, f, indent=2)
        print(f"Results saved to: {os.path.abspath(log_path)}")
    except Exception:
        pass
