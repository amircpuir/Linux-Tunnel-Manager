"""NAT-based port forwarding (iptables DNAT/MASQUERADE) with persistence."""

import os
import json
import time
from typing import Any, Dict, List

from ..config import PORT_FWD_FILE, ensure_state_dir
from ..core.system import run_cmd


def load_port_fwd_rules() -> List[Dict[str, Any]]:
    if os.path.exists(PORT_FWD_FILE):
        try:
            with open(PORT_FWD_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_port_fwd_rules(rules: List[Dict[str, Any]]):
    ensure_state_dir()
    try:
        with open(PORT_FWD_FILE, "w") as f:
            json.dump(rules, f, indent=2)
    except Exception:
        pass


def apply_port_fwd_rule(proto: str, listen_port: str, dest_ip: str, dest_port: str):
    run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
    protos = ["tcp", "udp"] if proto.lower() in ["both", "tcp+udp", "all"] else [proto.lower()]
    to_dest = f"{dest_ip}:{dest_port}"
    for pr in protos:
        run_cmd(f"iptables -t nat -I PREROUTING 1 -p {pr} --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")
        run_cmd(f"iptables -t nat -I POSTROUTING 1 -p {pr} -d {dest_ip} --dport {dest_port} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -I FORWARD 1 -p {pr} -d {dest_ip} --dport {dest_port} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -t nat -I OUTPUT 1 -p {pr} -d 127.0.0.1 --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")
    run_cmd("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
    run_cmd("iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")


def remove_port_fwd_rule(proto: str, listen_port: str, dest_ip: str, dest_port: str):
    protos = ["tcp", "udp"] if proto.lower() in ["both", "tcp+udp", "all"] else [proto.lower()]
    to_dest = f"{dest_ip}:{dest_port}"
    for pr in protos:
        run_cmd(f"iptables -t nat -D PREROUTING -p {pr} --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")
        run_cmd(f"iptables -t nat -D POSTROUTING -p {pr} -d {dest_ip} --dport {dest_port} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -p {pr} -d {dest_ip} --dport {dest_port} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -t nat -D OUTPUT -p {pr} -d 127.0.0.1 --dport {listen_port} -j DNAT --to-destination {to_dest} 2>/dev/null")


def _add_rule_flow():
    print("\nEnter Listen Port (e.g. 443, or 80,443, or 10000:20000):")
    lp = input("Listen Port: ").strip()
    if not lp:
        return
    dip = input("Destination IP (e.g. 10.0.0.2): ").strip()
    if not dip:
        return
    dp = input(f"Destination Port [{lp}]: ").strip() or lp
    pr = input("Protocol (tcp / udp / both) [both]: ").strip().lower() or "both"
    if pr not in ["tcp", "udp", "both"]:
        pr = "both"

    ports = [p.strip() for p in lp.split(",")] if "," in lp else [lp]
    dports = [p.strip() for p in dp.split(",")] if "," in dp else [dp]

    rules = load_port_fwd_rules()
    for idx, p in enumerate(ports):
        dest_p = dports[idx] if idx < len(dports) else dports[0]
        apply_port_fwd_rule(pr, p, dip, dest_p)
        rules.append({"id": len(rules) + 1, "proto": pr, "listen_port": p, "dest_ip": dip,
                      "dest_port": dest_p, "created_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    save_port_fwd_rules(rules)
    print(f"\n[OK] Port forwarding applied: {lp} ({pr}) -> {dip}:{dp}")
    print("[INFO] MASQUERADE & TCPMSS clamping enabled.")
    time.sleep(1)


def port_fwd_menu():
    run_cmd("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
    while True:
        print("\n--- Port Forwarding (NAT Relay) ---")
        print("1) Add Forward Rule (Single / Multi / Range)")
        print("2) List Active Forward Rules")
        print("3) Delete Forward Rule")
        print("4) Flush All Forward Rules")
        print("0) Back")
        c = input("Select [0-4]: ").strip()
        if c == "0":
            break
        if c == "1":
            _add_rule_flow()
        elif c == "2":
            rules = load_port_fwd_rules()
            print("\n" + "=" * 65)
            print(f"{'ID':<4} | {'PROTO':<8} | {'LISTEN PORT':<14} | {'FORWARD TO':<25}")
            print("-" * 65)
            if rules:
                for r in rules:
                    print(f"#{r['id']:<3} | {r['proto']:<8} | {r['listen_port']:<14} | {r['dest_ip']}:{r['dest_port']}")
            else:
                print("No stored forwarding rules.")
            print("=" * 65)
            _, out = run_cmd("iptables -t nat -L PREROUTING -n -v --line-numbers")
            print("\n--- Active PREROUTING iptables rules ---")
            print(out or "None")
            input("\nPress Enter to return...")
        elif c == "3":
            rules = load_port_fwd_rules()
            if not rules:
                print("No active rules to delete.")
                time.sleep(1)
                continue
            for r in rules:
                print(f"  {r['id']}) {r['proto'].upper()} {r['listen_port']} -> {r['dest_ip']}:{r['dest_port']}")
            sel = input("Rule ID: ").strip()
            if sel.isdigit():
                rid = int(sel)
                target = next((r for r in rules if r["id"] == rid), None)
                if target:
                    remove_port_fwd_rule(target["proto"], target["listen_port"], target["dest_ip"], target["dest_port"])
                    rules = [r for r in rules if r["id"] != rid]
                    for i, r in enumerate(rules, 1):
                        r["id"] = i
                    save_port_fwd_rules(rules)
                    print(f"[OK] Rule #{rid} removed.")
                else:
                    print("Rule not found.")
            time.sleep(1)
        elif c == "4":
            if input("Remove ALL port forward rules? [y/N]: ").strip().lower() == "y":
                for r in load_port_fwd_rules():
                    remove_port_fwd_rule(r["proto"], r["listen_port"], r["dest_ip"], r["dest_port"])
                save_port_fwd_rules([])
                run_cmd("iptables -t nat -F PREROUTING 2>/dev/null")
                run_cmd("iptables -t nat -F OUTPUT 2>/dev/null")
                print("[OK] All port forwarding rules flushed.")
                time.sleep(1)
