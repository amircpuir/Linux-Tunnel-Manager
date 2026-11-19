"""iptables helpers for opening the ports/protocols tunnels need."""

from typing import Dict, Optional

from .system import run_cmd


def open_firewall(ports: Dict[str, Optional[int]]):
    # Accept the IP-protocol numbers used by the L3/L2 tunnels.
    run_cmd("iptables -I INPUT 1 -p 47 -j ACCEPT 2>/dev/null")   # GRE
    run_cmd("iptables -I INPUT 1 -p 4 -j ACCEPT 2>/dev/null")    # IPIP
    run_cmd("iptables -I INPUT 1 -p 41 -j ACCEPT 2>/dev/null")   # SIT/6in4
    run_cmd("iptables -I INPUT 1 -p 50 -j ACCEPT 2>/dev/null")   # ESP
    run_cmd("iptables -I INPUT 1 -s 10.99.1.0/30 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I FORWARD 1 -s 10.99.1.0/30 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I FORWARD 1 -d 10.99.1.0/30 -j ACCEPT 2>/dev/null")

    for _, p_val in ports.items():
        if p_val:
            run_cmd(f"iptables -I INPUT 1 -p udp --dport {p_val} -j ACCEPT 2>/dev/null")
            run_cmd(f"iptables -I INPUT 1 -p tcp --dport {p_val} -j ACCEPT 2>/dev/null")
