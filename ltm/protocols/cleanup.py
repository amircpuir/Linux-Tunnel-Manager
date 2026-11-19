"""Best-effort teardown of benchmark interfaces and leftover state."""

from ..core.system import run_cmd
from .drivers import TunnelDriver

BENCH_DEVS = [
    "tun_bench", "gre_bench", "gt_bench", "ipip_bench", "vx_bench",
    "eoip_bench", "wg_bench", "gen_bench", "sit_bench", "l2tp_bench",
]


def auto_cleanup(verbose: bool = False):
    if verbose:
        print("Cleaning up network interfaces...")

    ok, out = run_cmd("ip -o -4 addr show")
    if ok and out:
        for line in out.splitlines():
            if "10.99.1." in line:
                parts = line.split()
                if len(parts) >= 2:
                    TunnelDriver.cleanup_interface(parts[1].split(":")[0])

    for d in BENCH_DEVS:
        TunnelDriver.cleanup_interface(d)

    ok_l, out_l = run_cmd("ip -o link show")
    if ok_l and out_l:
        for line in out_l.splitlines():
            for p in BENCH_DEVS:
                if f": {p}" in line:
                    TunnelDriver.cleanup_interface(p)

    run_cmd("ip route del 10.99.1.0/30 2>/dev/null")
    run_cmd("pkill -9 iperf3 2>/dev/null")

    if verbose:
        print("Cleanup completed.")
