"""Transient Holy endpoints used during a benchmark run.

These are short-lived processes bound to the benchmark interface (`tun_bench`)
and the 10.99.1.x addressing. They are started, measured and killed within a
single protocol iteration and never touch an installed Holy service.
"""

import os
import json
import signal
import tempfile
import subprocess
from typing import Optional

from ..config import HOLY_BIN
from ..protocols.drivers import TunnelDriver
from . import holy as holy_mgr


def ensure_core() -> bool:
    """Make sure the native binary exists (build it on demand)."""
    return holy_mgr.build_core()


def start_transient(role: str, dev: str, local_bind: str, remote_ip: str,
                    port: int, key: str, my_inner: str, peer_inner: str,
                    mtu: int) -> Optional[subprocess.Popen]:
    if not os.path.exists(HOLY_BIN):
        return None

    cfg = {
        "role": role,
        "secret": key,
        "tun_name": dev,
        "tun_ip": my_inner,
        "peer_ip": peer_inner,
        "prefix": 30,
        "mtu": int(mtu),
        "keepalive": 3,
    }
    if local_bind and local_bind not in ("0.0.0.0", "127.0.0.1"):
        cfg["local"] = local_bind

    if role == "server":
        bind_ip = local_bind if local_bind and local_bind not in ("0.0.0.0", "127.0.0.1") else "0.0.0.0"
        cfg["listen"] = f"{bind_ip}:{port}"
    else:
        cfg["remote"] = f"{remote_ip}:{port}"

    fd, path = tempfile.mkstemp(prefix="holy_bench_", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)

    try:
        proc = subprocess.Popen(
            [HOLY_BIN, "--config", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        return None

    proc._holy_cfg_path = path  # type: ignore[attr-defined]
    return proc


def stop_transient(proc: Optional[subprocess.Popen], dev: str):
    if proc is not None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        path = getattr(proc, "_holy_cfg_path", None)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
    TunnelDriver.cleanup_interface(dev)
