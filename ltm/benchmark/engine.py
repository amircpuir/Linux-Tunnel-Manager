"""Throughput / latency measurement (iperf3 with a pure-Python TCP fallback)."""

import os
import sys
import time
import json
import socket
import signal
import threading
import subprocess
from typing import Any, Dict, Optional

from ..config import STREAM_PORT, TEST_DURATION
from ..core.system import run_cmd


class TcpReceiverThread(threading.Thread):
    def __init__(self, port: int, duration_sec: int):
        super().__init__()
        self.daemon = True
        self.port = port
        self.duration_sec = duration_sec
        self.total_bytes = 0
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(16)
            server.settimeout(0.5)
            self.ready_event.set()
        except Exception:
            self.ready_event.set()
            return

        threads = []

        def worker(conn):
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(1.0)
            chunk = 64 * 1024
            try:
                while not self.stop_event.is_set():
                    data = conn.recv(chunk)
                    if not data:
                        break
                    self.total_bytes += len(data)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        end = time.time() + self.duration_sec + 2.0
        while time.time() < end and not self.stop_event.is_set():
            try:
                c, _ = server.accept()
                t = threading.Thread(target=worker, args=(c,), daemon=True)
                t.start()
                threads.append(t)
            except socket.timeout:
                continue
            except Exception:
                break

        try:
            server.close()
        except Exception:
            pass
        for t in threads:
            t.join(timeout=0.2)

    def stop(self) -> int:
        self.stop_event.set()
        self.join(timeout=1.0)
        return self.total_bytes


class BenchmarkEngine:
    @staticmethod
    def ping(my_ip: str, target_ip: str, count: int = 5) -> Dict[str, Any]:
        ok, out = run_cmd(f"ping -I {my_ip} -c {count} -W 1 -i 0.2 {target_ip}")
        if not ok or not out:
            ok, out = run_cmd(f"ping -c {count} -W 1 -i 0.2 {target_ip}")
        if not ok:
            return {"success": False, "loss_pct": 100.0, "avg_ms": 999.0}

        loss, avg_rtt = 100.0, 999.0
        for line in out.splitlines():
            if "packet loss" in line:
                try:
                    for p in line.split(","):
                        if "packet loss" in p:
                            loss = float(p.strip().split("%")[0].split()[-1])
                except Exception:
                    pass
            if line.startswith("rtt ") or line.startswith("round-trip "):
                try:
                    avg_rtt = float(line.split("=")[1].strip().split("/")[1])
                except Exception:
                    pass
        return {"success": loss < 100.0, "loss_pct": loss, "avg_ms": avg_rtt}

    @staticmethod
    def start_iperf_server(port: int = STREAM_PORT) -> Optional[subprocess.Popen]:
        run_cmd("pkill -9 iperf3 2>/dev/null")
        try:
            proc = subprocess.Popen(
                ["iperf3", "-s", "-p", str(port), "-1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            time.sleep(0.3)
            return proc
        except Exception:
            return None

    @staticmethod
    def run_iperf_client(target_ip: str, port: int, duration_sec: int, bind_ip: Optional[str] = None) -> Optional[float]:
        run_cmd("pkill -9 -f 'iperf3.*-c' 2>/dev/null")
        cmd = ["iperf3", "-c", target_ip, "-p", str(port), "-t", str(duration_sec), "-P", "2", "-J"]
        if bind_ip and bind_ip not in ["0.0.0.0", "127.0.0.1"]:
            cmd.extend(["-B", bind_ip])

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, preexec_fn=os.setsid)
        except Exception:
            return None

        start = time.time()
        max_duration = duration_sec + 2
        while proc.poll() is None:
            elapsed = int(time.time() - start)
            if elapsed >= max_duration:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
                break
            pct = min(100, int((elapsed / duration_sec) * 100))
            sys.stdout.write(f"\rTesting bandwidth... {pct}% ({min(elapsed, duration_sec)}s/{duration_sec}s)")
            sys.stdout.flush()
            time.sleep(0.25)

        try:
            stdout, _ = proc.communicate(timeout=1.0)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            stdout = ""

        sys.stdout.write("\r" + " " * 45 + "\r")
        sys.stdout.flush()

        if stdout:
            try:
                data = json.loads(stdout)
                bps = data.get("end", {}).get("sum_sent", {}).get("bits_per_second")
                if not bps:
                    bps = data.get("end", {}).get("sum_received", {}).get("bits_per_second")
                if bps and float(bps) > 0:
                    return float(bps)
            except Exception:
                pass
        return None

    @staticmethod
    def run_tcp_sender(target_ip: str, port: int, duration_sec: int, streams: int = 2) -> float:
        payload = b"X" * (64 * 1024)
        stop_event = threading.Event()
        total = [0]

        def worker():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(2.0)
            try:
                s.connect((target_ip, port))
                s.settimeout(0.5)
                while not stop_event.is_set():
                    s.sendall(payload)
                    total[0] += len(payload)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        threads = []
        for _ in range(streams):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        start = time.time()
        try:
            while time.time() - start < duration_sec:
                time.sleep(0.25)
                elapsed = int(time.time() - start)
                pct = min(100, int((elapsed / duration_sec) * 100))
                sys.stdout.write(f"\rTesting bandwidth... {pct}% ({min(elapsed, duration_sec)}s/{duration_sec}s)")
                sys.stdout.flush()
        finally:
            stop_event.set()
            for t in threads:
                t.join(timeout=0.5)
            sys.stdout.write("\r" + " " * 45 + "\r")
            sys.stdout.flush()

        elapsed_total = max(0.1, time.time() - start)
        return (total[0] * 8) / elapsed_total
