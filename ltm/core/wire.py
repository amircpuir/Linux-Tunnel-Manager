"""Length-prefixed JSON messaging used by the client/server sync channel."""

import json
import socket
import struct
from typing import Optional


def send_msg(sock: socket.socket, data: dict):
    payload = json.dumps(data).encode("utf-8")
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_msg(sock: socket.socket, timeout: Optional[float] = None) -> Optional[dict]:
    if timeout:
        sock.settimeout(timeout)
    try:
        header = sock.recv(4)
        if not header or len(header) < 4:
            return None
        length = struct.unpack("!I", header)[0]
        data = bytearray()
        while len(data) < length:
            packet = sock.recv(min(4096, length - len(data)))
            if not packet:
                return None
            data.extend(packet)
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None
