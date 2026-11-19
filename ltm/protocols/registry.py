"""Catalogue of the classic tunnel protocols the benchmark iterates over."""

PROTOCOLS = [
    {"id": "ipip", "name": "IPIP", "layer": "L3", "port": None},
    {"id": "gre", "name": "GRE", "layer": "L3", "port": None},
    {"id": "gretap", "name": "GRETAP", "layer": "L2", "port": None},
    {"id": "eoip", "name": "EoIP", "layer": "L2", "port": None},
    {"id": "vxlan", "name": "VXLAN", "layer": "L2", "port": 4789},
    {"id": "geneve", "name": "GENEVE", "layer": "L2", "port": 6081},
    {"id": "sit", "name": "SIT-6in4", "layer": "L3", "port": None},
    {"id": "l2tp", "name": "L2TPv3", "layer": "L2", "port": 5000},
    {"id": "wireguard", "name": "WireGuard", "layer": "L3", "port": 51820},
]
