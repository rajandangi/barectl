import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import TypedDict

from .observation import SecurityState

MAX_PORTS = 12
TIMEOUT = 1.5


class PortResult(TypedDict):
    port: int
    result: str
    unexpected: bool


class Reachability(TypedDict):
    address: str
    ports: list[PortResult]
    note: str


def check(peer: tuple[str, int] | None, state: SecurityState | None) -> Reachability:
    unavailable: Reachability = {
        "address": "",
        "ports": [],
        "note": "Use a saved public IPv4 or IPv6 address to check TCP reachability.",
    }
    if peer is None:
        return unavailable
    address, ssh_port = peer
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return unavailable
    if (
        not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or "%" in address
        or not 1 <= ssh_port <= 65535
    ):
        return {"address": "", "ports": [], "note": "The verified SSH endpoint is not a public IP."}

    standard = {ssh_port, 80, 443}
    listeners = state.listeners if state is not None else None
    observed = {
        listener.port
        for listener in (listeners.value or () if listeners and listeners.observed else ())
        if listener.public and listener.protocol == "tcp" and 1 <= listener.port <= 65535
    }
    candidates = sorted(standard) + sorted(observed - standard)
    note = ""
    if listeners is None or not listeners.observed:
        note = "Host listeners could not be read. Only SSH, HTTP and HTTPS were checked."
    elif len(candidates) > MAX_PORTS:
        note = "The check reached its port limit. Some observed listeners were omitted."
    ports = sorted(candidates[:MAX_PORTS])
    with ThreadPoolExecutor(max_workers=4) as pool:
        states = list(pool.map(lambda port: _connect(address, port), ports))
    results = [
        PortResult(port=port, result=result, unexpected=port not in standard and accepted)
        for port, (result, accepted) in zip(ports, states, strict=True)
    ]
    return {"address": address, "ports": results, "note": note}


def _connect(address: str, port: int) -> tuple[str, bool]:
    try:
        connection = socket.create_connection((address, port), timeout=TIMEOUT)
    except ConnectionRefusedError:
        return "Connection refused", False
    except OSError:
        return "Could not connect", False
    connection.close()
    return "Connection accepted", True
