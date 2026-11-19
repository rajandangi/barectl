import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import TypedDict

from .observation import SecurityState

MAX_EXTRA_PORTS = 9
TIMEOUT = 1.5

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class PortResult(TypedDict):
    port: int
    result: str
    unexpected: bool


class Reachability(TypedDict):
    address: str
    ports: list[PortResult]
    note: str


def check(peer: tuple[str, int] | None, state: SecurityState | None) -> Reachability:
    if peer is None:
        return _skipped("The saved SSH connection uses an SSH alias.")
    address, ssh_port = peer
    if "%" in address:
        return _skipped("The verified address has an IPv6 scope.")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return _skipped("The saved SSH connection uses a hostname.")
    if not _public_unicast(ip):
        return _skipped("The verified SSH address is outside public unicast address space.")
    if not 1 <= ssh_port <= 65535:
        return _skipped("The saved SSH port is outside the valid range.")

    standard = {ssh_port, 80, 443}
    extra, note = _extra_ports(standard, state)
    ports = sorted(standard.union(extra))
    with ThreadPoolExecutor(max_workers=4) as pool:
        states = list(pool.map(lambda port: _connect(ip, port), ports))
    results = [
        PortResult(port=port, result=result, unexpected=port not in standard and accepted)
        for port, (result, accepted) in zip(ports, states, strict=True)
    ]
    return {"address": address, "ports": results, "note": note}


def _skipped(reason: str) -> Reachability:
    return {"address": "", "ports": [], "note": f"TCP check skipped. {reason}"}


def _public_unicast(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.is_site_local:
            return False
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def _extra_ports(standard: set[int], state: SecurityState | None) -> tuple[list[int], str]:
    if state is None or not state.listeners.observed:
        return [], "Host listeners could not be read. Only SSH, HTTP and HTTPS were checked."
    observed = {
        listener.port
        for listener in state.listeners.value or ()
        if listener.protocol == "tcp"
        and 1 <= listener.port <= 65535
        and listener.public
        and not _loopback(listener.address)
    }
    extra = sorted(observed - standard)
    omitted = len(extra) - MAX_EXTRA_PORTS
    note = (
        f"The check reached its port limit. It omitted {omitted} observed TCP ports."
        if omitted > 0
        else ""
    )
    return extra[:MAX_EXTRA_PORTS], note


def _loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _connect(ip: IPAddress, port: int) -> tuple[str, bool]:
    try:
        _attempt(ip, port)
    except ConnectionRefusedError:
        return "Connection refused", False
    except OSError:
        return "Inconclusive", False
    return "Connection accepted", True


def _attempt(ip: IPAddress, port: int) -> None:
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    endpoint = (str(ip), port) if ip.version == 4 else (str(ip), port, 0, 0)
    with closing(socket.socket(family, socket.SOCK_STREAM)) as connection:
        connection.settimeout(TIMEOUT)
        connection.connect(endpoint)
