"""A fault-injecting front for Pebble's ACME API and challtestsrv's DNS.

docs/ssh-connections.md#acme-and-dns-fixtures

It runs as its own container on a disposable server's test network, started by
``docker/disposable-server/run-tests.sh`` with the disposable image's Python, so it uses the
standard library only and runs on Python 3.12. A test selects faults through the control API;
everything else is relayed unchanged.
"""

import argparse
import http.client
import json
import socket
import ssl
import sys
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import override

# Pebble 2.10.1's paths for the ACME resources a fault can target (wfe/wfe.go).
RESOURCES = {
    "newNonce": "/nonce-plz",
    "newAccount": "/sign-me-up",
    "newOrder": "/order-plz",
    "finalize": "/finalize-order/",
    "revokeCert": "/revoke-cert",
}
# Each problem type a fault can carry, with its default HTTP status.
PROBLEM_TYPES = {
    "badNonce": 400,
    "caa": 403,
    "rateLimited": 429,
    "serverInternal": 500,
    "unauthorized": 403,
}
HOP_BY_HOP = {"connection", "content-length", "keep-alive", "transfer-encoding"}
HEADER_LENGTH = 12
MAX_LABEL = 63
NXDOMAIN = 3


class FixtureError(ValueError):
    pass


@dataclass(frozen=True)
class Fault:
    resource: str
    type: str
    status: int
    detail: str
    retry_after: str
    count: int


def parse_fault(document: object) -> Fault:
    """Validate a control request's fault; ``count`` is how many matching requests fail."""
    if not isinstance(document, dict):
        raise FixtureError("a fault is a JSON object")
    resource = document.get("resource")
    problem = document.get("type")
    status = document.get("status", PROBLEM_TYPES.get(str(problem), 400))
    detail = document.get("detail", f"Injected {problem} fault")
    retry_after = document.get("retryAfter", "")
    count = document.get("count", 1)
    if not isinstance(resource, str) or resource not in RESOURCES:
        raise FixtureError(f"resource must be one of {sorted(RESOURCES)}")
    if not isinstance(problem, str) or problem not in PROBLEM_TYPES:
        raise FixtureError(f"type must be one of {sorted(PROBLEM_TYPES)}")
    if not isinstance(status, int) or not 400 <= status <= 599:
        raise FixtureError("status must be an HTTP error status")
    if not isinstance(detail, str) or not isinstance(retry_after, str):
        raise FixtureError("detail and retryAfter must be strings")
    if not isinstance(count, int) or count < 1:
        raise FixtureError("count must be a positive integer")
    return Fault(resource, problem, status, detail, retry_after, count)


def parse_host(document: object) -> str:
    """Validate a control request's name, returned fully qualified in lower case."""
    host = document.get("host") if isinstance(document, dict) else None
    if not isinstance(host, str) or not host.strip("."):
        raise FixtureError("host must be a DNS name")
    return host.lower().rstrip(".") + "."


def problem_document(fault: Fault) -> bytes:
    """RFC 8555 section 6.7's problem document for a fault."""
    return json.dumps(
        {
            "type": f"urn:ietf:params:acme:error:{fault.type}",
            "detail": fault.detail,
            "status": fault.status,
        }
    ).encode()


def question_name(packet: bytes) -> str:
    """The first question's name, lower-case and fully qualified, from a DNS query."""
    labels: list[str] = []
    offset = HEADER_LENGTH
    while True:
        if offset >= len(packet):
            raise FixtureError("truncated DNS question")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels).lower() + "."
        if length > MAX_LABEL or offset + length > len(packet):
            raise FixtureError("malformed DNS question")
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length


def with_rcode(reply: bytes, rcode: int) -> bytes:
    """The reply as an error response: the response code replaced and no answers.

    An error reply that still carries answer records is not one a resolver accepts:
    systemd-resolved read the records out of an NXDOMAIN-tagged reply, so the answer
    section must be dropped, not just relabelled.
    """
    if len(reply) < HEADER_LENGTH:
        raise FixtureError("truncated DNS reply")
    questions = int.from_bytes(reply[4:6], "big")
    answers = int.from_bytes(reply[6:8], "big")
    offset = HEADER_LENGTH
    for _ in range(questions):
        offset = record_end(reply, offset, question=True)
    end = offset
    for _ in range(answers):
        end = record_end(reply, end)
    return (
        reply[:3]
        + bytes([(reply[3] & 0xF0) | rcode])
        + reply[4:6]
        + b"\x00\x00"
        + reply[8:offset]
        + reply[end:]
    )


def record_end(packet: bytes, offset: int, *, question: bool = False) -> int:
    """The offset just past one record: its name, then its fixed fields and data."""
    offset = name_end(packet, offset)
    fixed = 4 if question else 10
    if offset + fixed > len(packet):
        raise FixtureError("truncated DNS record")
    if question:
        return offset + fixed
    length = int.from_bytes(packet[offset + 8 : offset + 10], "big")
    return offset + fixed + length


def name_end(packet: bytes, offset: int) -> int:
    """The offset just past a name: labels ending at the root label or a pointer."""
    while True:
        if offset >= len(packet):
            raise FixtureError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xC0 == 0xC0:
            return offset + 1
        offset += length


class State:
    """Faults and NXDOMAIN names selected by the tests, and the faults already served."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.faults: list[Fault] = []
        self.served: list[Fault] = []
        self.nxdomain: set[str] = set()

    def take(self, path: str) -> Fault | None:
        with self.lock:
            for index, fault in enumerate(self.faults):
                if path.startswith(RESOURCES[fault.resource]):
                    if fault.count == 1:
                        del self.faults[index]
                    else:
                        self.faults[index] = replace(fault, count=fault.count - 1)
                    self.served.append(fault)
                    return fault
        return None

    def describe(self) -> bytes:
        with self.lock:
            return json.dumps(
                {
                    "faults": [asdict(fault) for fault in self.faults],
                    "served": [asdict(fault) for fault in self.served],
                    "nxdomain": sorted(self.nxdomain),
                }
            ).encode()


class DualStackServer(ThreadingHTTPServer):
    address_family: int = socket.AF_INET6.value
    daemon_threads = True

    def __init__(self, port: int, handler: type[BaseHTTPRequestHandler], state: State) -> None:
        self.state = state
        super().__init__(("::", port), handler)

    @override
    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class Upstream:
    def __init__(self, host: str, port: int, cafile: str) -> None:
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(cafile=cafile)

    def request(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=30
        )
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()


class AcmeServer(DualStackServer):
    def __init__(
        self, port: int, state: State, upstream: Upstream, context: ssl.SSLContext
    ) -> None:
        self.upstream = upstream
        self.context = context
        super().__init__(port, AcmeHandler, state)

    @override
    def get_request(self) -> tuple[socket.socket, str]:
        # The handshake then happens in the connection's own thread, on its first read, so a
        # stalled client blocks no other.
        request, address = super().get_request()
        tls = self.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        return tls, address


class AcmeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.relay()

    def do_HEAD(self) -> None:
        self.relay()

    def do_POST(self) -> None:
        self.relay()

    def relay(self) -> None:
        server = self.server
        if not isinstance(server, AcmeServer):
            raise TypeError(server)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {
            name: value for name, value in self.headers.items() if name.lower() not in HOP_BY_HOP
        }
        fault = server.state.take(self.path)
        if fault is None:
            status, response_headers, content = server.upstream.request(
                self.command, self.path, body, headers
            )
            self.send_response(status)
            for name, value in response_headers:
                if name.lower() not in HOP_BY_HOP:
                    self.send_header(name, value)
        else:
            content = self.send_fault(server.upstream, fault, headers)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def send_fault(self, upstream: Upstream, fault: Fault, headers: dict[str, str]) -> bytes:
        # Clients retry badNonce with the nonce an error response carries (RFC 8555 section
        # 6.5), so every injected problem carries a fresh one from Pebble.
        identity = {
            name: value for name, value in headers.items() if name.lower() in {"host", "user-agent"}
        }
        _, nonce_headers, _ = upstream.request("HEAD", RESOURCES["newNonce"], None, identity)
        self.send_response(fault.status)
        self.send_header("Content-Type", "application/problem+json")
        for name, value in nonce_headers:
            if name.lower() == "replay-nonce":
                self.send_header(name, value)
        if fault.retry_after:
            self.send_header("Retry-After", fault.retry_after)
        return problem_document(fault)


class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.reply(200, self.state().describe())

    def do_POST(self) -> None:
        state = self.state()
        length = int(self.headers.get("Content-Length") or 0)
        try:
            document: object = json.loads(self.rfile.read(length) or b"null")
            if self.path == "/faults":
                fault = parse_fault(document)
                with state.lock:
                    state.faults.append(fault)
            elif self.path == "/nxdomain":
                host = parse_host(document)
                with state.lock:
                    state.nxdomain.add(host)
            else:
                self.reply(404, b"{}")
                return
        except ValueError as error:
            self.reply(400, json.dumps({"error": str(error)}).encode())
            return
        self.reply(200, state.describe())

    def do_DELETE(self) -> None:
        state = self.state()
        with state.lock:
            if self.path == "/faults":
                state.faults.clear()
                state.served.clear()
            elif self.path == "/nxdomain":
                state.nxdomain.clear()
        self.reply(200, state.describe())

    def state(self) -> State:
        server = self.server
        if not isinstance(server, DualStackServer):
            raise TypeError(server)
        return server.state

    def reply(self, status: int, content: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def serve_dns(state: State, port: int, upstream: tuple[str, int]) -> None:
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", port))

    def answer(query: bytes, client: tuple[str, int]) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward:
            forward.settimeout(5)
            forward.sendto(query, upstream)
            try:
                reply, _ = forward.recvfrom(65535)
            except TimeoutError:
                return
        try:
            name = question_name(query)
        except FixtureError:
            name = ""
        with state.lock:
            if name in state.nxdomain:
                reply = with_rcode(reply, NXDOMAIN)
        server.sendto(reply, client)

    while True:
        query, client = server.recvfrom(65535)
        threading.Thread(target=answer, args=(query, client), daemon=True).start()


def start(target: Callable[[], None]) -> None:
    threading.Thread(target=target, daemon=True).start()


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, help="Pebble's ACME host:port")
    parser.add_argument("--cafile", required=True, help="the root that issued Pebble's TLS")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--dns-upstream", required=True, help="challtestsrv's DNS host:port")
    parser.add_argument("--acme-port", type=int, default=14000)
    parser.add_argument("--control-port", type=int, default=8080)
    parser.add_argument("--dns-port", type=int, default=8053)
    options = parser.parse_args(argv)
    host, _, port = options.upstream.rpartition(":")
    dns_host, _, dns_port = options.dns_upstream.rpartition(":")
    state = State()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(options.certificate, options.key)
    acme = AcmeServer(options.acme_port, state, Upstream(host, int(port), options.cafile), context)
    control = DualStackServer(options.control_port, ControlHandler, state)
    dns_address = (socket.gethostbyname(dns_host), int(dns_port))
    start(lambda: serve_dns(state, options.dns_port, dns_address))
    start(control.serve_forever)
    acme.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
