"""Answer every DNS query with NXDOMAIN and record the name asked for.

docs/quality.md#native-layer. Aliased names are answered by Docker's embedded resolver
before it forwards anything here, so this server only ever sees a name that is not one of a
lane's known hosts. The runner reads the log after each scenario: any name there is a
scenario reaching outside its network, and fails the item with that name reported.
"""

import argparse
import socketserver
import struct
import sys
from collections.abc import Sequence
from typing import TextIO, cast, override

NXDOMAIN = 3
_HEADER = struct.Struct("!HHHHHH")


def question_name(packet: bytes) -> str:
    """The queried name of the first question, or ``""`` when the packet is malformed."""
    if len(packet) < _HEADER.size:
        return ""
    _, _, questions, _, _, _ = _HEADER.unpack_from(packet, 0)
    if questions < 1:
        return ""
    labels: list[str] = []
    offset = _HEADER.size
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels).lower()
        if length & 0xC0 or offset + length > len(packet):
            return ""
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ""


def refusal(packet: bytes) -> bytes:
    """A response with the request's ID and question and the NXDOMAIN rcode."""
    if len(packet) < _HEADER.size:
        return b""
    identifier, _, questions, _, _, _ = _HEADER.unpack_from(packet, 0)
    response = bytearray(_HEADER.pack(identifier, 0x8183, questions, 0, 0, 0))
    response.extend(packet[_HEADER.size :])
    return bytes(response)


class _Handler(socketserver.BaseRequestHandler):
    @override
    def handle(self) -> None:
        packet, sock = self.request
        server = cast(_Server, self.server)
        name = question_name(packet)
        if name:
            server.log.write(f"{name}\n")
            server.log.flush()
        answer = refusal(packet)
        if answer:
            sock.sendto(answer, self.client_address)


class _Server(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True
    log: TextIO


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", required=True, type=argparse.FileType("a"))
    parser.add_argument("--port", type=int, default=53)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    server = _Server(("0.0.0.0", options.port), _Handler)  # noqa: S104 - inside the lane network
    server.log = options.log
    sys.stderr.write("dns: answering NXDOMAIN for every name\n")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
