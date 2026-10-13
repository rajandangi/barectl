"""Forward a published TCP port to a server on a lane's internal network.

docs/quality.md#native-layer. Docker Desktop does not publish ports on an ``--internal``
network (spike P6.2), so a lane server cannot be reached directly. This dual-homed
container joins the lane network and a normal bridge and relays the connection, keeping the
server's egress denied.
"""

import argparse
import select
import socket
import socketserver
import sys
from collections.abc import Sequence
from typing import cast, override

BUFFER = 64 * 1024


def _pump(client: socket.socket, upstream: socket.socket) -> None:
    peers = [client, upstream]
    while True:
        readable, _, _ = select.select(peers, [], [], 300)
        for source in readable:
            try:
                data = source.recv(BUFFER)
            except OSError:
                return
            if not data:
                return
            destination = upstream if source is client else client
            try:
                destination.sendall(data)
            except OSError:
                return


class _Handler(socketserver.BaseRequestHandler):
    @override
    def handle(self) -> None:
        target = cast(_Server, self.server).target
        try:
            upstream = socket.create_connection(target, timeout=30)
        except OSError:
            return
        with upstream:
            _pump(self.request, upstream)


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    target: tuple[str, int]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--target", required=True, help="HOST:PORT on the lane network")
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    host, _, port = options.target.rpartition(":")
    server = _Server(("0.0.0.0", options.listen), _Handler)  # noqa: S104 - inside the lane network
    server.target = (host, int(port))
    sys.stderr.write(f"forward: 0.0.0.0:{options.listen} -> {options.target}\n")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
