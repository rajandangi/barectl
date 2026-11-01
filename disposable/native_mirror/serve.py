"""Serve the local mirror over HTTPS, choosing the document root from the Host header.

docs/quality.md#native-layer. Each mirrored host name has its files under ``root/<host>/``,
so ``https://cache.nixos.org/<hash>.narinfo`` is served from ``<root>/cache.nixos.org/``.
The certificate is signed by the harness's fixture CA, which the served servers trust.
"""

import argparse
import ssl
import sys
from collections.abc import Sequence
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast, override
from urllib.parse import urlsplit


class _Handler(SimpleHTTPRequestHandler):
    # apt reads the response over TLS and reports a missing close_notify as an error, so the
    # mirror keeps the connection alive instead of closing it after every file.
    protocol_version = "HTTP/1.1"

    @override
    def translate_path(self, path: str) -> str:
        server = cast(_Server, self.server)
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if host not in server.hosts:
            return "/nonexistent"
        relative = urlsplit(path).path.lstrip("/")
        return str(server.root / host / relative)

    @override
    def date_time_string(self, timestamp: float | None = None) -> str:
        """Report every mirrored file as just served.

        The mirror's cached bytes are immutable, but apt stores a list file's modification
        time from ``Last-Modified``. Serving the fetch time keeps the list age on the
        disposable server honest after a refresh (docs/security-native-design.md).
        """
        return super().date_time_string()

    @override
    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"mirror {self.address_string()} {format % args}\n")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], root: Path, hosts: frozenset[str]) -> None:
        self.root = root
        self.hosts = hosts
        super().__init__(address, _Handler)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--port", type=int, default=443)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(options.certificate, options.key)
    server = _Server(("0.0.0.0", options.port), options.root, frozenset(options.host))  # noqa: S104
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
