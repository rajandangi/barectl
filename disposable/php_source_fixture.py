"""Serve the PHP source fixture over HTTPS; docs/ssh-connections.md#php-source-fixture."""

import contextlib
import functools
import socket
import ssl
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import override


class DualStackServer(ThreadingHTTPServer):
    address_family: int = socket.AF_INET6

    @override
    def server_bind(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class Handler(SimpleHTTPRequestHandler):
    # APT 3's OpenSSL refuses a body ended by an HTTP/1.0 close without TLS close_notify.
    protocol_version = "HTTP/1.1"


def main(root: str) -> None:
    handler = functools.partial(Handler, directory=f"{root}/www")
    try:
        server: ThreadingHTTPServer = DualStackServer(("::", 443), handler)
    except OSError:
        server = ThreadingHTTPServer(("0.0.0.0", 443), handler)  # noqa: S104 - lane network only
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{root}/server.crt", f"{root}/server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1])
