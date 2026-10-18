"""Serve a bare repository over Git smart HTTP for the native fixtures.

docs/quality.md#native-layer. The lane runs this behind a fixture-CA TLS certificate so a
scenario server clones the fixture repository over HTTPS without touching the internet.
``git http-backend`` does the protocol work; this only translates a request into its CGI
environment and the CGI response back into an HTTP response.
"""

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast, override
from urllib.parse import unquote, urlsplit

BACKEND = ["git", "http-backend"]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:
        server = cast(_Server, self.server)
        request = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_PROJECT_ROOT": str(server.root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": unquote(request.path),
            "QUERY_STRING": request.query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_USER": "git",
            "REMOTE_ADDR": self.client_address[0],
        }
        completed = subprocess.run(  # noqa: S603 - fixed backend command
            BACKEND, input=body, env=environment, capture_output=True, check=False, timeout=120
        )
        self._respond(completed.stdout)

    def _respond(self, output: bytes) -> None:
        head, separator, payload = output.partition(b"\r\n\r\n")
        if not separator:
            self.send_error(502)
            return
        status = 200
        headers: list[tuple[str, str]] = []
        for line in head.decode("utf-8", "replace").splitlines():
            name, _, value = line.partition(":")
            value = value.strip()
            if name.lower() == "status":
                status = int(value.split()[0])
            else:
                headers.append((name, value))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    @override
    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"git-http {self.address_string()} {format % args}\n")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    root: Path


def main(argv: Sequence[str] | None = None) -> int:
    import ssl

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--port", type=int, default=443)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    server = _Server(("0.0.0.0", options.port), _Handler)  # noqa: S104 - inside the lane network
    server.root = options.root
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(options.certificate, options.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
