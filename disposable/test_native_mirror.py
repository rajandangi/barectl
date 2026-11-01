import os
import socket
import struct
import tempfile
import threading
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from .native_mirror import dns, forward


def query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )


class DnsTests(SimpleTestCase):
    def test_reads_the_queried_name(self) -> None:
        self.assertEqual(dns.question_name(query("example.com")), "example.com")

    def test_answers_nxdomain_and_echoes_the_question(self) -> None:
        request = query("example.com")
        response = dns.refusal(request)
        identifier, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", response, 0)
        self.assertEqual(identifier, 0x1234)
        self.assertEqual(flags & 0x000F, dns.NXDOMAIN)
        self.assertEqual(questions, 1)
        self.assertEqual(answers, 0)
        self.assertEqual(dns.question_name(response), "example.com")

    def test_ignores_a_truncated_packet(self) -> None:
        self.assertEqual(dns.refusal(b"\x00"), b"")
        self.assertEqual(dns.question_name(b"\x00"), "")


class ForwardTests(SimpleTestCase):
    def test_tcp_relay_sends_small_payloads_without_buffering_on_either_socket(self) -> None:
        options: list[int] = []
        finished = threading.Event()
        pump = forward._pump

        def observe(client: socket.socket, upstream: socket.socket) -> None:
            options.extend(
                peer.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
                for peer in (client, upstream)
            )
            try:
                pump(client, upstream)
            finally:
                finished.set()

        with socket.create_server(("127.0.0.1", 0)) as target:
            target.settimeout(5)
            relay = forward._Server(("127.0.0.1", 0), forward._Handler)
            relay.target = target.getsockname()
            thread = threading.Thread(target=relay.serve_forever)
            with patch.object(forward, "_pump", observe):
                thread.start()
                try:
                    with socket.create_connection(
                        ("127.0.0.1", relay.server_address[1]), timeout=5
                    ) as client:
                        upstream, _ = target.accept()
                        with upstream:
                            upstream.settimeout(5)
                            client.sendall(b"request")
                            self.assertEqual(upstream.recv(16), b"request")
                            upstream.sendall(b"reply")
                            self.assertEqual(client.recv(16), b"reply")
                    self.assertTrue(finished.wait(5))
                finally:
                    relay.shutdown()
                    relay.server_close()
                    thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual([bool(option) for option in options], [True, True])

    def test_relays_both_directions(self) -> None:
        client = socket.socketpair()
        upstream = socket.socketpair()
        with client[0], client[1], upstream[0], upstream[1]:
            relay = threading.Thread(target=forward._pump, args=(client[1], upstream[0]))
            relay.start()
            client[0].sendall(b"out")
            self.assertEqual(upstream[1].recv(16), b"out")
            upstream[1].sendall(b"in")
            self.assertEqual(client[0].recv(16), b"in")
            client[0].close()
            relay.join(timeout=5)
            self.assertFalse(relay.is_alive())


class ServeRoutingTests(SimpleTestCase):
    def test_serves_each_host_from_its_own_directory(self) -> None:
        from .native_mirror import serve

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cache.nixos.org").mkdir()
            (root / "cache.nixos.org" / "x.narinfo").write_bytes(b"cached")
            server = serve._Server(("127.0.0.1", 0), root, frozenset({"cache.nixos.org"}))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                import http.client

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("GET", "/x.narinfo", headers={"Host": "cache.nixos.org"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"cached")
                connection.request("GET", "/x.narinfo", headers={"Host": "other.example"})
                self.assertEqual(connection.getresponse().status, 404)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_a_cached_file_reports_a_fresh_last_modified(self) -> None:
        from .native_mirror import serve

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = Path("snapshot.ubuntu.com") / "ubuntu" / "dists" / "resolute" / "InRelease"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(b"cached")
            old = time.time() - 30 * 86400
            os.utime(path, (old, old))
            server = serve._Server(("127.0.0.1", 0), root, frozenset({"snapshot.ubuntu.com"}))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                import http.client

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/ubuntu/dists/resolute/InRelease",
                    headers={"Host": "snapshot.ubuntu.com"},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                modified = parsedate_to_datetime(response.getheader("Last-Modified") or "")
                self.assertGreater(modified.timestamp(), time.time() - 60)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
