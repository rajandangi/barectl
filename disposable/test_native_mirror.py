import socket
import struct
import tempfile
import threading
from pathlib import Path

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
