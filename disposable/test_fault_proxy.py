import json
import struct
import threading
import urllib.request
from typing import override

from django.test import SimpleTestCase

from .fault_proxy import (
    NXDOMAIN,
    ControlHandler,
    DualStackServer,
    Fault,
    FixtureError,
    State,
    parse_fault,
    parse_host,
    problem_document,
    question_name,
    with_rcode,
)


def query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"


class FaultTests(SimpleTestCase):
    def test_defaults_follow_the_problem_type(self) -> None:
        self.assertEqual(
            parse_fault({"resource": "newOrder", "type": "rateLimited", "retryAfter": "60"}),
            Fault("newOrder", "rateLimited", 429, "Injected rateLimited fault", "60", 1),
        )
        self.assertEqual(parse_fault({"resource": "finalize", "type": "badNonce"}).status, 400)
        self.assertEqual(parse_fault({"resource": "finalize", "type": "caa"}).status, 403)

    def test_rejects_invalid_faults(self) -> None:
        documents: tuple[object, ...] = (
            [],
            {"resource": "orders", "type": "caa"},
            {"resource": "newOrder", "type": "unknown"},
            {"resource": "newOrder", "type": "caa", "status": 200},
            {"resource": "newOrder", "type": "caa", "retryAfter": 60},
            {"resource": "newOrder", "type": "caa", "count": 0},
        )
        for document in documents:
            with self.subTest(document=document), self.assertRaises(FixtureError):
                parse_fault(document)

    def test_problem_document(self) -> None:
        fault = parse_fault({"resource": "newOrder", "type": "caa", "detail": "CAA forbids"})
        self.assertEqual(
            json.loads(problem_document(fault)),
            {"type": "urn:ietf:params:acme:error:caa", "detail": "CAA forbids", "status": 403},
        )

    def test_faults_match_by_path_and_run_out(self) -> None:
        state = State()
        fault = parse_fault({"resource": "finalize", "type": "caa", "count": 2})
        state.faults.append(fault)
        self.assertIsNone(state.take("/order-plz"))
        self.assertEqual(state.take("/finalize-order/abc"), fault)
        self.assertEqual(state.take("/finalize-order/abc"), Fault(**{**vars(fault), "count": 1}))
        self.assertIsNone(state.take("/finalize-order/abc"))
        self.assertEqual(len(state.served), 2)


class DnsTests(SimpleTestCase):
    def test_question_name(self) -> None:
        self.assertEqual(question_name(query("WWW.Barectl.test")), "www.barectl.test.")
        for packet in (b"\x00" * 12, query("a")[:14]):
            with self.subTest(packet=packet), self.assertRaises(FixtureError):
                question_name(packet)

    def test_rcode_keeps_the_rest_of_the_reply(self) -> None:
        reply = bytes.fromhex("1234 8180 0001 0000 0001 0000".replace(" ", "")) + b"rest"
        changed = with_rcode(reply, NXDOMAIN)
        self.assertEqual(changed[3] & 0x0F, NXDOMAIN)
        self.assertEqual(changed[:3] + changed[4:], reply[:3] + reply[4:])

    def test_parse_host(self) -> None:
        self.assertEqual(parse_host({"host": "Missing.Barectl.Test"}), "missing.barectl.test.")
        with self.assertRaises(FixtureError):
            parse_host({"host": "."})


class QuietControlHandler(ControlHandler):
    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


class ControlTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.state = State()
        server = DualStackServer(0, QuietControlHandler, self.state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base = f"http://[::1]:{server.server_address[1]}"

    def call(self, method: str, path: str, document: object = None) -> tuple[int, object]:
        body = None if document is None else json.dumps(document).encode()
        request = urllib.request.Request(  # noqa: S310 - the test's own server
            self.base + path, data=body, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_selects_and_clears_faults_and_names(self) -> None:
        status, _ = self.call("POST", "/faults", {"resource": "newOrder", "type": "caa"})
        self.assertEqual(status, 200)
        status, _ = self.call("POST", "/nxdomain", {"host": "missing.barectl.test"})
        self.assertEqual(status, 200)
        self.state.take("/order-plz")
        _, described = self.call("GET", "/")
        self.assertEqual(
            described,
            {
                "faults": [],
                "served": [
                    {
                        "resource": "newOrder",
                        "type": "caa",
                        "status": 403,
                        "detail": "Injected caa fault",
                        "retry_after": "",
                        "count": 1,
                    }
                ],
                "nxdomain": ["missing.barectl.test."],
            },
        )
        self.call("DELETE", "/faults")
        _, described = self.call("DELETE", "/nxdomain")
        self.assertEqual(described, {"faults": [], "served": [], "nxdomain": []})

    def test_rejects_invalid_requests(self) -> None:
        self.assertEqual(self.call("POST", "/faults", {"resource": "x"})[0], 400)
        self.assertEqual(self.call("POST", "/nxdomain", {})[0], 400)
        self.assertEqual(self.call("POST", "/other", {})[0], 404)
