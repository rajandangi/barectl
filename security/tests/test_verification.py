import json
import re
import socket
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import replace
from http.client import HTTPException, HTTPResponse
from threading import Event, Thread
from unittest import mock

from django.contrib.auth.models import Permission
from django.http import HttpResponse
from django.template.defaultfilters import date
from django.test import SimpleTestCase
from django.utils import timezone

from backups.observation import ObservedBackup
from bootstrap.standing import HostJudgment, Standing
from discovery import recorded, ssh
from discovery.fakes import COLLECTED, DiscoveryTestCase
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import CollectedSnapshot, Observation
from runtimes import updates
from runtimes.catalog import Architecture, load
from security import advisories, observation, reachability
from security.observation import Listener
from security.testing import blocked, check, ok_state
from servers.models import Server
from servers.ssh_config import ConnectionTarget


def notice(
    key: str, *ranges: tuple[str, str | None], state: str = "published", withdrawn: bool = False
) -> dict[str, object]:
    return {
        "ghsa_id": f"GHSA-aaaa-bbbb-{key}",
        "state": state,
        "published_at": "2026-10-21T13:34:25Z",
        "withdrawn_at": "2026-10-22T13:34:25Z" if withdrawn else None,
        "vulnerabilities": [
            {"vulnerable_version_range": affected, "patched_versions": patched}
            for affected, patched in ranges
        ],
    }


def https_response(
    data: object, *, status: int = 200, headers: dict[str, str] | None = None
) -> mock.Mock:
    response = mock.Mock(status=status)
    response.getheader.side_effect = (headers or {}).get
    body = data if isinstance(data, bytes) else json.dumps(data).encode()
    response.read.side_effect = lambda size: body[:size]
    connection = mock.Mock()
    connection.getresponse.return_value = response
    return connection


class AdvisoryTests(SimpleTestCase):
    def caddy_observation(self) -> CollectedSnapshot:
        caddy = next(
            build for build in load().offered(Architecture.X86_64) if build.entry == "caddy"
        )
        return replace(
            COLLECTED,
            standing=HostJudgment(
                Standing.TARGET_STACK, (), (), (), profiles=(("caddy", caddy.path),)
            ),
            runtimes=(),
        )

    def test_php_branch_and_node_major_are_matched_without_checking_php_extensions(self) -> None:
        catalog = load()
        installed = [
            build
            for build in catalog.offered(Architecture.X86_64)
            if build.entry in {"php84", "php84_redis", "nodejs_24"}
        ]
        standing = HostJudgment(
            Standing.TARGET_STACK,
            (),
            (),
            (),
            profiles=tuple((build.entry, build.path) for build in installed),
        )
        collected = replace(COLLECTED, standing=standing, runtimes=())
        php = https_response(
            [
                notice("0001", ("<8.4.28", "8.4.28"), ("<8.5.99", "8.5.99")),
                notice("0002", ("<8.5.99", "8.5.99")),
                notice("0003", ("<8.4.99", "8.4.99"), state="draft"),
                notice("0004", ("<8.4.99", "8.4.99"), withdrawn=True),
                {**notice("0005", ("<8.4.99", "8.4.99")), "withdrawn_at": True},
            ]
        )
        node = https_response(
            [
                {"version": "v24.22.99", "security": False},
                {"version": "v25.22.99", "security": True},
                {"version": "v24.22.4-rc.1", "security": True},
                {"version": "v24.22.3", "security": True},
                {"version": "v24.22.2", "security": True},
            ]
        )
        with mock.patch.object(
            advisories,
            "HTTPSConnection",
            side_effect=lambda host, **_opts: {"api.github.com": php, "nodejs.org": node}[host],
        ) as connect:
            report = advisories.check(collected)

        self.assertCountEqual(
            [(row["name"], row["fixed"], row["catalog_version"]) for row in report["findings"]],
            [("PHP 8.4", "8.4.28", "8.4.27"), ("Node.js 24", "24.22.3", "24.22.1")],
        )
        self.assertCountEqual(report["checked"], ["PHP", "Node.js"])
        self.assertIn(
            "php84_redis 6.3.0 has no upstream advisory source in this check.", report["notes"]
        )
        self.assertTrue(any("FastCGI" in note for note in report["notes"]))
        self.assertIn("The PHP source returned unsupported records.", report["notes"])
        self.assertEqual(connect.call_count, 2)
        php.request.assert_called_once_with(
            "GET",
            "/repos/php/php-src/security-advisories?per_page=100&state=published&sort=published",
            headers={"User-Agent": "Barectl", "Accept": "application/json"},
        )
        node.request.assert_called_once_with(
            "GET",
            "/dist/index.json",
            headers={"User-Agent": "Barectl", "Accept": "application/json"},
        )

    def test_offers_and_coverage_gaps_use_observed_entries_and_architecture(self) -> None:
        catalog = load()
        x86 = {build.entry: build for build in catalog.offered(Architecture.X86_64)}
        caddy = replace(
            x86["caddy"], version="2.11.6", path=x86["caddy"].path + "-old", retired=True
        )
        restic = replace(x86["restic"], retired=True)
        composer = replace(x86["composer"], version="2.10.3-dev")
        other_arch = next(
            build for build in catalog.offered(Architecture.AARCH64) if build.entry == "restic"
        )
        offered = replace(x86["caddy"], version="2.11.8")
        catalog = replace(catalog, builds=(caddy, restic, composer, offered, other_arch))
        collected = replace(
            COLLECTED,
            standing=HostJudgment(
                Standing.TARGET_STACK,
                (),
                (),
                (),
                profiles=(
                    ("caddy", caddy.path),
                    ("composer", composer.path),
                    ("php84", "/unknown"),
                ),
            ),
            runtimes=(),
            backups=replace(
                COLLECTED.backups, value=(ObservedBackup("alpha", profile=restic.path),)
            ),
        )

        def reply() -> mock.Mock:
            connection = https_response(None)

            def request(method: str, path: str, **_headers: object) -> None:
                if "/caddyserver/caddy/" in path:
                    connection.getresponse.return_value = https_response(
                        [
                            notice("0001", ("<2.11.8", "2.11.8")),
                            notice("0002", ("<2.11.8", None)),
                        ]
                    ).getresponse.return_value
                elif "/restic/restic/" in path:
                    connection.getresponse.return_value = https_response(
                        [
                            notice("0003", ("<=0.18.1", "0.18.2")),
                        ]
                    ).getresponse.return_value
                else:
                    self.fail(f"Unexpected advisory request {method} {path}")

            connection.request.side_effect = request
            return connection

        with (
            mock.patch.object(
                advisories, "HTTPSConnection", side_effect=lambda *_a, **_kw: reply()
            ),
            mock.patch.object(advisories, "load", return_value=catalog),
            mock.patch.object(updates, "load", return_value=catalog),
        ):
            report = advisories.check(collected)

        self.assertCountEqual(
            [
                (row["version"], row["fixed"], row["catalog_comparison"])
                for row in report["findings"]
            ],
            [
                ("2.11.6", "2.11.8", "reaches_fix"),
                ("2.11.6", "", "unknown"),
                ("0.18.1", "0.18.2", "no_offer"),
            ],
        )
        self.assertIn(
            "Could not match the installed php84 profile to a catalog build.", report["notes"]
        )
        self.assertIn("Composer 2.10.3-dev uses an unsupported version format.", report["notes"])

    def test_response_limit_and_omitted_matches_are_reported(self) -> None:
        collected = self.caddy_observation()
        data = json.dumps(
            [
                notice(f"{index:04d}", ("<=2.11.7", "2.11.8"))
                for index in range(advisories.MAX_FINDINGS + 1)
            ]
        ).encode()
        at_limit = data.ljust(advisories.MAX_RESPONSE)

        with mock.patch.object(
            advisories, "HTTPSConnection", return_value=https_response(at_limit)
        ):
            report = advisories.check(collected)
        self.assertEqual(len(report["findings"]), advisories.MAX_FINDINGS)
        self.assertIn("The report reached its display limit and omitted 1 more.", report["notes"])

        for body, note in (
            (at_limit + b" ", "The Caddy advisory response exceeded the size limit."),
            (b"<html>", "The Caddy advisory response was malformed."),
        ):
            with (
                self.subTest(note=note),
                mock.patch.object(advisories, "HTTPSConnection", return_value=https_response(body)),
            ):
                report = advisories.check(collected)
                self.assertEqual(report["findings"], [])
                self.assertEqual(report["checked"], [])
                self.assertIn(note, report["notes"])

    def test_slow_response_expires_while_bytes_are_still_arriving(self) -> None:
        collected = self.caddy_observation()
        incoming, outgoing = socket.socketpair()
        stop = Event()

        def send_body() -> None:
            with suppress(OSError):
                for byte in b"[    ]":
                    if stop.wait(0.025):
                        return
                    outgoing.sendall(bytes([byte]))

        with incoming, outgoing:
            incoming.settimeout(0.15)
            outgoing.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n")
            response = HTTPResponse(incoming)
            response.begin()
            connection = mock.Mock(sock=incoming)
            connection.getresponse.return_value = response
            peer = Thread(target=send_body)
            peer.start()
            try:
                with (
                    mock.patch.object(advisories, "HTTPSConnection", return_value=connection),
                    mock.patch.object(advisories, "TIMEOUT", 0.05),
                ):
                    report = advisories.check(collected)
            finally:
                stop.set()
                peer.join()
                response.close()

        self.assertEqual(report["checked"], [])
        self.assertIn("The advisory request for Caddy timed out.", report["notes"])

    def test_https_setup_and_exchange_failures_are_reported(self) -> None:
        collected = self.caddy_observation()
        for failure, note in (
            (TimeoutError, "The advisory request for Caddy timed out."),
            (OSError, "Could not read the Caddy advisory source."),
            (HTTPException, "Could not read the Caddy advisory source."),
        ):
            for step in ("connect", "request"):
                with self.subTest(failure=failure, step=step):
                    connection = https_response([])
                    getattr(connection, step).side_effect = failure
                    with mock.patch.object(advisories, "HTTPSConnection", return_value=connection):
                        report = advisories.check(collected)
                    self.assertEqual(report["checked"], [])
                    self.assertIn(note, report["notes"])
                    connection.close.assert_called_once()

    def test_unexpected_error_outside_the_https_exchange_propagates(self) -> None:
        collected = self.caddy_observation()
        connection = https_response([])
        with (
            mock.patch.object(advisories, "HTTPSConnection", return_value=connection),
            mock.patch.object(
                type(connection),
                "sock",
                new_callable=mock.PropertyMock,
                side_effect=OSError("Unexpected socket access failure"),
                create=True,
            ),
            self.assertRaisesRegex(OSError, "Unexpected socket access failure"),
        ):
            advisories.check(collected)
        connection.close.assert_called_once()

    def test_uncovered_extension_is_still_an_identified_catalog_build(self) -> None:
        ext = next(
            build for build in load().offered(Architecture.X86_64) if build.entry == "php84_redis"
        )
        collected = replace(
            COLLECTED,
            standing=HostJudgment(
                Standing.TARGET_STACK, (), (), (), profiles=((ext.entry, ext.path),)
            ),
            runtimes=(),
        )
        with mock.patch.object(advisories, "HTTPSConnection") as https:
            report = advisories.check(collected)
            https.assert_not_called()
        self.assertEqual(report["checked"], [])
        self.assertIn(
            "php84_redis 6.3.0 has no upstream advisory source in this check.", report["notes"]
        )
        self.assertNotIn("No installed catalog builds could be identified.", report["notes"])


class ReachabilityTests(SimpleTestCase):
    def test_only_the_verified_public_address_and_observed_tcp_ports_are_probed(self) -> None:
        address = "5.5.5.5"
        listeners = (
            Listener("192.168.1.1", 3306, "tcp", "database", True),
            Listener("192.168.1.2", 3306, "tcp", "database", True),
            Listener("*", 2222, "tcp", "sshd", True),
            Listener("*", 443, "tcp", "web", True),
            Listener("*", 9000, "udp", "service", True),
            Listener("127.0.0.7", 6379, "tcp", "cache", False),
            Listener("::ffff:127.0.0.1", 5432, "tcp", "database", True),
            Listener("*", 0, "tcp", "service", True),
            Listener("*", 1, "tcp", "service", True),
            Listener("*", 65535, "tcp", "service", True),
            Listener("*", 65536, "tcp", "service", True),
        )
        sockets: list[mock.Mock] = []

        def open_socket(family: socket.AddressFamily, kind: socket.SocketKind) -> mock.Mock:
            self.assertEqual(family, socket.AF_INET)
            self.assertEqual(kind, socket.SOCK_STREAM)
            connection = mock.Mock()

            def connect(endpoint: tuple[str, int]) -> None:
                if endpoint[1] == 80:
                    raise ConnectionRefusedError
                if endpoint[1] == 443:
                    raise TimeoutError

            connection.connect.side_effect = connect
            sockets.append(connection)
            return connection

        state = replace(ok_state(), listeners=check(listeners))
        with (
            mock.patch.object(socket, "socket", side_effect=open_socket),
            mock.patch.object(socket, "getaddrinfo") as resolve,
        ):
            result = reachability.check((address, 2222), state)
            resolve.assert_not_called()
        destinations = [(address, port) for port in (1, 80, 443, 2222, 3306, 65535)]
        self.assertCountEqual(
            [connection.connect.call_args.args[0] for connection in sockets], destinations
        )
        for connection in sockets:
            endpoint = connection.connect.call_args.args[0]
            self.assertEqual(
                connection.mock_calls,
                [mock.call.settimeout(1.5), mock.call.connect(endpoint), mock.call.close()],
            )
        self.assertEqual(
            result["ports"],
            [
                {"port": 1, "result": "Connection accepted", "unexpected": True},
                {"port": 80, "result": "Connection refused", "unexpected": False},
                {"port": 443, "result": "Inconclusive", "unexpected": False},
                {"port": 2222, "result": "Connection accepted", "unexpected": False},
                {"port": 3306, "result": "Connection accepted", "unexpected": True},
                {"port": 65535, "result": "Connection accepted", "unexpected": True},
            ],
        )

    def test_unsupported_addresses_do_not_open_sockets(self) -> None:
        cases = (
            (None, "uses an SSH alias"),
            (("example.com", 22), "uses a hostname"),
            (("2600::1%en0", 22), "has an IPv6 scope"),
            (("127.0.0.1", 22), "public unicast"),
            (("10.0.0.1", 22), "public unicast"),
            (("100.64.0.1", 22), "public unicast"),
            (("224.0.0.1", 22), "public unicast"),
            (("ff02::1", 22), "public unicast"),
            (("fe80::1", 22), "public unicast"),
            (("fec0::1", 22), "public unicast"),
            (("::ffff:127.0.0.1", 22), "public unicast"),
            (("::ffff:224.0.0.1", 22), "public unicast"),
        )
        with mock.patch.object(socket, "socket") as probe:
            for peer, reason in cases:
                with self.subTest(peer=peer):
                    result = reachability.check(peer, ok_state())
                    self.assertEqual(result["address"], "")
                    self.assertFalse(result["ports"])
                    self.assertIn(reason, result["note"])
            probe.assert_not_called()

    def test_saved_ssh_port_must_be_between_1_and_65535(self) -> None:
        address = "5.5.5.5"
        with mock.patch.object(socket, "socket") as open_socket:
            for port in (0, 65536):
                with self.subTest(port=port):
                    result = reachability.check((address, port), ok_state())
                    self.assertEqual(result["ports"], [])
                    self.assertIn("The saved SSH port is outside the valid range.", result["note"])
            open_socket.assert_not_called()
            for port, expected in ((1, [1, 80, 443]), (65535, [80, 443, 65535])):
                with self.subTest(port=port):
                    result = reachability.check((address, port), ok_state())
                    self.assertEqual([row["port"] for row in result["ports"]], expected)

    def test_port_limit_keeps_the_standard_endpoints(self) -> None:
        listeners = tuple(Listener("*", port, "tcp", "service", True) for port in range(49, 29, -1))
        state = replace(ok_state(), listeners=check(listeners))
        with mock.patch.object(socket, "socket"):
            result = reachability.check(("5.5.5.5", 443), state)

        self.assertEqual(
            [row["port"] for row in result["ports"]],
            [*range(30, 39), 80, 443],
        )
        self.assertIn("It omitted 11 observed TCP ports.", result["note"])

    def test_missing_listeners_leave_only_standard_ipv6_ports(self) -> None:
        address = "2600::1"
        state = replace(ok_state(), listeners=blocked())
        with mock.patch.object(socket, "socket") as open_socket:
            result = reachability.check((address, 80), state)

        self.assertEqual(
            open_socket.call_args_list, [mock.call(socket.AF_INET6, socket.SOCK_STREAM)] * 2
        )
        self.assertCountEqual(
            open_socket.return_value.connect.call_args_list,
            [mock.call((address, 80, 0, 0)), mock.call((address, 443, 0, 0))],
        )
        self.assertEqual([row["port"] for row in result["ports"]], [80, 443])
        self.assertIn("Host listeners could not be read", result["note"])


class VerificationWorkflowTests(DiscoveryTestCase):
    def rendered_form(self, server: Server, button: str) -> tuple[str, dict[str, str]]:
        page = self.client.get(f"/servers/{server.pk}/security/")
        for action, body in re.findall(
            r'<form method="post" action="([^"]+)">(.*?)</form>',
            page.content.decode(),
            re.DOTALL,
        ):
            if re.search(rf"<button\b[^>]*>\s*{re.escape(button)}\s*</button>", body):
                fields = re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', body)
                return action, dict(fields)
        raise AssertionError(f"The Security page did not render a {button!r} form.")

    def rendered_verification(self, server: Server) -> tuple[str, dict[str, str]]:
        return self.rendered_form(server, "Check upstream fixes and reachability")

    def submit_rendered_verification(self, server: Server, **extra: str) -> HttpResponse:
        action, fields = self.rendered_verification(server)
        return self.client.post(action, {**extra, **fields})

    def register_saved_address(self, address: str) -> Server:
        self.sign_in_with("view_server", "add_server", "add_discoveryattempt")
        response = self.client.post(
            "/servers/add/",
            {"name": "Saved address", "address": address, "username": "root", "port": "2222"},
        )
        self.assertEqual(response.status_code, 302)
        return Server.objects.get(name="Saved address")

    def test_verified_ipv6_tcp_results_survive_an_advisory_outage_and_ordinary_refresh(
        self,
    ) -> None:
        address = "2600::1"
        server = self.register_saved_address(address)
        transcript = recorded.load("laravel-create-26.04")
        listeners = check((Listener("*", 8443, "tcp", "web", True),))
        security = Observation(
            ObservationOutcome.OBSERVED, (), "", replace(ok_state(), listeners=listeners)
        )

        def connect(endpoint: tuple[str, int, int, int]) -> None:
            if endpoint[1] == 80:
                raise ConnectionRefusedError
            if endpoint[1] == 443:
                raise TimeoutError

        url = f"/servers/{server.pk}/security/"
        with (
            mock.patch.object(
                ssh,
                "connect",
                side_effect=lambda _target: nullcontext(recorded.ReplayShell(transcript)),
            ) as ssh_transport,
            mock.patch.object(observation, "collect", return_value=security),
            mock.patch.object(
                advisories, "HTTPSConnection", return_value=https_response(None, status=503)
            ) as https,
            mock.patch.object(socket, "socket") as open_socket,
        ):
            tcp = open_socket.return_value
            tcp.connect.side_effect = connect
            self.run_worker()
            self.submit_rendered_verification(server, address="127.0.0.1", port="1")
            https.assert_not_called()
            open_socket.assert_not_called()
            self.run_worker()
            self.assertEqual(ssh_transport.call_count, 2)
            target = ssh_transport.call_args.args[0]
            self.assertEqual((target.hostname, target.port), (address, 2222))
            expected = [mock.call((address, port, 0, 0)) for port in (80, 443, 2222, 8443)]
            self.assertCountEqual(tcp.connect.call_args_list, expected)
            advisory_requests = https.call_count
            page = self.client.get(url)
            fragment = self.client.get(
                url + "?verification=1",
                headers={
                    "HX-Request": "true",
                    "HX-Request-Type": "partial",
                    "HX-Target": "section#security-verification",
                },
            )
            self.assertCountEqual(tcp.connect.call_args_list, expected)
            self.assertEqual(https.call_count, advisory_requests)

            action, fields = self.rendered_form(server, "Refresh server")
            self.assertRedirects(
                self.client.post(action, fields),
                f"/servers/{server.pk}/",
                fetch_redirect_response=False,
            )
            self.run_worker()
            self.assertEqual(ssh_transport.call_count, 3)
            self.assert_succeeded()
            self.assertEqual(open_socket.call_count, len(expected))
            self.assertCountEqual(tcp.connect.call_args_list, expected)
            self.assertEqual(https.call_count, advisory_requests)

        attempt = DiscoveryAttempt.objects.get(server=server, check_security=True)
        if attempt.finished_at is None:
            self.fail("The worker did not record completion.")
        completed = date(timezone.localtime(attempt.finished_at), "M j, Y, H:i:s T")
        for response in (page, fragment):
            self.assertContains(response, f"Verification completed {completed}.")
            self.assertContains(response, f"Checked {address} from the Barectl controller host.")
            self.assertContains(response, "This check covers TCP only.")
            self.assertContains(response, "TCP 80. Connection refused.")
            self.assertContains(response, "TCP 443. Inconclusive.")
            self.assertContains(response, "TCP 2222. Connection accepted.")
            self.assertContains(response, "TCP 8443. Connection accepted.")
            self.assertContains(response, "Extra port reachable.", count=1)
            self.assertContains(response, "The Caddy advisory source was unavailable (HTTP 503).")

    def test_advisory_matches_and_partial_coverage_are_read_from_the_stored_report(self) -> None:
        server = self.register()
        transcript = recorded.load("laravel-create-26.04")
        caddy = next(
            build for build in load().offered(Architecture.AARCH64) if build.entry == "caddy"
        )

        def connect(host: str, *, timeout: float) -> mock.Mock:
            self.assertEqual(host, "api.github.com")
            self.assertEqual(timeout, 4)
            connection = https_response(None)

            def request(method: str, path: str, **headers: object) -> None:
                self.assertEqual(method, "GET")
                self.assertEqual(
                    headers, {"headers": {"User-Agent": "Barectl", "Accept": "application/json"}}
                )
                if "/caddyserver/caddy/" in path:
                    response = https_response(
                        [
                            notice("0001", ("<=2.11.7", "2.11.8")),
                            notice("0002", ("<2.12.0", None)),
                            {"state": "published", "ghsa_id": "malformed"},
                        ],
                        headers={"Link": '<https://example.test/ignored>; rel="next"'},
                    )
                elif "/composer/composer/" in path:
                    response = https_response(
                        None, status=403, headers={"X-RateLimit-Remaining": "0"}
                    )
                else:
                    response = https_response([])
                connection.getresponse.return_value = response.getresponse.return_value

            connection.request.side_effect = request
            return connection

        url = f"/servers/{server.pk}/security/"
        with (
            mock.patch.object(advisories, "HTTPSConnection", side_effect=connect) as https,
            mock.patch.object(
                ssh,
                "connect",
                side_effect=lambda _target: nullcontext(recorded.ReplayShell(transcript)),
            ),
        ):
            self.run_worker()
            self.submit_rendered_verification(server)
            https.assert_not_called()
            self.run_worker()
            calls = https.call_count
            self.assertGreater(calls, 0)
            page = self.client.get(url)
            fragment = self.client.get(
                url + "?verification=1",
                headers={
                    "HX-Request": "true",
                    "HX-Request-Type": "partial",
                    "HX-Target": "section#security-verification",
                },
            )
            self.assertEqual(https.call_count, calls)
        for response in (page, fragment):
            self.assertContains(response, f"Caddy {caddy.version}.")
            self.assertContains(
                response,
                "https://github.com/caddyserver/caddy/security/advisories/GHSA-aaaa-bbbb-0001",
            )
            self.assertContains(response, "Upstream fix in 2.11.8.")
            self.assertContains(
                response,
                f"The catalog used for this check offers {caddy.version}, "
                "which is older than the upstream fix.",
            )
            self.assertContains(response, "The source provides no usable fixed version.")
            self.assertContains(response, "GitHub rate-limited the advisory request for Composer.")
            self.assertContains(
                response, "Additional pages of the Caddy advisory source were skipped."
            )
            self.assertContains(response, "The Caddy source returned unsupported records.")
            self.assertContains(
                response, "TCP check skipped. The saved SSH connection uses an SSH alias."
            )

    def test_an_older_report_keeps_the_recorded_offer(self) -> None:
        server = self.register()
        self.run_worker()
        finding = {
            "name": "Caddy",
            "version": "2.11.6",
            "advisory": "GHSA-aaaa-bbbb-0001",
            "url": "https://github.com/caddyserver/caddy/security/advisories/GHSA-aaaa-bbbb-0001",
            "fixed": "2.11.8",
            "catalog_has_fix": False,
        }
        report = {
            "checked": ["Caddy"],
            "notes": [],
            "findings": [
                {**finding, "catalog_version": "2.11.7"},
                {**finding, "catalog_version": "2.11.7-dev"},
            ],
        }
        with mock.patch.object(advisories, "check", return_value=report):
            self.submit_rendered_verification(server)
            self.run_worker()
        page = self.client.get(f"/servers/{server.pk}/security/")
        self.assertContains(page, "Upstream fix in 2.11.8.")
        self.assertContains(
            page,
            "The catalog used for this check offers 2.11.7, which is older than the upstream fix.",
        )
        self.assertContains(
            page,
            "The catalog used for this check offers 2.11.7-dev. "
            "The comparison with the upstream fix is unknown.",
        )

    def test_repeated_security_requests_share_one_attempt_and_ordinary_refresh_is_busy(
        self,
    ) -> None:
        server = self.register()
        self.run_worker()
        action, fields = self.rendered_verification(server)
        self.client.post(action, fields)
        queued = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(queued.status, DiscoveryAttempt.Status.QUEUED)
        self.client.post(action, fields)
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").pk, queued.pk)
        self.run_worker()

        refresh_action, refresh_fields = self.rendered_form(server, "Refresh server")
        self.client.post(refresh_action, refresh_fields)
        ordinary = DiscoveryAttempt.objects.latest("pk")
        self.assertNotEqual(ordinary.pk, queued.pk)
        busy = self.client.post(action, fields, follow=True)
        self.assertContains(busy, "Another server operation is still running")
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").pk, ordinary.pk)

    def test_viewer_reads_history_but_cannot_request_a_check(self) -> None:
        server = self.register()
        self.run_worker()
        with mock.patch.object(
            advisories, "check", return_value={"findings": [], "notes": [], "checked": ["PHP"]}
        ):
            self.submit_rendered_verification(server)
            self.run_worker()
        action, fields = self.rendered_verification(server)
        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        self.assertContains(
            self.client.get(f"/servers/{server.pk}/security/"), "No matches in the sources checked."
        )
        before = DiscoveryAttempt.objects.count()
        self.assertEqual(self.client.post(action, fields).status_code, 403)
        self.assertEqual(DiscoveryAttempt.objects.count(), before)

    def test_connection_edit_hides_prior_verification(self) -> None:
        server = self.register()
        self.run_worker()
        with mock.patch.object(
            advisories, "check", return_value={"findings": [], "notes": [], "checked": ["PHP"]}
        ):
            self.submit_rendered_verification(server)
            self.run_worker()
        url = f"/servers/{server.pk}/security/"
        self.assertContains(self.client.get(url), "No matches in the sources checked.")
        server.connection_revision += 1
        server.save(update_fields=["connection_revision"])
        self.assertNotContains(self.client.get(url), "No matches in the sources checked.")

    def test_revoked_request_fails_before_network_checks(self) -> None:
        server = self.register()
        self.run_worker()
        self.submit_rendered_verification(server)
        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        with (
            mock.patch.object(advisories, "check") as upstream,
            mock.patch.object(reachability, "check") as tcp,
        ):
            self.run_worker()
        upstream.assert_not_called()
        tcp.assert_not_called()
        page = self.client.get(f"/servers/{server.pk}/security/")
        self.assertContains(page, "Permission to check this server is no longer available.")
        self.assertNotContains(page, "No matches in the sources checked.")

    def test_revocation_during_native_collection_blocks_both_extra_checks(self) -> None:
        server = self.register_saved_address("2600::1")
        transcript = recorded.load("laravel-create-26.04")
        with mock.patch.object(
            ssh, "connect", return_value=nullcontext(recorded.ReplayShell(transcript))
        ):
            self.run_worker()
        self.assert_succeeded()
        self.submit_rendered_verification(server)

        shell = recorded.ReplayShell(transcript)

        @contextmanager
        def collect_then_revoke(_target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            yield shell
            self.user.user_permissions.remove(
                Permission.objects.get(codename="add_discoveryattempt")
            )

        with (
            mock.patch.object(ssh, "connect", side_effect=collect_then_revoke),
            mock.patch.object(advisories, "HTTPSConnection") as https,
            mock.patch.object(socket, "socket") as tcp,
        ):
            self.run_worker()
        self.assertTrue(shell.commands)
        https.assert_not_called()
        tcp.assert_not_called()
        page = self.client.get(f"/servers/{server.pk}/security/")
        self.assertContains(page, "Permission to check this server is no longer available.")
        self.assertNotContains(page, "Verification completed")

    def test_revocation_during_checks_cannot_publish_a_new_report(self) -> None:
        server = self.register()
        self.run_worker()
        url = f"/servers/{server.pk}/security/"
        report: dict[str, object] = {"findings": [], "notes": [], "checked": ["PHP"]}
        with mock.patch.object(advisories, "check", return_value=report):
            self.submit_rendered_verification(server)
            self.run_worker()
        first_checked = re.search(
            r"Verification completed ([^<]+)</p>", self.client.get(url).content.decode()
        )
        if first_checked is None:
            self.fail("The first verification did not show its completion time.")
        self.submit_rendered_verification(server)

        def revoke(_collected: object) -> dict[str, object]:
            self.user.user_permissions.remove(
                Permission.objects.get(codename="add_discoveryattempt")
            )
            return report

        with mock.patch.object(advisories, "check", side_effect=revoke):
            self.run_worker()
        page = self.client.get(url)
        self.assertContains(page, f"Verification completed {first_checked[1]}")
        self.assertContains(page, "No matches in the sources checked.")
        self.assertContains(page, "Permission to check this server is no longer available.")
        self.assertContains(page, "older")
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").security_verification, {})

    def test_connection_change_during_checks_hides_old_report_and_refuses_publication(self) -> None:
        server = self.register()
        self.run_worker()
        report: dict[str, object] = {"findings": [], "notes": [], "checked": ["PHP"]}
        with mock.patch.object(advisories, "check", return_value=report):
            self.submit_rendered_verification(server)
            self.run_worker()
        self.submit_rendered_verification(server)

        def edit(_collected: object) -> dict[str, object]:
            server.connection_revision += 1
            server.save(update_fields=["connection_revision"])
            return report

        with mock.patch.object(advisories, "check", side_effect=edit):
            self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").security_verification, {})
        self.assertNotContains(
            self.client.get(f"/servers/{server.pk}/security/"),
            "No matches in the sources checked.",
        )

    def test_failed_verification_retains_the_previous_report(self) -> None:
        server = self.register()
        self.run_worker()
        url = f"/servers/{server.pk}/security/"
        with mock.patch.object(
            advisories, "check", return_value={"findings": [], "notes": [], "checked": ["PHP"]}
        ):
            self.submit_rendered_verification(server)
            self.run_worker()
        first_checked = re.search(
            r"Verification completed ([^<]+)</p>", self.client.get(url).content.decode()
        )
        if first_checked is None:
            self.fail("The first verification did not show its completion time.")
        self.submit_rendered_verification(server)
        queued = self.client.get(url)
        self.assertContains(queued, "No matches in the sources checked.")
        self.assertContains(queued, "older")
        self.remote.failure = "SSH authentication failed."
        self.run_worker()
        failed = self.client.get(url)
        self.assertContains(failed, f"Verification completed {first_checked[1]}")
        self.assertContains(failed, "No matches in the sources checked.")
        self.assertContains(failed, "SSH authentication failed.")
        self.assertContains(failed, "older")

    def test_later_refresh_keeps_the_dated_report_and_shows_attempt_status(self) -> None:
        server = self.register()
        self.run_worker()
        url = f"/servers/{server.pk}/security/"
        with mock.patch.object(
            advisories, "check", return_value={"findings": [], "notes": [], "checked": ["PHP"]}
        ):
            self.submit_rendered_verification(server)
            self.run_worker()
        verified = self.client.get(url)
        first_checked = re.search(r"Verification completed ([^<]+)</p>", verified.content.decode())
        if first_checked is None:
            self.fail("The verification did not show its completion time.")
        self.assertContains(verified, "No matches in the sources checked.")
        self.assertContains(verified, "Verification completed ")

        action, fields = self.rendered_form(server, "Refresh server")
        self.client.post(action, fields)
        queued = self.client.get(url)
        self.assertContains(queued, "No matches in the sources checked.")
        self.assertContains(queued, "older")
        self.assertContains(queued, "queued")
        self.assertContains(queued, "Refreshing server observations…")
        self.run_worker()
        refreshed = self.client.get(url)
        self.assertContains(refreshed, f"Verification completed {first_checked[1]}")
        self.assertContains(refreshed, "No matches in the sources checked.")
        self.assertContains(refreshed, "older")

    def test_the_rendered_form_runs_verification_only_in_the_worker(self) -> None:
        with mock.patch.object(advisories, "check") as upstream:
            server = self.register()
            self.run_worker()
            upstream.assert_not_called()

            page_url = f"/servers/{server.pk}/security/"
            self.assertRedirects(
                self.submit_rendered_verification(server),
                f"{page_url}#security-verification",
                fetch_redirect_response=False,
            )
            self.assertContains(self.client.get(page_url), "Checking upstream fixes")
            upstream.assert_not_called()
            upstream.return_value = {"findings": [], "notes": [], "checked": ["PHP"]}
            self.run_worker()
            upstream.assert_called_once()

        attempt = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        with (
            mock.patch.object(advisories, "check") as upstream,
            mock.patch.object(socket, "socket") as tcp,
        ):
            page = self.client.get(
                page_url + "?verification=1",
                headers={
                    "HX-Request": "true",
                    "HX-Request-Type": "partial",
                    "HX-Target": "section#security-verification",
                },
            )
            upstream.assert_not_called()
            tcp.assert_not_called()
        self.assertContains(page, "No matches in the sources checked.")
        self.assertContains(page, "TCP check skipped. The saved SSH connection uses an SSH alias.")
        self.assertNotContains(page, "<html")
