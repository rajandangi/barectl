import re
import socket
from dataclasses import replace
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, DiscoveryTestCase
from discovery.models import DiscoveryAttempt
from runtimes import updates
from runtimes.catalog import Architecture, load
from security import advisories, reachability
from security.observation import Listener
from security.testing import check, ok_state


class AdvisoryTests(SimpleTestCase):
    def test_installed_and_offered_builds_are_compared_with_upstream_fixes(self) -> None:
        catalog = load()
        installed = tuple(
            replace(build, version=version, retired=build.entry == "caddy")
            for entry, version in (
                ("php84", "8.4.27"),
                ("caddy", "2.11.7"),
                ("nodejs_24", "24.22.1"),
            )
            for build in catalog.offered(Architecture.X86_64)
            if build.entry == entry
        )
        caddy_build = next(build for build in installed if build.entry == "caddy")
        updated_caddy = replace(
            caddy_build, version="2.11.8", path=caddy_build.path + "-updated", retired=False
        )
        catalog = replace(catalog, builds=(*installed, updated_caddy))
        standing = HostJudgment(
            Standing.TARGET_STACK,
            (),
            (),
            (),
            profiles=tuple((build.entry, build.path) for build in installed),
        )
        collected = replace(COLLECTED, standing=standing, runtimes=())

        php = {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2026-12345",
            "vulnerabilities": [
                {"vulnerable_version_range": "<8.4.27", "patched_versions": "8.4.27"},
                {"vulnerable_version_range": "<8.5.99", "patched_versions": "8.5.99"},
            ],
        }
        caddy = {
            "ghsa_id": "GHSA-bbbb-cccc-dddd",
            "vulnerabilities": [
                {"vulnerable_version_range": ">=2.11.7, <2.11.8", "patched_versions": "2.11.8"}
            ],
        }
        node = [
            {"version": "v24.22.99", "security": False},
            {"version": "v25.22.99", "security": True},
            {"version": "v24.22.3", "security": True},
        ]
        responses = {
            "php/php-src": ([php], False),
            "caddyserver/caddy": ([caddy], False),
            "": (node, False),
        }
        with (
            mock.patch.object(advisories, "_source", side_effect=responses.__getitem__),
            mock.patch.object(advisories, "load", return_value=catalog),
            mock.patch.object(updates, "load", return_value=catalog),
        ):
            report = advisories.check(collected)

        self.assertEqual(
            [(row["name"], row["fixed"], row["catalog_has_fix"]) for row in report["findings"]],
            [("Node.js 24", "24.22.3", False), ("Caddy", "2.11.8", True)],
        )
        self.assertEqual(report["checked"], ["PHP", "Node.js", "Caddy"])
        self.assertEqual(report["notes"], [])


class ReachabilityTests(SimpleTestCase):
    def test_only_the_verified_public_address_and_observed_tcp_ports_are_probed(self) -> None:
        address = "5.5.5.5"
        listeners = (
            Listener("*", 3306, "tcp", "database", True),
            Listener("*", 443, "udp", "web", True),
            Listener("127.0.0.1", 6379, "tcp", "cache", False),
        )

        def connect(endpoint: tuple[str, int], *, timeout: float) -> mock.Mock:
            self.assertEqual(timeout, reachability.TIMEOUT)
            if endpoint[1] == 80:
                raise ConnectionRefusedError
            if endpoint[1] == 443:
                raise TimeoutError
            return mock.Mock()

        state = replace(ok_state(), listeners=check(listeners))
        with mock.patch.object(socket, "create_connection", side_effect=connect) as probe:
            result = reachability.check((address, 2222), state)
            self.assertEqual(
                {call.args[0] for call in probe.call_args_list},
                {(address, port) for port in (80, 443, 2222, 3306)},
            )
        self.assertEqual(
            result["ports"],
            [
                {"port": 80, "result": "Connection refused", "unexpected": False},
                {"port": 443, "result": "Could not connect", "unexpected": False},
                {"port": 2222, "result": "Connection accepted", "unexpected": False},
                {"port": 3306, "result": "Connection accepted", "unexpected": True},
            ],
        )

    def test_unsupported_addresses_do_not_open_sockets(self) -> None:
        with mock.patch.object(socket, "create_connection") as probe:
            for address in ("example.com", "127.0.0.1", "10.0.0.1", "ff02::1", "fe80::1"):
                with self.subTest(address=address):
                    result = reachability.check((address, 22), ok_state())
                    self.assertFalse(result["ports"])
                    self.assertIn("public", result["note"])
            probe.assert_not_called()

    def test_port_limit_keeps_the_standard_endpoints(self) -> None:
        listeners = tuple(Listener("*", port, "tcp", "service", True) for port in range(30, 50))
        state = replace(ok_state(), listeners=check(listeners))
        with mock.patch.object(socket, "create_connection"):
            result = reachability.check(("5.5.5.5", 2222), state)

        self.assertEqual(
            [row["port"] for row in result["ports"]],
            [*range(30, 39), 80, 443, 2222],
        )
        self.assertIn("port limit", result["note"])


class VerificationWorkflowTests(DiscoveryTestCase):
    def test_the_rendered_form_runs_verification_only_in_the_worker(self) -> None:
        with mock.patch.object(advisories, "check") as upstream:
            server = self.register()
            self.run_worker()
            upstream.assert_not_called()

            page_url = f"/servers/{server.pk}/security/"
            page = self.client.get(page_url)
            form = re.search(
                r'<form method="post" action="([^"]+)">\s*'
                r'<input[^>]+>\s*<input type="hidden" name="([^"]+)" value="security">',
                page.content.decode(),
            )
            if form is None:
                self.fail("The Security section did not render a verification form.")
            self.assertRedirects(
                self.client.post(form[1], {form[2]: "security"}),
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
        page = self.client.get(
            page_url + "?verification=1",
            headers={
                "HX-Request": "true",
                "HX-Request-Type": "partial",
                "HX-Target": "section#security-verification",
            },
        )
        self.assertContains(page, "No matches in the sources checked.")
        self.assertContains(page, "Use a saved public IPv4 or IPv6 address")
        self.assertNotContains(page, "<html")
