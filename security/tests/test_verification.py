import re
import socket
from dataclasses import replace
from unittest import mock

from django.contrib.auth.models import Permission
from django.test import SimpleTestCase

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, DiscoveryTestCase
from discovery.models import DiscoveryAttempt
from runtimes import updates
from runtimes.catalog import Architecture, load
from security import advisories, reachability
from security.observation import Listener
from security.testing import check, ok_state
from servers.models import Server


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
    def submit_rendered_verification(self, server: Server) -> None:
        page = self.client.get(f"/servers/{server.pk}/security/")
        form = re.search(
            r'<form method="post" action="([^"]+)">\s*'
            r'<input[^>]+>\s*<input type="hidden" name="([^"]+)" value="security">',
            page.content.decode(),
        )
        if form is None:
            self.fail("The Security section did not render a verification form.")
        self.client.post(form[1], {form[2]: "security"})

    def test_repeated_security_requests_share_one_attempt_and_ordinary_refresh_is_busy(
        self,
    ) -> None:
        server = self.register()
        self.run_worker()
        verify_url = f"/servers/{server.pk}/verify/"
        self.client.post(verify_url, {"next": "security"})
        queued = DiscoveryAttempt.objects.latest("pk")
        self.client.post(verify_url, {"next": "security"})
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").pk, queued.pk)
        self.run_worker()

        self.client.post(verify_url, {})
        ordinary = DiscoveryAttempt.objects.latest("pk")
        busy = self.client.post(verify_url, {"next": "security"}, follow=True)
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
        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        self.assertContains(
            self.client.get(f"/servers/{server.pk}/security/"), "No matches in the sources checked."
        )
        before = DiscoveryAttempt.objects.count()
        self.assertEqual(
            self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"}).status_code,
            403,
        )
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

    def test_revocation_during_checks_cannot_publish_a_new_report(self) -> None:
        server = self.register()
        self.run_worker()
        url = f"/servers/{server.pk}/security/"
        report: dict[str, object] = {"findings": [], "notes": [], "checked": ["PHP"]}
        with mock.patch.object(advisories, "check", return_value=report):
            self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})
            self.run_worker()
        first_checked = re.search(r"Checked ([^<]+)</p>", self.client.get(url).content.decode())
        if first_checked is None:
            self.fail("The first verification did not show its completion time.")
        self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})

        def revoke(_collected: object) -> dict[str, object]:
            self.user.user_permissions.remove(
                Permission.objects.get(codename="add_discoveryattempt")
            )
            return report

        with mock.patch.object(advisories, "check", side_effect=revoke):
            self.run_worker()
        page = self.client.get(url)
        self.assertContains(page, f"Checked {first_checked[1]}")
        self.assertContains(page, "No matches in the sources checked.")
        self.assertContains(page, "Permission to check this server is no longer available.")
        self.assertContains(page, "older")
        self.assertEqual(DiscoveryAttempt.objects.latest("pk").security_verification, {})

    def test_connection_change_during_checks_hides_old_report_and_refuses_publication(self) -> None:
        server = self.register()
        self.run_worker()
        report: dict[str, object] = {"findings": [], "notes": [], "checked": ["PHP"]}
        with mock.patch.object(advisories, "check", return_value=report):
            self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})
            self.run_worker()
        self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})

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
            self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})
            self.run_worker()
        first_checked = re.search(r"Checked ([^<]+)</p>", self.client.get(url).content.decode())
        if first_checked is None:
            self.fail("The first verification did not show its completion time.")
        self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})
        queued = self.client.get(url)
        self.assertContains(queued, "No matches in the sources checked.")
        self.assertContains(queued, "older")
        self.remote.failure = "SSH authentication failed."
        self.run_worker()
        failed = self.client.get(url)
        self.assertContains(failed, f"Checked {first_checked[1]}")
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
            self.client.post(f"/servers/{server.pk}/verify/", {"next": "security"})
            self.run_worker()
        verified = self.client.get(url)
        first_checked = re.search(r"Checked ([^<]+)</p>", verified.content.decode())
        if first_checked is None:
            self.fail("The verification did not show its completion time.")
        self.assertContains(verified, "No matches in the sources checked.")
        self.assertContains(verified, "Checked ")

        self.client.post(f"/servers/{server.pk}/verify/", {})
        queued = self.client.get(url)
        self.assertContains(queued, "No matches in the sources checked.")
        self.assertContains(queued, "older")
        self.assertContains(queued, "queued")
        self.assertContains(queued, "Refreshing server observations…")
        self.run_worker()
        refreshed = self.client.get(url)
        self.assertContains(refreshed, f"Checked {first_checked[1]}")
        self.assertContains(refreshed, "No matches in the sources checked.")
        self.assertContains(refreshed, "older")

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
        with (
            mock.patch.object(advisories, "check") as upstream,
            mock.patch.object(socket, "create_connection") as tcp,
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
        self.assertContains(page, "Use a saved public IPv4 or IPv6 address")
        self.assertNotContains(page, "<html")
