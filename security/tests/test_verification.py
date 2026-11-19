import json
import re
import socket
from contextlib import nullcontext
from dataclasses import replace
from unittest import mock

from django.contrib.auth.models import Permission
from django.test import SimpleTestCase

from backups.observation import ObservedBackup
from bootstrap.standing import HostJudgment, Standing
from discovery import recorded, ssh
from discovery.fakes import COLLECTED, DiscoveryTestCase
from discovery.models import DiscoveryAttempt
from runtimes import updates
from runtimes.catalog import Architecture, load
from security import advisories, reachability
from security.observation import Listener
from security.testing import check, ok_state
from servers.models import Server


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
        caddy = next(
            build for build in load().offered(Architecture.X86_64) if build.entry == "caddy"
        )
        collected = replace(
            COLLECTED,
            standing=HostJudgment(
                Standing.TARGET_STACK, (), (), (), profiles=(("caddy", caddy.path),)
            ),
            runtimes=(),
        )
        data = json.dumps(
            [notice(f"{index:04d}", ("<=2.11.7", "2.11.8")) for index in range(21)]
        ).encode()
        at_limit = data.ljust(advisories.MAX_RESPONSE)

        with mock.patch.object(
            advisories, "HTTPSConnection", return_value=https_response(at_limit)
        ):
            report = advisories.check(collected)
        self.assertEqual(len(report["findings"]), 20)
        self.assertIn("The display limit was reached. Omitted matches: 1.", report["notes"])

        for body, note in (
            (at_limit + b" ", "Caddy: the upstream response exceeded the size limit."),
            (b"<html>", "Caddy: the upstream response was malformed."),
        ):
            with (
                self.subTest(note=note),
                mock.patch.object(advisories, "HTTPSConnection", return_value=https_response(body)),
            ):
                report = advisories.check(collected)
                self.assertEqual(report["findings"], [])
                self.assertEqual(report["checked"], [])
                self.assertIn(note, report["notes"])

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
                f"The catalog offers {caddy.version}, which is older than the upstream fix.",
            )
            self.assertContains(response, "The source provides no usable fixed version.")
            self.assertContains(response, "Composer: GitHub rate-limited the advisory request.")
            self.assertContains(response, "Caddy: additional upstream advisory pages were skipped.")
            self.assertContains(response, "Caddy: some upstream records were unsupported.")
            self.assertContains(response, "TCP reachability")

    def test_an_older_report_keeps_the_recorded_offer(self) -> None:
        server = self.register()
        self.run_worker()
        report = {
            "checked": ["Caddy"],
            "notes": [],
            "findings": [
                {
                    "name": "Caddy",
                    "version": "2.11.6",
                    "advisory": "GHSA-aaaa-bbbb-0001",
                    "url": "https://github.com/caddyserver/caddy/security/advisories/GHSA-aaaa-bbbb-0001",
                    "fixed": "2.11.8",
                    "catalog_version": "2.11.7",
                    "catalog_has_fix": False,
                }
            ],
        }
        with mock.patch.object(advisories, "check", return_value=report):
            self.submit_rendered_verification(server)
            self.run_worker()
        page = self.client.get(f"/servers/{server.pk}/security/")
        self.assertContains(page, "Upstream fix in 2.11.8.")
        self.assertContains(
            page, "The catalog offers 2.11.7. The comparison with the upstream fix is unknown."
        )

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
