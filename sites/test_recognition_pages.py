import re
from dataclasses import replace
from typing import override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, ObservedSite, save_snapshot
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.observation import COMMON_SOURCE, PHP_TRANSITION_INCOMPLETE
from sites.recognition import CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT
from sites.ui_testing import record_shaped_sites


def rows(html: str, table_id: str) -> list[str]:
    """Each table row's visible text, whitespace collapsed; empty when the table is absent."""
    table = re.search(rf'<table[^>]*id="{table_id}".*?</table>', html, re.DOTALL)
    return [
        " ".join(re.sub(r"<[^>]+>", " ", row).split())
        for row in re.findall(r"<tr>(.*?)</tr>", table.group(0) if table else "", re.DOTALL)[1:]
    ]


ADMINISTRATION = "Correct it with ordinary administration, then run discovery again."
UNREAD = "The native site configuration could not be reconstructed."


def attention(html: str) -> list[str]:
    """Each Needs attention item's visible text, whitespace collapsed."""
    found = re.search(r'<ul[^>]*id="needs-attention".*?</ul>', html, re.DOTALL)
    return [
        " ".join(re.sub(r"<[^>]+>", " ", item).split())
        for item in re.findall(r"<li>(.*?)</li>", found.group(0) if found else "", re.DOTALL)
    ]


def pool(identifier: str, runtime: str = "php84") -> str:
    return f"/etc/php-fpm/sites/{identifier}/{runtime}/pools/{identifier}.conf {identifier}"


class ReaderFindingTests(SimpleTestCase):
    def test_recognition_follows_the_native_readers_own_findings(self) -> None:
        # Joins implicitly concatenated string literals split across lines.
        source = re.sub(r'"\s*\n\s*"', "", COMMON_SOURCE)
        for finding in (CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT):
            with self.subTest(finding=finding):
                self.assertIn(f'"{finding}"', source)


class StackRecognitionTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_shaped_sites(self.server)

    def page(self, url: str) -> str:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_web_lists_each_site_file_as_recognized_or_unsupported(self) -> None:
        html = self.page(f"/servers/{self.server.pk}/stack/?tab=web")
        self.assertEqual(
            rows(html, "site-files"),
            [
                "/etc/caddy/sites/alpha.caddy alpha Recognized",
                "/etc/caddy/sites/beta.caddy beta Recognized",
                f"/etc/caddy/sites/gamma.caddy gamma Outside supported settings {CADDY_OUTSIDE}",
                "/etc/caddy/sites/delta.caddy delta Recognized",
                f"/etc/caddy/sites/omega.caddy omega Absent {ROUTE_ABSENT}",
            ],
        )

    def test_php_runtimes_lists_each_site_pool_as_recognized_or_unsupported(self) -> None:
        html = self.page(f"/servers/{self.server.pk}/stack/?tab=php")
        self.assertEqual(
            rows(html, "site-pools"),
            [
                f"{pool('alpha')} Recognized",
                f"{pool('beta')} Outside supported settings {POOL_OUTSIDE}",
                f"{pool('gamma')} Not confirmed {CADDY_OUTSIDE}",
                f"{pool('delta', 'php85')} Not confirmed {PHP_TRANSITION_INCOMPLETE}",
                f"{pool('omega')} Not confirmed {ROUTE_ABSENT}",
            ],
        )

    def test_overview_lists_each_unsupported_item_with_one_next_action(self) -> None:
        html = self.page(f"/servers/{self.server.pk}/")
        self.assertEqual(
            attention(html),
            [
                f"Site beta {POOL_OUTSIDE} {ADMINISTRATION}",
                f"Site gamma {CADDY_OUTSIDE} {ADMINISTRATION}",
                f"Site delta {PHP_TRANSITION_INCOMPLETE} Finish the runtime change",
                f"Site omega {ROUTE_ABSENT} {ADMINISTRATION}",
                "PHP runtime php85 Master failed Inspect PHP runtimes",
            ],
        )
        server = self.server.pk
        self.assertInHTML(
            f'<a href="/servers/{server}/sites/delta/runtime/">Finish the runtime change</a>', html
        )
        self.assertInHTML(f'<a href="/servers/{server}/sites/beta/overview/">beta</a>', html)
        self.assertInHTML(
            f'<a href="/servers/{server}/stack/?tab=php">Inspect PHP runtimes</a>', html
        )


class StandingAttentionTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def overview(self, standing: HostJudgment, sites: Observation[tuple[ObservedSite, ...]]) -> str:
        collected = replace(COLLECTED, components=(), sites=sites, standing=standing)
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            collected,
            timezone.now(),
        )
        return self.client.get(f"/servers/{self.server.pk}/").content.decode()

    def test_host_findings_carry_their_next_action(self) -> None:
        unread = Observation(
            ObservationOutcome.INACCESSIBLE,
            ("/etc/caddy/sites",),
            UNREAD,
            (),
        )
        clock = "The system clock is not synchronized."
        cases = (
            (
                HostJudgment(
                    Standing.NOT_MANAGEABLE,
                    ("Another web stack is installed: nginx.",),
                    (clock,),
                    (),
                ),
                [
                    f"Host Another web stack is installed: nginx. {ADMINISTRATION}",
                    f"Host {clock} {ADMINISTRATION}",
                ],
            ),
            (
                HostJudgment(
                    Standing.INCOMPLETE_FOUNDATION,
                    (),
                    (),
                    (("Nix", "present"), ("Caddy", "incomplete"), ("journald", "missing")),
                ),
                ["Host foundation Unfinished stages: Caddy, journald. Set up server"],
            ),
        )
        for standing, expected in cases:
            with self.subTest(standing=standing.standing):
                self.assertEqual(
                    attention(self.overview(standing, unread))[: len(expected)], expected
                )
        html = self.overview(HostJudgment(Standing.TARGET_STACK, (), (), ()), unread)
        self.assertEqual(
            attention(html),
            [f"Sites {UNREAD} Inspect the unavailable evidence"],
        )
        self.assertInHTML(
            f'<a href="/servers/{self.server.pk}/advanced/">Inspect the unavailable evidence</a>',
            html,
        )
