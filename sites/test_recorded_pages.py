"""S9 and S10 as an operator sees them, rendered from the scenarios' recorded checkpoints."""

import contextlib
import re
from typing import override
from unittest import mock

from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.recorded import ReplayShell, load
from discovery.snapshot import save_snapshot
from operations.fakes import ChangeTestCase, finished_unit
from operations.models import ChangeReview, ChangeRun, Result
from operations.models import RemoteOperation as Operation
from servers.attention import ADMINISTRATION
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .bodies.common import POOL_OUTSIDE


def rows(html: str, table_id: str) -> list[str]:
    table = html[html.index(f'id="{table_id}"') :]
    table = table[: table.index("</table>")]
    return [
        " ".join(re.sub(r"<[^>]+>", " ", row).split())
        for row in re.findall(r"<tr>(.*?)</tr>", table, re.DOTALL)[1:]
    ]


class RecordedJudgeByShapePageTests(ControllerConfigTestCase):
    """docs/site-conventions.md: an unsupported pool is reported once and blocks one site."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Shape", ssh_alias="shape.example.com")
        collected = collect(ReplayShell(load("judge-by-shape-26.04")))
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def page(self, path: str) -> str:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/{path}")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_stack_recognizes_adopted_edits_and_reports_the_unsupported_pool(self) -> None:
        self.assertEqual(
            rows(self.page("stack/?tab=web"), "site-files"),
            [
                f"/etc/caddy/sites/{name}.caddy {name} Recognized"
                for name in ("s9alpha", "s9beta", "s9gamma")
            ],
        )
        pools = rows(self.page("stack/?tab=php"), "site-pools")
        self.assertEqual(len(pools), 3)
        self.assertRegex(
            pools[0], r"^/etc/php-fpm/sites/s9alpha/php8\d/pools/s9alpha\.conf s9alpha Recognized$"
        )
        self.assertRegex(
            pools[1],
            r"^/etc/php-fpm/sites/s9beta/php8\d/pools/s9beta\.conf s9beta "
            + re.escape(f"Outside supported settings {POOL_OUTSIDE}")
            + "$",
        )
        self.assertRegex(
            pools[2], r"^/etc/php-fpm/sites/s9gamma/php8\d/pools/s9gamma\.conf s9gamma Recognized$"
        )

    def test_overview_reports_the_unsupported_site_once(self) -> None:
        overview = " ".join(re.sub(r"<[^>]+>", " ", self.page("")).split())
        self.assertEqual(overview.count(POOL_OUTSIDE), 1)
        self.assertIn(f"Site s9beta {POOL_OUTSIDE} {ADMINISTRATION}", overview)
        self.assertNotIn("Site s9alpha", overview)
        self.assertNotIn("Site s9gamma", overview)

    def test_adopted_sites_offer_a_fresh_review_and_the_blocked_site_does_not(self) -> None:
        for identifier, offered in (("s9alpha", True), ("s9gamma", True), ("s9beta", False)):
            with self.subTest(site=identifier):
                html = self.page(f"sites/{identifier}/runtime/")
                self.assertEqual("Select site PHP runtime</button>" in html, offered)


class RecordedLockBusyRunTests(ChangeTestCase):
    """docs/ssh-connections.md: a run refused at the lock changed nothing and needs a new review."""

    def test_the_refused_run_from_the_race_reads_as_lock_busy_with_a_new_review(self) -> None:
        transcript = load("race-lock-busy-26.04")
        unit = next(
            match[0]
            for command, _ in transcript.commands
            if (match := re.search(r"barectl-apply-[0-9a-f]{32}\.service", command))
        )
        self.systemd.units["barectl-apply-" + "a" * 32 + ".service"] = finished_unit(1)
        review = self.change()
        self.systemd.lose_acknowledgement = True
        run = self.apply(review)
        self.assertEqual(run.status, Operation.Status.RECONCILING)
        ChangeRun.objects.filter(pk=run.pk).update(unit_name=unit, invocation_id="")
        ChangeReview.objects.filter(pk=review.pk).update(host_key=transcript.host_key)
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(transcript)),
        ):
            run = self.check(run)
        self.assertEqual(run.status, Operation.Status.FAILED)
        self.assertEqual(run.execution, Result.LOCK_BUSY)
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "The run stopped before making any requested change.")
        self.assertContains(page, "Another change held Barectl&#x27;s mutation lock")
        self.assertContains(page, "Prepare a new review after that change finishes.")
