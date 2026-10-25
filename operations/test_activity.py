"""Activity lists every check and change, newest first (docs/dashboard-workflows.md, #369)."""

import re
from datetime import timedelta
from typing import override
from unittest import mock

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.activity_testing import record_change, record_run
from operations.engine import ReviewDraft, save_review
from operations.fakes import BOOT_ID
from operations.models import ChangePreparation, ChangeRun, RemoteOperation, Result
from servers.models import Server
from servers.testing import HTMX_FRAGMENT, ControllerConfigTestCase
from sites.ui_testing import record_http_sites


class ActivityPageTests(ControllerConfigTestCase):
    """The Activity pages as requests: what each lists and who may see it."""

    web: Server
    db: Server

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.web = Server.objects.create(name="Web", ssh_alias="web.example.com")
        cls.db = Server.objects.create(name="DB", ssh_alias="stage.example.net")

    def signed_in(self, *codenames: str) -> None:
        self.grant("view_server", *codenames)
        self.client.force_login(self.user)

    def test_checks_and_changes_are_listed_newest_first_across_servers(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED, age=timedelta(hours=3))
        preparation = record_change(self.db, age=timedelta(hours=2))
        run = record_run(preparation, age=timedelta(minutes=30))
        content = self.client.get("/activity/").content.decode()
        self.assertIn("Check the connection", content)
        self.assertIn("Set up DB", content)
        self.assertIn(f'href="/runs/{run.pk}/"', content)
        self.assertLess(content.index("Set up DB"), content.index("Check the connection"))
        self.assertIn("Applied", content)

    def test_a_change_without_a_run_links_to_its_confirm_screen(self) -> None:
        self.signed_in("view_changes")
        preparation = record_change(self.web)
        content = self.client.get("/activity/").content.decode()
        self.assertIn(f'href="/changes/{preparation.pk}/"', content)
        self.assertIn("Prepared", content)

    def test_a_viewer_without_the_change_permission_sees_checks_only(self) -> None:
        self.signed_in()
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        preparation = record_change(self.web)
        content = self.client.get("/activity/").content.decode()
        self.assertIn("Check the connection", content)
        self.assertNotIn("Set up", content)
        self.assertNotIn(f"/changes/{preparation.pk}/", content)

    def test_the_server_filter_narrows_the_list_to_one_server(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.db)
        content = self.client.get("/activity/", {"server": self.db.pk}).content.decode()
        self.assertIn("Set up DB", content)
        self.assertNotIn("Check the connection", content)

    def test_the_site_filter_lists_only_that_site_s_changes(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.web, kind_slug="create_http_site", site="alpha")
        record_change(self.web, kind_slug="create_http_site", site="beta")
        content = self.client.get("/activity/", {"site": "alpha"}).content.decode()
        self.assertIn(
            f"/changes/{ChangePreparation.objects.get(inputs__identifier='alpha').pk}/", content
        )
        self.assertNotIn(
            f"/changes/{ChangePreparation.objects.get(inputs__identifier='beta').pk}/", content
        )
        # A check belongs to its server, never to a site.
        self.assertNotIn("Check the connection", content)

    def test_a_server_s_activity_lists_the_same_rows_for_that_server(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.db)
        content = self.client.get(f"/servers/{self.web.pk}/activity/").content.decode()
        self.assertIn("Check the connection", content)
        self.assertNotIn("Set up DB", content)

    def test_a_site_s_activity_lists_that_site_s_rows_from_the_same_list(self) -> None:
        record_http_sites(self.web)
        self.signed_in("view_changes", "view_siteobservation")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        alpha = record_change(self.web, kind_slug="create_http_site", site="alpha")
        beta = record_change(self.web, kind_slug="create_http_site", site="beta")
        content = self.client.get(f"/servers/{self.web.pk}/sites/alpha/activity/").content.decode()
        self.assertIn(f'href="/changes/{alpha.pk}/"', content)
        self.assertNotIn(f"/changes/{beta.pk}/", content)
        self.assertNotIn("Check the connection", content)

    def test_a_viewer_without_the_change_permission_sees_no_site_change_rows(self) -> None:
        record_http_sites(self.web)
        self.signed_in("view_siteobservation")
        preparation = record_change(self.web, kind_slug="create_http_site", site="alpha")
        content = self.client.get(f"/servers/{self.web.pk}/sites/alpha/activity/").content.decode()
        self.assertNotIn(f"/changes/{preparation.pk}/", content)
        self.assertIn("may not view change records", content)

    def test_activity_says_it_never_establishes_current_state(self) -> None:
        self.signed_in()
        self.assertContains(self.client.get("/activity/"), "never establishes")
        self.assertContains(
            self.client.get(f"/servers/{self.web.pk}/activity/"), "never establishes"
        )

    def test_opening_any_activity_page_makes_no_ssh_connection(self) -> None:
        record_http_sites(self.web)
        self.signed_in("view_changes", "view_siteobservation")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.web, kind_slug="create_http_site", site="alpha")
        with (
            mock.patch("discovery.ssh.connect", side_effect=AssertionError("used SSH")),
            mock.patch("discovery.ssh.connect_alias", side_effect=AssertionError("used SSH")),
        ):
            for url in (
                "/activity/",
                f"/servers/{self.web.pk}/activity/",
                f"/servers/{self.web.pk}/sites/alpha/activity/",
            ):
                with self.subTest(url=url):
                    self.assertEqual(self.client.get(url).status_code, 200)

    def test_the_query_count_does_not_grow_with_the_number_of_rows(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.db)
        with CaptureQueriesContext(connection) as few:
            self.client.get("/activity/")
        for _ in range(10):
            record_attempt(self.web, DiscoveryAttempt.Status.FAILED)
            record_change(self.db)
        with self.assertNumQueries(len(few)):
            self.client.get("/activity/")

    def test_activity_polls_while_a_row_is_active(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.QUEUED)
        page = self.client.get("/activity/")
        self.assertContains(page, 'hx-trigger="every 2s"')
        self.assertContains(page, 'hx-get="/activity/rows/?shown=')
        fragment = self.client.get("/activity/rows/", headers=HTMX_FRAGMENT)
        self.assertContains(fragment, "Connection check queued")

    def test_a_server_s_activity_polls_with_its_own_scope(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.QUEUED)
        page = self.client.get(f"/servers/{self.web.pk}/activity/")
        self.assertContains(page, f'hx-get="/activity/rows/?server={self.web.pk}&shown=')
        fragment = self.client.get(
            "/activity/rows/", {"server": self.web.pk}, headers=HTMX_FRAGMENT
        )
        self.assertContains(fragment, "Connection check queued")
        self.assertNotContains(fragment, "<h1>")

    def test_a_finished_list_does_not_poll(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.db)
        self.assertNotContains(self.client.get("/activity/"), "hx-trigger")

    def test_a_poll_announces_a_change_once(self) -> None:
        self.signed_in("view_changes")
        record_attempt(self.web, DiscoveryAttempt.Status.QUEUED)
        page = self.client.get("/activity/").content.decode()
        shown = re.search(r"shown=([0-9a-f]+)", page)
        if shown is None:
            self.fail("The Activity page does not carry its poll token.")
        unchanged = self.client.get(
            "/activity/rows/", {"shown": shown.group(1)}, headers=HTMX_FRAGMENT
        )
        self.assertNotContains(unchanged, "Activity updated.")
        changed = self.client.get("/activity/rows/", {"shown": "stale"}, headers=HTMX_FRAGMENT)
        self.assertContains(changed, "Activity updated.")

    def test_the_server_changes_url_redirects_to_its_activity(self) -> None:
        self.signed_in("view_changes")
        self.assertRedirects(
            self.client.get(f"/servers/{self.web.pk}/changes/"),
            f"/servers/{self.web.pk}/activity/",
        )

    def test_cleanup_of_finished_runs_is_prepared_from_advanced(self) -> None:
        self.signed_in("view_changes", "change_site")
        page = self.client.get(f"/servers/{self.web.pk}/advanced/")
        self.assertContains(page, "Clean up finished runs")
        self.assertContains(page, 'value="cleanup_runs"')
        self.assertNotContains(page, "Prepare clear finished barectl runs")


class ActivityRowTests(ControllerConfigTestCase):
    """Each recorded state in plain words, through the rows the page renders."""

    web: Server

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.web = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def row_text(self) -> str:
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        return self.client.get("/activity/").content.decode()

    def test_a_failed_run_says_failed_with_its_reason(self) -> None:
        preparation = record_change(self.web)
        record_run(
            preparation,
            status=RemoteOperation.Status.FAILED,
            execution=Result.PARTIAL,
        )
        ChangeRun.objects.filter(review__preparation=preparation).update(
            failure="The change stopped after preparing the site."
        )
        content = self.row_text()
        self.assertIn("Failed", content)
        self.assertIn("The change stopped after preparing the site.", content)

    def test_a_failed_preparation_says_failed(self) -> None:
        record_change(self.web, status=RemoteOperation.Status.FAILED)
        self.assertIn("Failed", self.row_text())

    def test_a_refused_preparation_says_refused(self) -> None:
        preparation = record_change(self.web)
        save_review(
            preparation,
            ReviewDraft(
                kind=preparation.kind_slug,
                intent="Change something on the server.",
                refusals=("The server is installing updates.",),
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        self.assertIn("Refused", self.row_text())

    def test_a_change_with_nothing_to_do_says_so(self) -> None:
        preparation = record_change(self.web)
        save_review(
            preparation,
            ReviewDraft(
                kind=preparation.kind_slug,
                intent="Change something on the server.",
                boot_id=BOOT_ID,
                uptime_centiseconds=500000,
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        self.assertIn("Nothing to change", self.row_text())

    def test_a_running_run_says_applying(self) -> None:
        preparation = record_change(self.web)
        record_run(preparation, status=RemoteOperation.Status.RUNNING, execution=Result.RUNNING)
        self.assertIn("Applying", self.row_text())

    def test_an_unknown_outcome_says_so(self) -> None:
        preparation = record_change(self.web)
        record_run(
            preparation,
            status=RemoteOperation.Status.FAILED,
            execution=Result.OUTCOME_UNKNOWN,
        )
        self.assertIn("Result unknown", self.row_text())
