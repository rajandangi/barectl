"""The operator's Jobs journey against production-built assets (#285, #291)."""

import re
import tempfile
from datetime import timedelta
from typing import override
from urllib.parse import urlsplit

from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from automation.worker_status import WorkerStatus
from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.activity_testing import record_change, record_run
from operations.models import ChangeRun
from servers.models import Server

from .testing import (
    backup,
    cache,
    change,
    record_jobs,
    scheduled,
    timer,
    worker,
)
from .testing import (
    run as backup_run,
)


@tag("browser")
class JobsBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_changes", "add_discoveryattempt"):
            from django.contrib.auth.models import Permission

            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")
        Server.objects.exclude(pk=self.server.pk).delete()
        now = timezone.now()
        finished = change(
            unit="barectl-apply-" + "a" * 32 + ".service",
            invocation="1" * 32,
            kind_slug="create_http_site",
            sites=("alpha",),
            result_class="succeeded",
            started_at=now,
            finished_at=now,
        )
        failed = change(
            unit="barectl-apply-" + "b" * 32 + ".service",
            invocation="2" * 32,
            kind_slug="set_default_php",
            sites=("alpha",),
            result_class="failed",
            started_at=now,
            finished_at=now,
        )
        beta = change(
            unit="barectl-apply-" + "c" * 32 + ".service",
            invocation="3" * 32,
            kind_slug="create_http_site",
            sites=("beta",),
            result_class="succeeded",
            started_at=now - timedelta(hours=1),
            finished_at=now - timedelta(hours=1),
        )
        older = change(
            unit="barectl-apply-" + "d" * 32 + ".service",
            invocation="4" * 32,
            kind_slug="create_http_site",
            sites=("omega",),
            result_class="succeeded",
            started_at=now - timedelta(days=20),
            finished_at=now - timedelta(days=20),
        )
        record_jobs(
            self.server,
            changes=(finished, failed, beta, older),
            schedules=(scheduled(),),
            workers=(worker(identifier="beta", status=WorkerStatus.STOPPED_AFTER_CRASHES),),
            cache=(cache(),),
            backups=(
                backup(
                    runs=(
                        backup_run(at=now, offsite="failed"),
                        backup_run(
                            kind="cleanup",
                            location="onsite",
                            at=now - timedelta(minutes=5),
                            onsite=(1, 2, 0, 0),
                        ),
                    ),
                    timers=(timer(),),
                ),
            ),
        )
        run = record_run(record_change(self.server, kind_slug="create_http_site"))
        ChangeRun.objects.filter(pk=run.pk).update(
            unit_name=finished.unit, invocation_id=finished.invocation_id
        )
        # A real browser zone, so the page can name it and place Today at local midnight.
        self.context.close()
        self.open_context(width=1280, height=900, timezone_id="Europe/London")
        self.sign_in()
        # Name the zone in the URL: the page then renders it without a background exchange,
        # so a later click cannot land on a panel that a swap replaces underneath it.
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/jobs/?tz=Europe%2FLondon")
        self.page.wait_for_load_state("networkidle")

    def test_jobs_groups_details_check_and_narrow_layout(self) -> None:
        page = self.page
        nav = page.get_by_role("navigation", name="Server sections")
        expect(nav.get_by_role("link", name="Jobs", exact=True)).to_have_attribute(
            "aria-current", "page"
        )
        expect(page.get_by_role("heading", name="Needs attention", level=2)).to_be_visible()
        expect(page.get_by_role("heading", name="Running", level=2)).to_be_visible()
        expect(page.get_by_role("heading", name="Automatic work", level=2)).to_be_visible()
        expect(page.get_by_role("heading", name="Recent results", level=2)).to_be_visible()
        expect(page.locator("li.barectl-job-row", has_text="Create PHP site").first).to_be_visible()
        expect(page.locator("li.barectl-job-row", has_text="Set default PHP").first).to_be_visible()
        expect(page.get_by_text("Started on another computer").first).to_be_visible()
        expect(page.get_by_role("link", name="Open this run")).to_be_visible()
        expect(page.get_by_text("On, the last run succeeded").first).to_be_visible()
        expect(page.get_by_text("Next run").first).to_be_visible()
        expect(page.get_by_text("Object cache").first).to_be_visible()
        expect(
            page.get_by_text("Queue workers for beta stopped after repeated crashes.").first
        ).to_be_visible()
        expect(page.get_by_role("link", name="Open scheduled tasks")).to_have_attribute(
            "href",
            f"/servers/{self.server.pk}/sites/alpha/settings/#scheduled-tasks",
        )
        expect(page.get_by_text("Backup schedule").first).to_be_visible()
        expect(page.get_by_text("On", exact=True).first).to_be_visible()
        backup_row = page.locator("li.barectl-job-row", has_text="Offsite storage").first
        expect(backup_row).to_be_visible()
        expect(backup_row).to_contain_text("On this server")
        expect(backup_row).to_contain_text("Copy failed")
        expect(page.get_by_role("link", name="Open Backups").first).to_have_attribute(
            "href",
            f"/servers/{self.server.pk}/sites/alpha/backups/#backups-heading",
        )
        expect(page.get_by_text("Saved here, offsite copy failed.").first).to_be_visible()
        self.assert_no_native_terms()
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 900})

        # #291: the small entry sends the browser's IANA zone under the HTMX lifecycle.
        recent_rows = page.locator("section[aria-labelledby='jobs-recent-heading'] ul")
        expect(page.locator("#jobs-zone")).to_contain_text("Europe/London")
        expect(page).to_have_url(re.compile(r"[?&]tz=Europe"))
        self.assertNotIn("range=", page.url)
        expect(page.locator("#jobs-results-status")).to_have_attribute("role", "status")
        expect(recent_rows).to_contain_text("Create PHP site")
        expect(recent_rows).not_to_contain_text("omega")
        attempts = DiscoveryAttempt.objects.count()

        page.get_by_label("Range").select_option("30d")
        page.get_by_role("button", name="Show results").click()
        expect(page).to_have_url(re.compile(r"[?&]range=30d"))
        expect(page.locator("#jobs-zone")).to_contain_text("Europe/London")
        expect(recent_rows).to_contain_text("omega")
        expect(page.get_by_label("Range")).to_be_focused()

        page.get_by_label("Site").select_option("alpha")
        page.get_by_label("Result", exact=True).select_option("failed")
        page.get_by_role("button", name="Show results").click()
        expect(page).to_have_url(re.compile(r"[?&]site=alpha.*[?&]result=failed"))
        expect(recent_rows).not_to_contain_text("beta")
        expect(recent_rows).to_contain_text("alpha")
        expect(recent_rows.locator("p").filter(has_text="Failed")).to_have_count(1)
        expect(recent_rows.locator("p").filter(has_text="Finished")).to_have_count(0)
        expect(page.get_by_label("Result", exact=True)).to_be_focused()

        # Back and forward restore the same bookmarkable selection.
        page.go_back()
        expect(page.get_by_label("Site")).to_have_value("")
        expect(page.get_by_label("Result", exact=True)).to_have_value("")
        self.assertNotIn("work=", page.url)
        expect(page).to_have_url(re.compile(r"range=30d&tz="))
        page.go_forward()
        expect(page.get_by_label("Site")).to_have_value("alpha")
        expect(page.get_by_label("Result", exact=True)).to_have_value("failed")

        self.assertEqual(DiscoveryAttempt.objects.count(), attempts)
        paths = [urlsplit(request.url).path for request in self.requests]
        self.assertFalse(
            any(path == f"/servers/{self.server.pk}/verify/" for path in paths),
            paths,
        )

        last_checked = page.locator("#jobs-last-checked time").get_attribute("datetime")

        page.get_by_role("button", name="Check now").click()
        expect(page.get_by_text("Barectl queued a check")).to_be_visible()
        expect(page.locator("li.barectl-job-row", has_text="Create PHP site").first).to_be_visible()
        expect(page.locator("#jobs-last-checked time")).to_have_attribute(
            "datetime", last_checked or ""
        )

        attempt = (
            DiscoveryAttempt.objects.filter(server=self.server)
            .exclude(status=DiscoveryAttempt.Status.SUCCEEDED)
            .latest("pk")
        )
        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING)
        page.reload()
        expect(page.get_by_text("checking the server now")).to_be_visible()
        expect(page.locator("li.barectl-job-row", has_text="Create PHP site").first).to_be_visible()

        unit = "barectl-apply-" + "a" * 32
        row = page.locator("li.barectl-job-row", has_text=unit).first
        row.get_by_text("Show details").click()
        expect(row.get_by_text("Result class")).to_be_visible()
        expect(row.get_by_text("Finished", exact=True)).to_be_visible()
        expect(row.locator("dt", has_text="Started")).to_be_visible()
        expect(row.locator("dt", has_text="Finished")).to_be_visible()
        expect(row.get_by_text(unit)).to_be_visible()

    def test_first_visit_without_a_snapshot_explains_and_offers_one_check(self) -> None:
        DiscoveryAttempt.objects.filter(server=self.server).delete()
        page = self.page
        page.reload()
        expect(page.locator("#jobs-empty")).to_contain_text(
            "Run a check to read it for the first time"
        )
        expect(page.get_by_role("button", name="Check now")).to_have_count(1)
        page.get_by_role("button", name="Check now").click()
        expect(page.get_by_text("Barectl queued a check")).to_be_visible()
        expect(page.get_by_role("button", name="Check now")).to_have_count(0)
