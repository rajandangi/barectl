"""The operator's Jobs journey against production-built assets (#285)."""

import tempfile
from typing import override

from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.activity_testing import record_change, record_run
from operations.models import ChangeRun
from servers.models import Server

from .testing import change, record_jobs


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
        record_jobs(self.server, changes=(finished, failed))
        run = record_run(record_change(self.server, kind_slug="create_http_site"))
        ChangeRun.objects.filter(pk=run.pk).update(
            unit_name=finished.unit, invocation_id=finished.invocation_id
        )
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/jobs/")

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
        expect(page.get_by_text("Create PHP site").first).to_be_visible()
        expect(page.get_by_text("Set default PHP").first).to_be_visible()
        expect(page.get_by_text("Started on another computer").first).to_be_visible()
        expect(page.get_by_role("link", name="Open this run")).to_be_visible()
        self.assert_no_native_terms()
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 900})
        last_checked = page.locator("#jobs-last-checked time").inner_text()

        page.get_by_role("button", name="Check now").click()
        expect(page.get_by_text("Barectl queued a check")).to_be_visible()
        expect(page.get_by_text("Create PHP site").first).to_be_visible()
        expect(page.locator("#jobs-last-checked time")).to_have_text(last_checked)

        attempt = (
            DiscoveryAttempt.objects.filter(server=self.server)
            .exclude(status=DiscoveryAttempt.Status.SUCCEEDED)
            .latest("pk")
        )
        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING)
        page.reload()
        expect(page.get_by_text("checking the server now")).to_be_visible()
        expect(page.get_by_text("Create PHP site").first).to_be_visible()

        row = page.locator("li.barectl-job-row", has_text="Create PHP site").first
        row.get_by_text("Show details").click()
        expect(row.get_by_text("Result class")).to_be_visible()
        expect(row.get_by_text("Finished")).to_be_visible()
        expect(row.get_by_text("barectl-apply-" + "a" * 32)).to_be_visible()
