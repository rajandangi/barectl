"""Journey: a WordPress site turns server cron on from Settings in three activations."""

import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from automation.testing import observed_worker, record_schedule, record_worker
from automation.worker_status import WorkerStatus
from dashboard.browser_testing import BrowserTestCase
from operations.models import ChangePreparation
from servers.models import Server


@tag("browser")
class ScheduledTasksBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_turning_on_server_cron_takes_three_activations_from_the_site_page(self) -> None:
        server = Server.objects.get(name="Production")
        record_schedule(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/")
        self.assert_no_native_terms()
        self.page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Settings", exact=True
        ).click()
        expect(self.page.get_by_role("heading", name="Scheduled tasks", level=2)).to_be_visible()
        self.assert_no_native_terms()
        button = self.page.get_by_role("button", name="Turn on", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Change scheduled tasks for shop", level=1)
        ).to_be_visible()
        self.assert_no_native_terms()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_wordpress_server_cron")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "shop", "state": "on"},
        )
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/settings/")
        expect(self.page.get_by_role("heading", name="Scheduled tasks", level=2)).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )


@tag("browser")
class QueueWorkersBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_starting_the_queue_workers_takes_three_activations_from_the_site_page(self) -> None:
        server = Server.objects.get(name="Production")
        record_worker(
            server,
            row=observed_worker(status=WorkerStatus.OFF, enabled=False, active_processes=0),
        )
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/")
        self.assert_no_native_terms()
        self.page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Settings", exact=True
        ).click()
        expect(self.page.get_by_role("heading", name="Queue workers", level=2)).to_be_visible()
        self.assert_no_native_terms()
        button = self.page.get_by_role("button", name="Start", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Change queue workers for shop", level=1)
        ).to_be_visible()
        self.assert_no_native_terms()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_laravel_queue_workers")
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["default"],
                "processes": 1,
                "timeout": 60,
            },
        )
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/settings/")
        expect(self.page.get_by_role("heading", name="Queue workers", level=2)).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
