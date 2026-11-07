"""The one Laravel identity from a release row, agreed by every Laravel card (spec #507)."""

from typing import override

from discovery.snapshot import current_snapshot
from servers.discovery_state import server_state
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.ui_testing import record_laravel_releases


class LaravelReleaseIdentityTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Laravel", ssh_alias="laravel.example.com")
        record_laravel_releases(self.server)

    def test_a_release_row_alone_is_the_one_laravel_identity_every_card_reads(self) -> None:
        from automation.views import context_for_site as automation_context
        from automation.worker_views import context_for_site as worker_context
        from cache.presentation import site_context as cache_context
        from laravel.settings_views import context_for_site as environment_context
        from sites.deploy_views import deploy_context

        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(snapshot.collected.settings.value, ())

        state = server_state(self.server)

        workers = worker_context(state, "alpha", self.user)
        scheduler = automation_context(state, "alpha", self.user)
        cache = cache_context(state, "alpha", self.user)
        environment = environment_context(self.server, "alpha", self.user)
        deploy = deploy_context(self.server, "alpha", self.user)

        self.assertTrue(workers["queue_workers_can_prepare"])
        self.assertTrue(scheduler["scheduled_tasks_can_prepare"])
        self.assertEqual(scheduler["scheduled_tasks_kind"], "laravel")
        self.assertTrue(cache["object_cache_applicable"])
        self.assertEqual(cache["object_cache_application"], "laravel")
        self.assertTrue(environment["environment_can_prepare"])
        self.assertTrue(deploy["deploy_can_prepare"])
        environment_page = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertEqual(environment_page.status_code, 200)
