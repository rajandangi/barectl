"""The Jobs page's permissions, check action, retention and query cost (#285)."""

from typing import override
from unittest import mock

from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from discovery.fakes import STALE, FakeServer, claim_task, record_attempt, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import ConnectionDefinition, Server
from servers.testing import ControllerConfigTestCase

from . import observation as observation_module
from .models import JobObservation
from .observation import ObservedChange
from .testing import (
    BOOT,
    SECRET,
    change,
    journal_shell,
    line,
    record_jobs,
    record_reading,
    result_line,
)


class JobsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        ConnectionDefinition.objects.create(
            server=self.server,
            revision=1,
            mode="alias",
            alias="web.example.com",
            address="203.0.113.10",
            username="deploy",
            port=22,
        )
        Server.objects.filter(pk=self.server.pk).update(connection_revision=1)
        self.server.refresh_from_db()
        self.url = reverse("server_jobs", args=(self.server.pk,))

    def a_finished_change(self, **values: object) -> ObservedChange:
        fields = {
            "unit": "barectl-apply-" + "a" * 32 + ".service",
            "kind_slug": "create_http_site",
            "sites": ("alpha",),
            "finished_at": timezone.now(),
        }
        fields.update(values)
        return change(**fields)  # type: ignore[arg-type]

    def test_view_server_is_needed_for_the_page(self) -> None:
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_change_rows_counts_and_details_need_view_changes(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, "may view this server but not its changes")
        self.assertNotContains(response, "Create PHP site")
        self.assertNotContains(response, "Needs attention")
        self.assertNotContains(response, "Show details")
        self.assertNotContains(response, "barectl-apply-")

    def test_a_row_and_its_details_are_plain_until_details_are_opened(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, "Last checked")
        self.assertContains(response, "Needs attention")
        self.assertContains(response, "Running")
        self.assertContains(response, "Automatic work")
        self.assertContains(response, "Recent results")
        self.assertContains(response, "Create PHP site")
        self.assertContains(response, "alpha")
        self.assertContains(response, "Finished")
        self.assertContains(response, "Show details")
        self.assertContains(response, "barectl-apply-")
        self.assertContains(response, "Result class")
        self.assertContains(response, "Started on another computer")
        self.assertNotContains(response, "No available Barectl change results.")

    def test_without_jobs_evidence_the_page_explains_how_to_begin(self) -> None:
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, "Run a check to read it for the first time")
        self.assertContains(response, "Check now")

    def test_a_server_off_the_target_stack_gets_one_sentence(self) -> None:
        from dataclasses import replace

        from bootstrap.standing import HostJudgment, Standing
        from discovery.fakes import COLLECTED, record_attempt
        from discovery.models import DiscoveryAttempt
        from discovery.snapshot import save_snapshot

        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        from sites.ui_testing import attach_current_connection

        attach_current_connection(self.server, attempt)
        save_snapshot(
            attempt,
            replace(
                COLLECTED,
                standing=HostJudgment(Standing.NOT_MANAGEABLE, ("Other stack.",), (), ()),
            ),
            timezone.now(),
        )
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, "Jobs reads only servers")
        self.assertNotContains(response, "Needs attention")
        self.assertNotContains(response, "Check now")

    def test_check_now_is_a_csrf_protected_discovery_request_that_returns_to_jobs(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        page = client.get(self.url)
        self.assertContains(page, 'name="next" value="jobs"')
        csrf = page.cookies["csrftoken"].value
        refused = client.post(reverse("server_verify", args=(self.server.pk,)), {"next": "jobs"})
        self.assertEqual(refused.status_code, 403)
        accepted = client.post(
            reverse("server_verify", args=(self.server.pk,)),
            {"next": "jobs", "csrfmiddlewaretoken": csrf},
        )
        self.assertRedirects(accepted, self.url, fetch_redirect_response=False)
        self.assertTrue(
            DiscoveryAttempt.objects.filter(
                server=self.server, status=DiscoveryAttempt.Status.QUEUED
            ).exists()
        )

    def test_check_now_needs_the_discovery_request_permission(self) -> None:
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("server_verify", args=(self.server.pk,)), {"next": "jobs"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_check_now_shows_queued_and_checking_and_keeps_the_previous_results(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post(reverse("server_verify", args=(self.server.pk,)), {"next": "jobs"})
        queued = self.client.get(self.url)
        self.assertContains(queued, "Barectl queued a check")
        self.assertContains(queued, "Create PHP site")
        self.assertContains(queued, "may be out of date")
        attempt = (
            DiscoveryAttempt.objects.filter(server=self.server)
            .exclude(status=DiscoveryAttempt.Status.SUCCEEDED)
            .latest("pk")
        )
        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING)
        checking = self.client.get(self.url)
        self.assertContains(checking, "checking the server now")
        self.assertContains(checking, "Create PHP site")
        self.assertContains(checking, "Last checked")

    def test_no_get_opens_an_ssh_connection(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        self.client.force_login(self.user)
        with (
            mock.patch("discovery.ssh.connect") as connect,
            mock.patch("discovery.ssh.connect_alias") as alias,
        ):
            self.client.get(self.url)
        connect.assert_not_called()
        alias.assert_not_called()

    def test_a_failed_check_keeps_the_previous_rows_and_says_they_may_be_stale(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        self.client.force_login(self.user)
        remote = FakeServer()
        remote.failure = "Barectl could not reach the SSH service configured for web."
        with remote.substituted():
            request_discovery(self.server, user=self.user)
            run_worker()
        response = self.client.get(self.url)
        self.assertContains(response, "Create PHP site")
        self.assertContains(response, "The latest connection check failed")
        self.assertContains(response, "may be out of date")

    def test_revoked_authority_before_publication_publishes_nothing(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        self.grant("view_server", "view_changes", "add_discoveryattempt")
        remote = FakeServer()
        permission = self.user.user_permissions.get(codename="add_discoveryattempt")

        def collected_then_revoked(*args: object, **kwargs: object) -> object:
            from discovery.observations import collect

            collected = collect(*args, **kwargs)  # type: ignore[arg-type]
            self.user.user_permissions.remove(permission)
            return collected

        with (
            remote.substituted(),
            mock.patch("discovery.services.collect", side_effect=collected_then_revoked),
        ):
            queued = request_discovery(self.server, user=self.user)
            run_worker()
        from discovery.fakes import current

        queued = DiscoveryAttempt.objects.get(pk=queued.pk)
        self.assertEqual(queued.status, DiscoveryAttempt.Status.FAILED)
        self.assertFalse(self.server.snapshots.filter(attempt=queued).exists())
        self.assertEqual(
            current(self.server).collected.jobs.value.changes[0].kind_slug, "create_http_site"
        )

    def test_an_interrupted_check_cannot_overwrite_newer_rows(self) -> None:
        record_jobs(self.server, changes=(self.a_finished_change(),))
        attempt = request_discovery(self.server)
        record_attempt(attempt, DiscoveryAttempt.Status.QUEUED, age=STALE)
        claim_task(attempt, age=STALE)
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        self.client.get(self.url)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        from discovery.fakes import current

        self.assertEqual(
            current(self.server).collected.jobs.value.changes[0].unit,
            self.a_finished_change().unit,
        )

    def test_jobs_rows_are_scoped_to_their_server_registration(self) -> None:
        other = Server.objects.create(name="Other", ssh_alias="db-1")
        record_jobs(
            self.server,
            changes=(self.a_finished_change(unit="barectl-apply-" + "c" * 32 + ".service"),),
        )
        record_jobs(
            other,
            changes=(
                self.a_finished_change(
                    unit="barectl-apply-" + "d" * 32 + ".service",
                    kind_slug="set_default_php",
                ),
            ),
        )
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, "barectl-apply-" + "c" * 32)
        self.assertNotContains(response, "barectl-apply-" + "d" * 32)

    def test_a_seeded_secret_never_reaches_rows_details_or_responses(self) -> None:
        reading = observation_module.read(
            journal_shell(
                units=BOOT + "\n",
                history="\n".join(
                    (
                        line(f"barectl-stage {SECRET}", usec=1_762_000_000_000_000),
                        line(
                            result_line(kind="create_http_site", sites=("alpha",)),
                            usec=1_762_000_000_100_000,
                        ),
                    )
                ),
            )
        )
        record_reading(self.server, reading)
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertNotIn(SECRET, response.content.decode())
        for row in JobObservation.objects.all():
            self.assertNotIn(SECRET, " ".join(str(value) for value in row.__dict__.values()))

    def test_the_read_query_count_does_not_grow_with_rows(self) -> None:
        self.grant("view_server", "view_changes")
        self.client.force_login(self.user)
        record_jobs(self.server, changes=(self.a_finished_change(),))
        with CaptureQueriesContext(connection) as one:
            self.client.get(self.url)
        record_jobs(
            self.server,
            changes=tuple(
                self.a_finished_change(unit=f"barectl-apply-{index:032x}.service")
                for index in range(5)
            ),
        )
        with CaptureQueriesContext(connection) as many:
            self.client.get(self.url)
        self.assertEqual(len(one), len(many))
