"""The Logs section, its read operation and the rotation repair (Phase C #389)."""

import pathlib
import tempfile
from datetime import datetime, timedelta
from typing import cast, override
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from logs import services
from logs.change import RotationEvidence, body, review
from logs.models import LogOutcome, LogRead
from logs.read import LogLine, LogPage, scrubbed
from logs.read import command as log_command
from logs.testing import php_error_page, record_log_site
from operations.engine import BodyContext, ReviewDraft
from operations.inputs import PreparationInputs
from operations.lifecycle import OperationRefused
from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.logrotate import (
    logrotate_parse,
    logrotate_render,
    logrotate_state,
)

CANARY = "canary-log-value-9f2c1d"


class LogsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.client.force_login(self.user)

    def test_a_viewer_without_view_evidence_sees_an_explanation_not_a_404(self) -> None:
        self.grant("view_server", "view_siteobservation", "view_changes")
        record_log_site(self.server)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "logs permission")
        self.assertNotContains(response, "PHP errors")

    def test_a_site_operator_lists_every_log_and_the_wordpress_debug_only_when_present(
        self,
    ) -> None:
        self.grant("view_server", "view_siteobservation", "view_changes", "view_evidence")
        record_log_site(self.server)
        plain = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        for label in ("Visits", "PHP errors", "Slow PHP requests", "Application log"):
            self.assertContains(plain, label)
        self.assertNotContains(plain, "WordPress debug log")
        record_log_site(self.server, application="wordpress")
        wordpress = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertContains(wordpress, "WordPress debug log")

    def test_reading_a_log_is_an_explicit_post_and_a_page_get_queues_nothing(self) -> None:
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "view_evidence",
        )
        record_log_site(self.server)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/?log=php_errors")
        self.assertEqual(LogRead.objects.count(), 0)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/read/",
            {"source": "php_errors", "term": "warning"},
        )
        self.assertRedirects(
            response, f"/servers/{self.server.pk}/sites/alpha/logs/?log=php_errors"
        )
        read = LogRead.objects.get()
        self.assertEqual(read.source, "php_errors")
        self.assertEqual(read.term, "warning")
        self.assertEqual(read.status, RemoteOperation.Status.QUEUED)

    def test_a_viewer_reading_a_log_directly_is_refused(self) -> None:
        self.grant("view_server", "view_siteobservation", "view_changes")
        record_log_site(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/read/", {"source": "php_errors"}
        )
        self.assertEqual(response.status_code, 403)

    def test_a_stored_page_renders_its_lines_and_never_the_canary(self) -> None:
        from logs.bodies import read

        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "view_evidence",
        )
        root = self.enterContext(tempfile.TemporaryDirectory())
        directory = pathlib.Path(root) / "alpha" / "logs"
        directory.mkdir(parents=True)
        lines = [f"PHP notice: line {number:04d}" for number in range(601)]
        lines[550] = "PHP warning: harmless"
        lines[300] = "PHP warning: base64:" + CANARY
        (directory / "php-error.log").write_text("\n".join(lines) + "\n")
        private = pathlib.Path(root) / "alpha" / "private"
        private.mkdir()
        environment = private / "laravel.env"
        environment.write_text("APP_KEY=base64:" + CANARY + "\n")
        environment.chmod(0o600)
        stored = read.read_page("alpha", "php_errors", root=root)
        self.assertNotIn(CANARY, str(stored))
        page = LogPage.from_document(stored)
        self.assertIsNotNone(page)
        record_log_site(self.server, page=page)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(
                f"/servers/{self.server.pk}/sites/alpha/logs/?log=php_errors"
            )
        self.assertContains(response, "harmless")
        self.assertContains(response, "Load older lines")
        self.assertNotIn(CANARY, response.content.decode())
        self.assertNotIn(CANARY, str(LogRead.objects.get().page))

    def test_an_expired_page_is_not_shown_and_the_next_read_removes_the_previous_page(
        self,
    ) -> None:
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "view_evidence",
        )
        stored = record_log_site(self.server, page=php_error_page("old page"))
        self.assertIsNotNone(stored)
        stored = cast(LogRead, stored)
        stored.page_expires_at = timezone.now() - timedelta(minutes=1)
        stored.save(update_fields=["page_expires_at"])
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/?log=php_errors")
        self.assertNotContains(response, "old page")
        self.assertContains(response, "This log has not been read yet")
        self.assertEqual(LogRead.objects.get().page, {})
        record_log_site(self.server, page=php_error_page("new page"))
        self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/read/", {"source": "php_errors"}
        )
        cleared = LogRead.objects.first()
        self.assertIsNotNone(cleared)
        self.assertEqual(cast(LogRead, cleared).page, {})

    def test_discovery_reports_a_missing_rotation_without_any_log_read(self) -> None:
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "view_evidence",
        )
        record_log_site(self.server, log_rotation="missing")
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertContains(response, "Log rotation is not set up for this site yet.")
        self.assertContains(response, "Set up log rotation")

    def test_the_rotation_note_and_its_action_reach_the_logs_section(self) -> None:
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "view_evidence",
        )
        record_log_site(
            self.server,
            log_rotation="outside",
            page=LogPage(
                "observed",
                (LogLine(raw="PHP warning: harmless"),),
                rotation="outside",
                rotation_problem="The site's log rotation file is outside the supported settings.",
            ),
        )
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertContains(response, "edited outside the supported settings")
        self.assertContains(response, "Set up log rotation")
        response = self.client.post(f"/servers/{self.server.pk}/sites/alpha/logs/rotation/prepare/")
        self.assertEqual(response.status_code, 302)
        from operations.models import ChangePreparation

        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "set_up_log_rotation")
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "alpha"})


class LogReadWorkerTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.grant("view_server", "view_siteobservation", "view_changes", "view_evidence")

    def queued(self) -> LogRead:
        return LogRead.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            requested_by=self.user,
            identifier="alpha",
            source="php_errors",
        )

    def test_a_read_stores_its_page_for_twenty_four_hours(self) -> None:
        read = self.queued()
        read.status = RemoteOperation.Status.RUNNING
        read.save(update_fields=["status"])
        page = php_error_page("one", "two")
        shell = mock.MagicMock()
        shell.__enter__.return_value.host_key = "ssh-ed25519 SHA256:abc"
        with (
            mock.patch("discovery.ssh.connect_operation", return_value=shell),
            mock.patch("logs.services.log_read.read", return_value=page),
        ):
            services._read(read)
        read.refresh_from_db()
        self.assertEqual(read.status, RemoteOperation.Status.SUCCEEDED)
        self.assertEqual(read.outcome, LogOutcome.OBSERVED)
        expires = read.page_expires_at
        self.assertIsNotNone(expires)
        self.assertGreater(cast(datetime, expires), timezone.now() + timedelta(hours=23))
        self.assertEqual(read.page["lines"][0]["raw"], "one")

    def test_a_read_is_refused_when_the_account_lost_the_logs_permission(self) -> None:
        read = self.queued()
        self.user.user_permissions.clear()
        with (
            mock.patch("discovery.ssh.connect_operation") as connect,
            self.assertRaises(OperationRefused),
        ):
            services._read(read)
        connect.assert_not_called()


class RotationConventionTests(SimpleTestCase):
    def test_the_supported_file_is_rendered_and_parsed_by_shape(self) -> None:
        text = logrotate_render("alpha", ("php-error.log", "php-slow.log"))
        self.assertEqual(logrotate_parse(text, "alpha"), ("php-error.log", "php-slow.log"))
        self.assertIn("root renames and recreates", text)
        self.assertNotIn("su salpha", text)
        self.assertIn("maxsize 20M", text)
        self.assertIn("rotate 5", text)
        self.assertIn("maxage 14", text)
        self.assertIn("compress", text)
        self.assertIn("create 0640 salpha salpha", text)
        self.assertNotIn("access.json", text)
        self.assertNotIn("laravel", text)

    def test_an_edit_outside_the_supported_shape_is_not_interpreted(self) -> None:
        text = logrotate_render("alpha", ("php-error.log", "php-slow.log"))
        self.assertIsNone(logrotate_parse(text.replace("rotate 5", "rotate 9"), "alpha"))
        self.assertIsNone(logrotate_parse(text.replace("salpha", "sbeta"), "alpha"))
        self.assertIsNone(logrotate_parse(text.replace("php-slow.log", "access.json"), "alpha"))
        self.assertIsNone(logrotate_parse(text, "beta"))

    def test_the_wordpress_debug_log_joins_the_rotation_when_it_exists(self) -> None:
        text = logrotate_render("alpha", ("php-error.log", "php-slow.log", "wp-debug.log"))
        self.assertIn("wp-debug.log", text)
        self.assertEqual(
            logrotate_parse(text, "alpha"),
            ("php-error.log", "php-slow.log", "wp-debug.log"),
        )

    def test_a_missing_logrotate_package_is_reported_as_unavailable(self) -> None:
        with mock.patch("sites.bodies.logrotate.LOGROTATE_DIRECTORY", "/nonexistent"):
            state, problem, names = logrotate_state("alpha")
        self.assertEqual(state, "unavailable")
        self.assertIn("does not run logrotate", problem)
        self.assertEqual(names, ())


class RotationReviewTests(SimpleTestCase):
    def native(self, **overrides: object) -> object:
        site = {
            "identifier": "alpha",
            "names": ["alpha.example.com"],
            "runtime": "php84",
            "node_runtime": "",
            "https": True,
            "readiness": "/",
            "certificate": None,
            "pool": None,
            "account": None,
            "file": "/etc/caddy/sites/alpha.caddy",
            "state": "complete",
            "problem": "",
            "application": "plain",
            "application_version": "",
            "application_problem": "",
            "serving_form": "plain",
            "client": "",
        }
        site.update(overrides)
        return {
            "version": 1,
            "boot": "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23",
            "uptime": 500000,
            "sites": [site],
            "current_sites": ["alpha"],
            "disk_digest": "a" * 64,
            "digest": "b" * 64,
            "evidence": {},
            "next_id": 1001,
            "next_proxy_id": 1002,
            "validation": "not_requested",
            "pool_validation": "not_requested",
            "master_present": False,
        }

    def draft(
        self,
        *,
        rotation_state: str = "missing",
        present: tuple[str, ...] = ("php-error.log", "php-slow.log"),
        **overrides: object,
    ) -> ReviewDraft:
        from logs.change import RotationState

        return review(
            RotationEvidence(
                True,
                "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23",
                500000,
                RotationState(rotation_state, "", (), present),
            ),
            PreparationInputs("", "alpha"),
        )

    def test_a_missing_file_is_one_site_change_naming_every_log(self) -> None:
        draft = self.draft()
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].sites, ("alpha",))
        self.assertEqual(draft.stages, ("preflight", "publish", "verify"))
        self.assertEqual(draft.document["files"], ["php-error.log", "php-slow.log"])
        self.assertEqual(draft.current_sites, ("alpha",))

    def test_a_supported_file_is_a_review_with_nothing_to_change(self) -> None:
        draft = self.draft(rotation_state="supported")
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())
        self.assertIn("already follows", str(draft.document["note"]))

    def test_a_server_without_logrotate_is_refused_in_words(self) -> None:
        draft = self.draft(rotation_state="unavailable")
        self.assertFalse(draft.eligible)
        self.assertIn("does not run logrotate", " ".join(draft.refusals))

    def test_the_wordpress_debug_file_is_named_only_when_present(self) -> None:
        draft = self.draft(present=("php-error.log", "php-slow.log", "wp-debug.log"))
        self.assertEqual(
            draft.document["files"],
            ["php-error.log", "php-slow.log", "wp-debug.log"],
        )

    def test_the_body_revalidates_the_reviewed_file(self) -> None:
        draft = self.draft()
        native_body = body(draft.document, BodyContext("", "", 0))
        self.assertIn(b"exec python3", native_body.source)
        forged = dict(draft.document)
        forged["rotation"] = "x"
        with self.assertRaises(ValueError):
            body(forged, BodyContext("", "", 0))


class LogReadShapeTests(SimpleTestCase):
    def test_the_read_is_one_fixed_command_under_the_shared_read_lock(self) -> None:
        command = log_command("alpha", "php_errors", term="warning")
        self.assertIn("flock -s -n 9", command)
        self.assertIn("python3 -c", command)
        self.assertIn("alpha php_errors", command)

    def test_the_controller_side_scrubber_replaces_a_known_value(self) -> None:
        page = LogPage("observed", (LogLine(raw=f"PHP warning: {CANARY}"),))
        cleaned = scrubbed(page, (CANARY,))
        self.assertNotIn(CANARY, cleaned.lines[0].raw)
        self.assertIn("<secret>", cleaned.lines[0].raw)

    def test_the_publish_body_and_the_reader_share_the_supported_file(self) -> None:
        from logs.bodies import rotation
        from sites.bodies.logrotate import logrotate_render

        names = ("php-error.log", "php-slow.log", "wp-debug.log")
        self.assertEqual(
            rotation.logrotate_render("alpha", names), logrotate_render("alpha", names)
        )

    def test_a_recorded_discovery_read_maps_the_typed_rotation_state(self) -> None:
        from discovery.recorded import ReplayShell, load
        from sites import observation

        native = observation.read(
            ReplayShell(load("http-site-26.04")), "observed", "", protections=False
        )
        if native is None:
            raise AssertionError("the recorded site read is unreadable")
        sites = cast(list[object], native["sites"])
        site = observation.observed_site(cast(dict[str, object], sites[0]))
        self.assertIn(
            site.log_rotation,
            ("supported", "partial", "outside", "missing", "unavailable"),
        )

    def test_the_publish_body_is_valid_python(self) -> None:
        from logs.change import BODY_SHA256, BODY_SOURCE

        compile(BODY_SOURCE, "rotation.py", "exec")
        self.assertEqual(len(BODY_SHA256), 64)


class PermissionTests(TestCase):
    def test_the_presets_grant_log_access_to_operators_and_administrators_only(self) -> None:
        self.assertTrue(
            Group.objects.get(name="Site operator")
            .permissions.filter(codename="view_evidence")
            .exists()
        )
        self.assertTrue(
            Group.objects.get(name="Administrator")
            .permissions.filter(codename="view_evidence")
            .exists()
        )
        self.assertFalse(
            Group.objects.get(name="Viewer").permissions.filter(codename="view_evidence").exists()
        )
        self.assertTrue(
            Permission.objects.filter(
                content_type__app_label="operations", codename="view_evidence"
            ).exists()
        )
