"""One backup schedule per site: fixed units, live capture, next run and overlap (#402)."""

import base64
import gzip
import importlib.resources
import json
from datetime import UTC, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from django.test import Client
from django.utils import timezone

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

from bootstrap.standing import Standing
from discovery import ssh
from discovery.models import ObservationOutcome
from discovery.recorded import Recorded, ReplayShell, Transcript
from discovery.snapshot import Observation
from operations import engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from servers.models import Server

from . import convention, observation, presentation, schedule
from .testing import record_backups, record_schedule, result

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
CANARY = "barectl-canary-schedule-4a7e"


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


ObservedSchedule = schedule.ObservedBackupSchedule


def recorded(identifier: str = IDENTIFIER) -> tuple[ObservedSchedule, ReplayShell]:
    text = fixture("systemd-backup-schedule.json")
    command = schedule.observe_command((identifier,))
    shell = ReplayShell(
        Transcript(
            "backup-schedule",
            {},
            "26.04",
            "x86_64",
            "ssh-ed25519 SHA256:x",
            (
                ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                (command, Recorded(ssh.CommandResult(0, text))),
            ),
        )
    )
    rows = schedule.read(shell, (identifier,))
    if rows is None:
        raise AssertionError("The recorded backup schedule was refused.")
    return rows[0], shell


def site_record(**values: object) -> dict[str, object]:
    return {
        "identifier": IDENTIFIER,
        "names": [f"{IDENTIFIER}.test"],
        "runtime": "php84",
        "https": True,
        "readiness": "/",
        "application": "plain",
        "serving_form": "plain",
        "state": "complete",
        "problem": "",
        "account": [1001, 1001, f"/var/www/{IDENTIFIER}", "/usr/sbin/nologin", [1001]],
        **values,
    }


def backup_row(*, enabled: bool = True, database: bool = True) -> observation.ObservedBackup:
    return observation.ObservedBackup(
        IDENTIFIER,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1" if enabled else "",
        enabled,
        enabled,
        (),
        database,
        "" if database else "This site has no site database.",
        None,
    )


def evidence(
    *,
    schedules: tuple[ObservedSchedule, ...] = (),
    enabled: bool = True,
    database: bool = True,
    current: str = "alpha",
) -> schedule.ScheduleEvidence:
    return schedule.ScheduleEvidence(
        standing=Standing.TARGET_STACK,
        site=site_record(),
        backup=backup_row(enabled=enabled, database=database),
        schedules=schedules,
        engine="mariadb",
        database=database,
        database_problem="" if database else "This site has no site database.",
        current_sites=(current,),
        boot_id=BOOT,
        uptime_centiseconds=100,
    )


class FixedUnitTests(ChangeTestCase):
    def test_a_daily_schedule_is_a_fixed_utc_timer_with_no_catch_up(self) -> None:
        timer = convention.render_schedule_timer(IDENTIFIER, "daily", "03:00")
        self.assertIn("OnCalendar=*-*-* 03:00:00 UTC", timer)
        self.assertIn("AccuracySec=1s", timer)
        self.assertIn("RandomizedDelaySec=0", timer)
        self.assertIn("Persistent=false", timer)
        self.assertIn("DeferReactivation=yes", timer)
        service = convention.render_schedule_service(IDENTIFIER)
        self.assertIn("TimeoutStartSec=2h", service)
        self.assertIn("Slice=barectl-site-alpha-backup.slice", service)
        self.assertIn(convention.schedule_script(IDENTIFIER), service)
        self.assertIn(convention.schedule_payload(IDENTIFIER), service)
        self.assertNotIn("barectl-site-alpha.slice", service)

    def test_the_staged_schedule_and_read_sources_compile(self) -> None:
        compile(schedule.BODY_SOURCE, "backup-schedule-body", "exec")
        compile(schedule.OBSERVE_SOURCE, "backup-schedule-read", "exec")

    def test_a_weekly_schedule_runs_on_monday_utc(self) -> None:
        self.assertIn(
            "OnCalendar=Mon *-*-* 04:30:00 UTC",
            convention.render_schedule_timer(IDENTIFIER, "weekly", "04:30"),
        )

    def test_the_recorded_schedule_is_reconstructed_with_its_next_run(self) -> None:
        row, _shell = recorded()
        self.assertTrue(row.configured)
        self.assertEqual(row.frequency, "daily")
        self.assertEqual(row.at, "03:00")
        self.assertEqual(row.scope, "database")
        self.assertTrue(row.timer_active)
        self.assertTrue(row.timer_enabled)
        next_at = row.next_at
        if next_at is None:
            self.fail("Systemd's next run was not read.")
        self.assertEqual(next_at.tzinfo, UTC)

    def test_a_hand_edited_timer_is_outside_supported_settings(self) -> None:
        text = fixture("systemd-backup-schedule.json")
        document = json.loads(text)
        document["sites"][0]["units"]["timer"] = document["sites"][0]["units"]["timer"].replace(
            "03:00:00", "04:00:00"
        )
        command = schedule.observe_command((IDENTIFIER,))
        shell = ReplayShell(
            Transcript(
                "backup-schedule-edited",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (command, Recorded(ssh.CommandResult(0, json.dumps(document)))),
                ),
            )
        )
        rows = schedule.read(shell, (IDENTIFIER,))
        if rows is None:
            self.fail("The edited schedule was not read.")
        self.assertIn("changed outside Barectl", rows[0].problem)

    def test_a_new_site_starts_with_no_schedule(self) -> None:
        document = json.loads(fixture("systemd-backup-schedule.json"))
        row = document["sites"][0]
        row["units"] = dict.fromkeys(("slice", "service", "timer"))
        row["payload"] = None
        row["script"] = None
        row["show"] = dict.fromkeys(("slice", "service", "timer"))
        row["timers"] = []
        command = schedule.observe_command((IDENTIFIER,))
        shell = ReplayShell(
            Transcript(
                "backup-schedule-new",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (command, Recorded(ssh.CommandResult(0, json.dumps(document)))),
                ),
            )
        )
        rows = schedule.read(shell, (IDENTIFIER,))
        if rows is None:
            self.fail("The empty schedule was not read.")
        self.assertFalse(rows[0].installed)
        self.assertEqual(rows[0].problem, "")
        self.assertEqual(schedule._next_label(rows[0]), "")


class ReviewTests(ChangeTestCase):
    def test_a_daily_schedule_is_site_consent_and_stages_a_fixed_body(self) -> None:
        draft = schedule.review(
            evidence(),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:00",
                scope="full",
            ),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        body = schedule.body(draft.document, BodyContext("unit", BOOT, 0))
        self.assertTrue(body.source)
        self.assertEqual(len(body.arguments), 1)
        payload = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        self.assertEqual(payload["scope"], "full")
        self.assertEqual(payload["units"], dict.fromkeys(("slice", "service", "timer"), "absent"))
        self.assertNotIn("RESTIC_PASSWORD=", json.dumps(payload))
        self.assertNotIn(CANARY, json.dumps(payload))

    def test_an_overlapping_window_is_refused_with_the_next_free_slot(self) -> None:
        other = ObservedSchedule(
            "beta",
            frequency="daily",
            at="03:00",
            scope="database",
            installed=True,
            units=dict.fromkeys(("slice", "service", "timer"), "a" * 64),
        )
        draft = schedule.review(
            evidence(schedules=(ObservedSchedule(IDENTIFIER), other)),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:30",
                scope="full",
            ),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("Choose 04:30 UTC", " ".join(draft.refusals))

    def test_the_next_run_is_never_invented(self) -> None:
        draft = schedule.review(
            evidence(),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:00",
                scope="full",
            ),
        )
        details = {
            str(row["label"]): str(row["value"])
            for row in cast(list[dict[str, object]], draft.document["details"])
        }
        self.assertEqual(details["Next run"], "Systemd has not reported it yet.")

    def test_a_hand_edited_schedule_blocks_only_its_own_backup_changes(self) -> None:
        broken = ObservedSchedule(
            IDENTIFIER,
            installed=True,
            problem="The backup schedule was changed outside Barectl.",
            units=dict.fromkeys(("slice", "service", "timer"), "a" * 64),
        )
        draft = schedule.review(
            evidence(schedules=(broken,)),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="off",
                backup_schedule=True,
            ),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("changed outside Barectl", " ".join(draft.refusals))

    def test_a_forged_schedule_document_is_refused(self) -> None:
        draft = schedule.review(
            evidence(),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:00",
                scope="full",
            ),
        )
        for key, value in (
            ("repository", "/var/lib/barectl-backups/other/onsite"),
            ("at", "25:00"),
            ("scope", "everything"),
            ("units", {"slice": "absent", "service": "absent", "timer": "not-a-digest"}),
        ):
            with self.subTest(key=key):
                forged = dict(draft.document)
                forged[key] = value
                with self.assertRaises(ValueError):
                    schedule.body(forged, BodyContext("unit", BOOT, 0))

    def test_a_database_schedule_without_a_site_database_is_refused(self) -> None:
        draft = schedule.review(
            evidence(database=False),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:00",
                scope="database",
            ),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("no site database", " ".join(draft.refusals))


class AdmissionTests(ChangeTestCase):
    def test_every_change_treats_a_running_backup_unit_as_busy_for_its_site(self) -> None:
        steps = engine._backup_step(
            cast(ChangeReview, SimpleNamespace(affected_sites=["alpha", "beta"]))
        )
        text = "\n".join(steps)
        self.assertIn("/sys/fs/cgroup/system.slice/barectl-site-alpha-backup.service", text)
        self.assertIn("/sys/fs/cgroup/system.slice/barectl-site-beta-backup.service", text)
        self.assertIn("active_backup", text)


class SiteListTests(ChangeTestCase):
    def test_a_site_without_a_complete_point_in_48_hours_is_marked(self) -> None:
        recent = observation.ObservedBackup(
            "alpha",
            "/nix/store/x-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            observation.BackupResult(
                "succeeded",
                "",
                "database",
                "scheduled",
                timezone.now().isoformat(),
                "0123456789abcdef",
                1,
                4096,
            ),
        )
        old = observation.ObservedBackup(
            "beta",
            "/nix/store/x-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            observation.BackupResult(
                "succeeded",
                "",
                "database",
                "scheduled",
                (timezone.now() - timedelta(hours=49)).isoformat(),
                "fedcba9876543210",
                1,
                4096,
            ),
        )
        collected = SimpleNamespace(
            backups=Observation(ObservationOutcome.OBSERVED, (), "", (recent, old))
        )
        self.assertEqual(schedule.recent_missing(collected), {"beta"})

    def test_the_sites_page_marks_a_site_without_a_recent_backup(self) -> None:
        old = observation.BackupResult(
            "succeeded",
            "",
            "database",
            "scheduled",
            (timezone.now() - timedelta(hours=49)).isoformat(),
            "0123456789abcdef",
            1,
            4096,
        )
        record_backups(self.server, identifier="shop", enabled=True, last=old)
        self.sign_in_with("view_server", "view_siteobservation")
        page = self.client.get("/sites/")
        self.assertContains(page, "No recent backup.")

    def test_a_skip_is_never_shown_as_saved(self) -> None:
        backup = observation.ObservedBackup(
            "alpha",
            "/nix/store/x-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            observation.BackupResult(
                "lock_busy",
                "backup_lock",
                "full",
                "scheduled",
                timezone.now().isoformat(),
                "",
                0,
                0,
            ),
        )
        view = presentation.last_view(backup)
        if view is None:
            self.fail("No wording.")
        self.assertEqual(view.headline, "The backup was skipped.")
        self.assertNotIn("saved", view.headline.lower())


class SchedulePageTests(ChangeTestCase):
    def store(self) -> Server:
        server = self.server
        record_backups(server, identifier="shop", enabled=True, last=result())
        record_schedule(server, identifier="shop")
        self.sign_in_with(
            "view_server",
            "view_changes",
            "view_siteobservation",
            "change_site",
            "change_shared",
            "manage_secrets",
        )
        return server

    def test_the_page_shows_the_schedule_and_next_run_without_ssh(self) -> None:
        server = self.store()
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Daily at 03:00 UTC")
        self.assertContains(page, "Next run:")
        self.assertEqual(self.remote.commands, [])

    def test_preparing_a_schedule_queues_the_reviewed_kind(self) -> None:
        server = self.store()
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/schedule/prepare/",
            {
                "state": "on",
                "frequency": "weekly",
                "at": "04:30",
                "scope": "full",
            },
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, schedule.SLUG)
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "state": "on",
                "frequency": "weekly",
                "at": "04:30",
                "scope": "full",
                "offsite": False,
            },
        )

    def test_turning_the_schedule_off_is_its_own_review(self) -> None:
        server = self.store()
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/schedule/prepare/",
            {"state": "off"},
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, schedule.SLUG)
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "shop", "state": "off"})

    def test_an_invalid_utc_time_is_refused_before_any_query(self) -> None:
        server = self.store()
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/schedule/prepare/",
            {"state": "on", "frequency": "daily", "at": "25:00", "scope": "full"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())


class AppliedScheduleTests(ChangeTestCase):
    def review(self) -> ChangeReview:
        draft: ReviewDraft = schedule.review(
            evidence(),
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at="03:00",
                scope="full",
            ),
        )
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=schedule.SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1, "identifier": IDENTIFIER, "state": "on"},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.SITE,
            affected_sites=[IDENTIFIER],
            effects=[
                {"scope": "site", "text": "Set the backup schedule.", "sites": [IDENTIFIER]},
            ],
            ssh_alias=self.server.ssh_alias,
            host_key=self.remote.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )

    def apply_review(
        self, review: ChangeReview, data: dict[str, str]
    ) -> _MonkeyPatchedWSGIResponse:
        return self.client.post(f"/changes/{review.preparation_id}/apply/", data)

    def test_site_consent_cannot_apply_a_shared_change(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared")
        response = self.apply_review(review, {})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_an_apply_needs_csrf(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_forged_document_never_reaches_ssh(self) -> None:
        review = self.review()
        ChangeReview.objects.filter(pk=review.pk).update(
            document={**review.document, "repository": "/var/lib/barectl-backups/other/onsite"}
        )
        self.sign_in_with("view_changes", "change_site")
        self.apply_review(review, {})
        run = ChangeRun.objects.get(review=review)
        self.remote.commands.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertEqual(self.remote.commands, [])

    def test_a_site_consent_review_can_be_applied(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site")
        response = self.apply_review(review, {})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ChangeRun.objects.filter(review=review).exists())
