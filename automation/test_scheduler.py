"""The Laravel scheduler: review, refusals, duplicates, body order and projection."""

import base64
import gzip
import json
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase, TestCase

from automation import convention, observation, scheduler
from automation.bodies import scheduler as body
from automation.duplicates import (
    schedule_crontab_problem,
    schedule_supervisor_problem,
)
from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from automation.testing import (
    automation,
    installed_units,
    native_state,
    record_laravel_schedule,
    schedule,
    show,
    site_record,
)
from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import (
    ObservedSite,
    SiteAccount,
    current_snapshot,
)
from discovery.ssh import CommandResult
from operations.engine import BodyContext, NativeBody
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.common import SITE_GATED, SiteRecord

ON = PreparationInputs("", "shop", schedule_state="on")
OFF = PreparationInputs("", "shop", schedule_state="off")
RUN = PreparationInputs("", "shop", schedule_state="run")
CURRENT = "abcdef0-0123456789abcdef"


def laravel(*, state: str = "complete", current: str = CURRENT) -> dict[str, object]:
    return {
        "identifier": "shop",
        "application": "laravel",
        "current": current,
        "repository": "https://example.com/shop.git",
        "branch": "main",
        "php_requirement": "",
        "repository_problem": "",
        "releases": [
            {
                "name": current,
                "commit": "abcdef0123456789",
                "created": 1,
                "state": state,
                "repository": "https://example.com/shop.git",
                "branch": "main",
            }
        ]
        if current
        else [],
        "shared": {"environment": True, "storage": True, "cache": True},
        "environment": [],
        "deploy_key": "",
        "host_keys": True,
        "problem": "",
    }


def inventory(row: dict[str, object] | None = None) -> dict[str, object]:
    return {"version": 1, "sites": [row if row is not None else laravel()]}


def evidence(
    *,
    standing: Standing = Standing.TARGET_STACK,
    site: SiteRecord | None = None,
    laravel_row: dict[str, object] | None = None,
    automation_row: dict[str, object] | None = None,
    pending: tuple[str, ...] | None = (),
) -> scheduler.SchedulerEvidence:
    return scheduler.SchedulerEvidence(
        standing,
        site if site is not None else site_record(application="laravel", uid=1001),
        inventory(laravel_row),
        automation_row if automation_row is not None else automation(units=[]),
        pending,
        str(native_state()["boot"]),
        500000,
    )


def installed_schedule() -> list[dict[str, str]]:
    return installed_units(role=convention.ROLE_SCHEDULE)


def running_service() -> dict[str, str]:
    return show(
        load="loaded",
        enabled="static",
        result="success",
        start="@1761393600",
        exit_time="@1761393605",
        group="/system.slice/barectl-site-shop.slice/barectl-site-shop-schedule.service",
    )


def armed_timer() -> dict[str, str]:
    return show(
        load="loaded",
        active="active",
        sub_state="waiting",
        enabled="enabled",
        last_trigger="@1761393600",
        next_elapse="@1761393660",
        group="/system.slice/barectl-site-shop.slice/barectl-site-shop-schedule.timer",
    )


def installed_automation() -> dict[str, object]:
    return automation(
        units=installed_schedule(),
        schedule_service=running_service(),
        schedule_timer=armed_timer(),
    )


class ReviewTests(SimpleTestCase):
    def test_turning_on_is_one_site_change_that_installs_the_reviewed_units(self) -> None:
        draft = scheduler.review(evidence(), ON)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].sites, ("shop",))
        self.assertEqual(draft.stages, scheduler.ON_STAGES)
        self.assertEqual(
            draft.document["units"], dict.fromkeys(("slice", "service", "timer"), "absent")
        )
        self.assertEqual(draft.document["run_wait_seconds"], scheduler.RUN_NOW_WAIT_SECONDS)
        self.assertEqual(draft.current_sites, ("shop",))
        self.assertIn("shop", draft.sites_read)
        self.assertEqual(draft.boot_id, native_state()["boot"])
        details = cast(list[dict[str, str]], draft.document["details"])
        self.assertTrue(
            any("one hour" in detail["value"].lower() for detail in details),
            details,
        )

    def test_turning_off_is_available_on_a_gated_partly_deployed_site(self) -> None:
        site = site_record(application="laravel", state="partial", problem=SITE_GATED)
        draft = scheduler.review(
            evidence(
                site=site,
                automation_row=installed_automation(),
                pending=None,
            ),
            OFF,
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.stages, scheduler.OFF_STAGES)
        self.assertEqual(len(draft.effects), 1)
        self.assertLess(draft.stages.index("install"), draft.stages.index("verify"))

    def test_run_now_is_one_site_change_with_no_unit_change(self) -> None:
        draft = scheduler.review(evidence(automation_row=installed_automation()), RUN)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.stages, scheduler.RUN_STAGES)
        self.assertEqual(draft.stages, ("preflight", "run", "verify"))
        self.assertEqual(len(draft.effects), 1)
        self.assertIn("once now", draft.effects[0].text)

    def test_run_now_needs_an_installed_scheduler(self) -> None:
        draft = scheduler.review(evidence(automation_row=automation(units=[])), RUN)
        self.assertFalse(draft.eligible)
        self.assertIn("Turn on the scheduler before running it now.", draft.refusals)

    def test_a_hand_made_scheduler_blocks_turning_on_and_run_now_is_not_affected(self) -> None:
        duplicate = "A hand-made crontab entry already runs the scheduler for this site."
        blocked = scheduler.review(
            evidence(automation_row=automation(units=[], schedule_duplicate=duplicate)), ON
        )
        run = scheduler.review(
            evidence(
                automation_row=automation(
                    units=installed_schedule(),
                    schedule_service=running_service(),
                    schedule_timer=armed_timer(),
                    schedule_duplicate=duplicate,
                )
            ),
            RUN,
        )
        self.assertFalse(blocked.eligible)
        self.assertIn(duplicate, blocked.refusals)
        self.assertTrue(run.eligible, run.refusals)

    def test_pending_migrations_gate_against_or_refuse_every_start(self) -> None:
        pending = ("2026_10_19_000002_create_fixture_notes",)
        for state in (ON, RUN):
            with self.subTest(state=state):
                row = installed_automation() if state == RUN else automation(units=[])
                draft = scheduler.review(evidence(automation_row=row, pending=pending), state)
                self.assertFalse(draft.eligible)
                self.assertIn(
                    "The site has pending migrations. Deploy it before running scheduled tasks.",
                    draft.refusals,
                )
        off = scheduler.review(
            evidence(automation_row=installed_automation(), pending=pending), OFF
        )
        self.assertTrue(off.eligible, off.refusals)

    def test_unreadable_migrations_refuse_starting(self) -> None:
        draft = scheduler.review(evidence(pending=None), ON)
        self.assertFalse(draft.eligible)
        self.assertIn("Barectl could not read the site's migration state.", draft.refusals)

    def test_a_partly_deployed_release_or_site_is_refused(self) -> None:
        partial_release = scheduler.review(evidence(laravel_row=laravel(state="partial")), ON)
        partial_site = scheduler.review(
            evidence(site=site_record(application="laravel", state="partial")), ON
        )
        for draft in (partial_release, partial_site):
            self.assertFalse(draft.eligible)
        self.assertIn("The site's current release is not complete.", partial_release.refusals)
        self.assertIn("The site is not deployed completely and verified.", partial_site.refusals)

    def test_a_gate_refuses_starting_with_the_reason(self) -> None:
        gated = site_record(application="laravel", problem=SITE_GATED)
        draft = scheduler.review(evidence(site=gated), ON)
        self.assertFalse(draft.eligible)
        self.assertIn(
            "The site is in maintenance. Finish the change in progress before running "
            "scheduled tasks.",
            draft.refusals,
        )

    def test_a_non_laravel_site_or_no_current_release_is_refused(self) -> None:
        plain_row = {**laravel(), "application": "plain", "current": ""}
        plain = scheduler.review(
            evidence(site=site_record(application="plain"), laravel_row=plain_row), ON
        )
        no_release = scheduler.review(evidence(laravel_row=laravel(current=""), pending=()), ON)
        self.assertIn("This site is not a Laravel application.", plain.refusals)
        self.assertIn("Deploy this site before turning on its scheduler.", no_release.refusals)

    def test_a_repeated_review_of_an_on_scheduler_proposes_nothing(self) -> None:
        draft = scheduler.review(evidence(automation_row=installed_automation()), ON)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already on", str(draft.document["note"]))

    def test_a_repeated_review_of_an_off_scheduler_proposes_nothing(self) -> None:
        draft = scheduler.review(evidence(automation_row=automation(units=[])), OFF)
        self.assertTrue(draft.no_changes)
        self.assertIn("already off", str(draft.document["note"]))

    def test_an_unsupported_hand_edit_blocks_the_change(self) -> None:
        edited = installed_schedule()
        edited[1] = {
            **edited[1],
            "text": edited[1]["text"].replace("User=sshop", "User=root"),
        }
        draft = scheduler.review(evidence(automation_row=automation(units=edited)), ON)
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("changed outside Barectl" in refusal for refusal in draft.refusals),
            draft.refusals,
        )

    def test_unreadable_automation_blocks_the_change(self) -> None:
        missing = scheduler.SchedulerEvidence(
            Standing.TARGET_STACK,
            site_record(application="laravel", uid=1001),
            inventory(),
            None,
            (),
            str(native_state()["boot"]),
            500000,
        )
        draft = scheduler.review(missing, ON)
        self.assertFalse(draft.eligible)
        self.assertIn("The site's scheduled tasks could not be read.", draft.refusals)

    def test_a_non_target_host_is_refused(self) -> None:
        draft = scheduler.review(evidence(standing=Standing.NOT_MANAGEABLE), ON)
        self.assertIn(
            "Set up and verify the host foundation before changing a site.",
            draft.refusals,
        )


class PendingMigrationTests(SimpleTestCase):
    class Shell:
        host_key = "host"

        def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
            del stdin
            if command == "id -u":
                return CommandResult(0, "0\n")
            if "SELECT migration FROM migrations" in command:
                return CommandResult(0, "2026_10_19_000001_create_fixture_widgets\n")
            if "database/migrations" in command:
                return CommandResult(
                    0,
                    "2026_10_19_000001_create_fixture_widgets.php\n"
                    "2026_10_19_000002_create_fixture_notes.php\n",
                )
            return CommandResult(0, "")

    def test_the_release_migrations_are_compared_with_the_database(self) -> None:
        pending = scheduler._pending_migrations(
            self.Shell(), "shop", site_record(application="laravel"), inventory()
        )
        self.assertEqual(pending, ("2026_10_19_000002_create_fixture_notes",))


class DocumentTests(SimpleTestCase):
    def reviewed(self) -> tuple[dict[str, object], NativeBody]:
        draft = scheduler.review(evidence(), ON)
        return draft.document, scheduler.body(draft.document, BodyContext("unit", "boot", 0))

    def test_the_body_carries_only_the_reviewed_non_secret_selection(self) -> None:
        _document, native = self.reviewed()
        self.assertEqual(len(native.arguments), 1)
        payload = json.loads(gzip.decompress(base64.b64decode(native.arguments[0])))
        self.assertEqual(
            set(payload),
            {"version", "identifier", "state", "uid", "gid", "units", "run_wait_seconds"},
        )
        self.assertEqual(payload["state"], "on")
        self.assertNotIn("details", payload)
        self.assertFalse(native.source.endswith(b"\n"))
        self.assertLessEqual(len(native.source), 192 * 1024)

    def test_a_forged_or_truncated_document_is_refused(self) -> None:
        draft = scheduler.review(evidence(), ON)
        for field in ("version", "identifier", "state", "uid", "gid", "units", "run_wait_seconds"):
            with self.subTest(field=field):
                forged = {key: value for key, value in draft.document.items() if key != field}
                with self.assertRaises(ValueError):
                    scheduler.body(forged, BodyContext("unit", "boot", 1))
        for forged in (
            {**draft.document, "state": "maybe"},
            {**draft.document, "run_wait_seconds": 5000},
        ):
            with self.assertRaises(ValueError):
                scheduler.body(forged, BodyContext("unit", "boot", 1))

    def test_the_assembled_body_is_valid_python_and_the_reviewed_size(self) -> None:
        compile(scheduler.BODY_SOURCE, "<scheduler-body>", "exec")
        self.assertLessEqual(len(scheduler.BODY_BYTES), 192 * 1024)


class BodyOrderTests(SimpleTestCase):
    def value(self, state: str) -> SimpleNamespace:
        return SimpleNamespace(
            identifier="shop",
            state=state,
            uid=1001,
            gid=1001,
            units=dict.fromkeys(("slice", "service", "timer"), "absent"),
            run_wait_seconds=1500,
        )

    def patched(self, outcome: str = "success") -> tuple[list[str], dict[str, object]]:
        order: list[str] = []

        def note(name: str) -> None:
            order.append(name)

        def result(value: str, reason: str = "") -> None:
            del reason
            note(f"result:{value}")

        def start(*_args: object) -> str:
            note("start-service")
            return outcome

        patches: dict[str, object] = {
            "publish_units": lambda *args: note("publish"),
            "daemon_reload": lambda: note("reload"),
            "enable_timer": lambda name: note("start-timer"),
            "timer_ready": lambda *args: True,
            "disable_and_stop": lambda *args: note("stop"),
            "remove_units": lambda *args: note("remove-units"),
            "unit_digests": lambda *args: dict.fromkeys(("slice", "service", "timer"), "absent"),
            "load_state": lambda *args: "loaded",
            "start_and_wait": start,
            "stage": lambda name: note(f"stage:{name}"),
            "result": result,
        }
        return order, patches

    def apply_patches(self, patches: dict[str, object]) -> ExitStack:
        stack = ExitStack()
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(body, name, value))
        return stack

    def test_turning_on_publishes_and_starts_the_timer(self) -> None:
        order, patches = self.patched()
        with self.apply_patches(patches):
            body._turn_on(self.value("on"))
        self.assertLess(order.index("publish"), order.index("reload"))
        self.assertLess(order.index("reload"), order.index("start-timer"))
        self.assertIn("result:succeeded", order)

    def test_turning_off_stops_before_it_removes_the_units(self) -> None:
        order, patches = self.patched()
        patches["load_state"] = lambda *args: "not-found"
        with self.apply_patches(patches):
            body._turn_off(self.value("off"))
        self.assertLess(order.index("stop"), order.index("remove-units"))
        self.assertIn("result:succeeded", order)

    def test_run_now_starts_the_installed_service_and_never_the_timer(self) -> None:
        order, patches = self.patched()
        with self.apply_patches(patches):
            body._run_now(self.value("run"))
        self.assertIn("start-service", order)
        self.assertNotIn("publish", order)
        self.assertNotIn("start-timer", order)
        self.assertIn("result:succeeded", order)

    def test_a_failed_or_still_running_run_is_reported_not_success(self) -> None:
        for outcome, _reason in (
            ("exit-code", "automation_run"),
            ("running", "automation_running"),
        ):
            with self.subTest(outcome=outcome):
                order, patches = self.patched(outcome)
                with self.apply_patches(patches):
                    body._run_now(self.value("run"))
                self.assertNotIn("result:succeeded", order)
                self.assertIn("result:partial", order)


class DuplicateTests(SimpleTestCase):
    def test_a_schedule_run_crontab_line_names_the_site_or_the_own_account(self) -> None:
        own = "* * * * * /var/www/shop/bin/php /var/www/shop/current/artisan schedule:run"
        root_named = (
            "* * * * * sshop /var/www/shop/bin/php /var/www/shop/current/artisan schedule:run"
        )
        other = "* * * * * /var/www/other/bin/php /var/www/other/current/artisan schedule:run"
        self.assertTrue(schedule_crontab_problem(own, "shop", own_crontab=True))
        self.assertTrue(schedule_crontab_problem(root_named, "shop", own_crontab=False))
        self.assertEqual(schedule_crontab_problem(other, "shop", own_crontab=False), "")
        self.assertEqual(
            schedule_crontab_problem("# schedule:run for shop", "shop", own_crontab=False),
            "",
        )

    def test_a_supervisor_program_running_schedule_run_is_a_duplicate(self) -> None:
        text = "[program:shop-scheduler]\ncommand=/var/www/shop/current/artisan schedule:run\n"
        self.assertIn(
            "Supervisor",
            schedule_supervisor_problem(text, "shop"),
        )
        self.assertEqual(
            schedule_supervisor_problem("[program:shop]\ncommand=/bin/true\n", "shop"), ""
        )


class ProjectionTests(SimpleTestCase):
    def site(self) -> ObservedSite:
        return ObservedSite(
            "shop",
            ("shop.example.com",),
            "php84",
            SiteAccount(1001, 1001, "/var/www/shop", "/usr/sbin/nologin"),
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file="/etc/caddy/sites/shop.caddy",
            application="laravel",
        )

    def plain(self) -> ObservedSite:
        return replace(self.site(), application="plain")

    def projected(self, native: dict[str, object]) -> ObservedSchedule:
        rows = observation.observations(native, sites=(self.site(),), disable_wp_cron={})
        if rows is None:
            self.fail("The projection was built.")
        return rows[0]

    def test_a_laravel_site_projects_its_schedule_role(self) -> None:
        row = self.projected(
            automation(
                units=installed_schedule(),
                schedule_service=running_service(),
                schedule_timer=armed_timer(),
            )
        )
        self.assertEqual(row.role, convention.ROLE_SCHEDULE)
        self.assertEqual(row.status, ScheduleStatus.SUCCEEDED)

    def test_a_tick_spanning_a_calendar_elapse_is_skipped_never_success(self) -> None:
        service = show(
            load="loaded",
            enabled="static",
            result="success",
            start="@1761393600",
            exit_time="@1761393720",
            group="/system.slice/barectl-site-shop.slice/barectl-site-shop-schedule.service",
        )
        row = self.projected(
            automation(
                units=installed_schedule(),
                schedule_service=service,
                schedule_timer=armed_timer(),
            )
        )
        self.assertEqual(row.status, ScheduleStatus.SKIPPED)
        self.assertNotEqual(row.status, ScheduleStatus.SUCCEEDED)

    def test_a_timed_out_tick_is_distinct_from_success(self) -> None:
        service = show(
            load="loaded",
            enabled="static",
            result="timeout",
            start="@1761393600",
            exit_time="@1761397200",
            group="/system.slice/barectl-site-shop.slice/barectl-site-shop-schedule.service",
        )
        row = self.projected(
            automation(
                units=installed_schedule(),
                schedule_service=service,
                schedule_timer=armed_timer(),
            )
        )
        self.assertEqual(row.status, ScheduleStatus.TIMED_OUT)

    def test_a_masked_scheduler_is_paused_after_an_interrupted_change(self) -> None:
        service = show(load="masked", active="inactive", enabled="", result="success")
        row = self.projected(
            automation(
                units=installed_schedule(),
                schedule_service=service,
                schedule_timer=show(load="masked", enabled="masked", active="inactive"),
            )
        )
        self.assertEqual(row.status, ScheduleStatus.PAUSED)

    def test_a_gate_with_boot_activation_off_reads_off_during_maintenance(self) -> None:
        gated = replace(self.site(), state=SiteState.PARTLY_APPLIED, missing=(SITE_GATED,))
        rows = observation.observations(
            automation(
                units=installed_schedule(),
                schedule_service=running_service(),
                schedule_timer=show(load="loaded", active="inactive", enabled=""),
            ),
            sites=(gated,),
            disable_wp_cron={},
        )
        if rows is None:
            self.fail("The projection was built.")
        self.assertEqual(rows[0].status, ScheduleStatus.OFF_MAINTENANCE)


class FencePlanTests(SimpleTestCase):
    def test_a_running_scheduler_joins_the_reviewed_resume_set(self) -> None:
        from automation.fence import plan_from

        value = automation(
            units=installed_schedule(),
            schedule_timer=show(load="loaded", active="active"),
            schedule_service=show(),
        )
        document = plan_from(value, ("shop",))
        if document is None:
            self.fail("The fence plan was built.")
        sites = document["sites"]
        if not isinstance(sites, list) or not sites:
            self.fail("The scheduler's plan was not recorded.")
        self.assertEqual(
            sites[0]["timers"], [convention.timer_name("shop", convention.ROLE_SCHEDULE)]
        )
        self.assertEqual(
            sites[0]["resume"], [convention.timer_name("shop", convention.ROLE_SCHEDULE)]
        )


class ReconstructionTests(TestCase):
    def test_a_stored_laravel_schedule_is_read_back_with_its_last_result(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        row = schedule(
            role=convention.ROLE_SCHEDULE,
            status=ScheduleStatus.SKIPPED,
            installed=True,
            timer_active=True,
            timer_enabled=True,
            result="success",
            last_start_us=1_761_393_600_000_000,
            last_exit_us=1_761_393_720_000_000,
        )
        record_laravel_schedule(server, rows=(row,))
        stored = current_snapshot(server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.automation.value, (row,))


class SchedulerInputTests(SimpleTestCase):
    def test_the_input_decoder_accepts_every_scheduler_action(self) -> None:
        for state in ("on", "off", "run"):
            with self.subTest(state=state):
                decoded = decode_inputs(
                    {"version": 1, "identifier": "shop", "state": state},
                    (),
                    InputShape.AUTOMATION_SCHEDULE,
                )
                self.assertEqual(decoded.schedule_state, state)


class SchedulerPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def settings_page(self) -> str:
        response = self.client.get(f"/servers/{self.server.pk}/sites/shop/settings/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_the_section_shows_the_state_limits_and_run_now_without_contacting_anyone(
        self,
    ) -> None:
        record_laravel_schedule(
            self.server,
            rows=(
                schedule(
                    role=convention.ROLE_SCHEDULE,
                    status=ScheduleStatus.SUCCEEDED,
                    installed=True,
                    timer_active=True,
                    timer_enabled=True,
                    result="success",
                    last_start_us=1_761_393_600_000_000,
                    last_exit_us=1_761_393_605_000_000,
                ),
            ),
            checked_at=datetime(2026, 10, 25, 12, 0, tzinfo=UTC),
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            html = self.settings_page()
        self.assertIn("Scheduled tasks", html)
        self.assertIn("On, the last run succeeded", html)
        self.assertIn("Turn off", html)
        self.assertIn("Run now", html)
        self.assertIn("one hour", html)
        self.assertIn("runInBackground", html)
        self.assertIn("caught up", html)
        for native in ("systemd", "timer", "slice", "journal", "socket"):
            self.assertNotIn(native, html.lower())

    def test_a_viewer_reads_the_state_and_is_not_offered_an_action(self) -> None:
        record_laravel_schedule(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        html = self.settings_page()
        self.assertIn("Scheduled tasks", html)
        self.assertNotIn("Run now", html)
        self.assertNotIn("site_scheduled_tasks_prepare", html)

    def test_run_now_queues_one_site_review_of_the_laravel_scheduler(self) -> None:
        from operations.services import read_changes

        record_laravel_schedule(
            self.server,
            rows=(
                schedule(
                    role=convention.ROLE_SCHEDULE,
                    status=ScheduleStatus.SUCCEEDED,
                    installed=True,
                    timer_active=True,
                    timer_enabled=True,
                    result="success",
                ),
            ),
        )
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/scheduled-tasks/prepare/",
            {"state": "run"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, scheduler.SLUG)
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "state": "run"},
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_the_overview_shows_one_plain_laravel_line(self) -> None:
        record_laravel_schedule(
            self.server,
            rows=(
                schedule(
                    role=convention.ROLE_SCHEDULE,
                    status=ScheduleStatus.FAILED,
                    installed=True,
                    timer_active=True,
                    timer_enabled=True,
                    result="exit-code",
                    last_start_us=1_761_393_600_000_000,
                    last_exit_us=1_761_393_605_000_000,
                ),
            ),
            checked_at=datetime(2026, 10, 25, 12, 0, tzinfo=UTC),
        )
        response = self.client.get(f"/servers/{self.server.pk}/sites/shop/")
        html = response.content.decode()
        self.assertIn("Scheduled tasks: On, the last run failed", html)
        self.assertIn("Checked", html)
