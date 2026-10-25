"""The scheduled-tasks review, its refusals, its document and the body's order."""

import base64
import gzip
import json
import pathlib
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from automation import change, convention
from automation.bodies import schedule as body
from automation.testing import (
    automation,
    installed_units,
    native_state,
    site_record,
    unit_digests,
    wordpress,
)
from bootstrap.standing import Standing
from operations.engine import BodyContext, NativeBody
from operations.inputs import PreparationInputs
from sites.bodies.common import SITE_GATED, SiteRecord

ON = PreparationInputs("", "shop", schedule_state="on")
OFF = PreparationInputs("", "shop", schedule_state="off")


def evidence(
    *,
    standing: Standing = Standing.TARGET_STACK,
    site: SiteRecord | None = None,
    wordpress_row: dict[str, object] | None = None,
    automation_row: dict[str, object] | None = None,
) -> change.ScheduleEvidence:
    return change.ScheduleEvidence(
        standing,
        native_state(site),
        wordpress_row if wordpress_row is not None else wordpress(),
        automation_row if automation_row is not None else automation(units=[]),
    )


class ReviewTests(SimpleTestCase):
    def test_turning_on_is_one_site_change_with_the_constant_after_a_tick(self) -> None:
        draft = change.review(evidence(), ON)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].sites, ("shop",))
        self.assertEqual(draft.stages, change.ON_STAGES)
        self.assertEqual(draft.stages[-1], "verify")
        self.assertLess(draft.stages.index("tick"), draft.stages.index("configuration"))
        self.assertEqual(draft.document["state"], "on")
        self.assertEqual(
            draft.document["units"], dict.fromkeys(("slice", "service", "timer"), "absent")
        )
        self.assertEqual(draft.current_sites, ("shop",))
        self.assertIn("shop", draft.sites_read)
        self.assertEqual(draft.boot_id, native_state()["boot"])

    def test_turning_off_clears_the_constant_before_it_stops_the_task(self) -> None:
        draft = change.review(
            evidence(wordpress_row=wordpress(disable="true"), automation_row=automation(units=[])),
            OFF,
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.stages, change.OFF_STAGES)
        self.assertLess(draft.stages.index("configuration"), draft.stages.index("install"))

    def test_a_site_that_is_not_wordpress_is_refused(self) -> None:
        draft = change.review(evidence(site=site_record(application="plain")), ON)
        self.assertFalse(draft.eligible)
        self.assertIn("This site is not a WordPress application.", draft.refusals)

    def test_wordpress_that_is_not_completely_installed_is_refused(self) -> None:
        for site in (
            site_record(state="partial"),
            site_record(application_problem="The WordPress core version file is missing."),
            site_record(state="partial", problem=SITE_GATED),
        ):
            with self.subTest(site=site):
                draft = change.review(evidence(site=site), ON)
                self.assertFalse(draft.eligible)
                self.assertIn(
                    "WordPress is not installed completely and verified on this site.",
                    draft.refusals,
                )

    def test_a_hand_made_scheduler_blocks_turning_on_and_never_turning_off(self) -> None:
        duplicate = "A hand-made crontab entry already runs WordPress cron for this site."
        blocked = change.review(evidence(automation_row=automation(duplicate=duplicate)), ON)
        allowed = change.review(evidence(automation_row=automation(duplicate=duplicate)), OFF)
        self.assertFalse(blocked.eligible)
        self.assertIn(duplicate, blocked.refusals)
        self.assertTrue(allowed.eligible, allowed.refusals)

    def test_a_repeated_review_of_an_on_site_proposes_nothing(self) -> None:
        draft = change.review(
            evidence(
                wordpress_row=wordpress(disable="true"),
                automation_row=automation(
                    timer={
                        "Id": "timer",
                        "LoadState": "loaded",
                        "ActiveState": "active",
                        "SubState": "waiting",
                        "UnitFileState": "enabled",
                        "Result": "success",
                        "ExecMainStatus": "0",
                        "ExecMainStartTimestamp": "@60000000",
                        "ExecMainExitTimestamp": "@65000000",
                        "LastTriggerUSec": "@60000000",
                        "NextElapseUSecRealtime": "@120000000",
                        "ControlGroup": "",
                    },
                    service={
                        "Id": "service",
                        "LoadState": "loaded",
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "UnitFileState": "static",
                        "Result": "success",
                        "ExecMainStatus": "0",
                        "ExecMainStartTimestamp": "@60000000",
                        "ExecMainExitTimestamp": "@65000000",
                        "LastTriggerUSec": "",
                        "NextElapseUSecRealtime": "",
                        "ControlGroup": "",
                    },
                ),
            ),
            ON,
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already on", str(draft.document["note"]))

    def test_a_repeated_review_of_an_off_site_proposes_nothing(self) -> None:
        draft = change.review(evidence(), OFF)
        self.assertTrue(draft.no_changes)
        self.assertIn("already off", str(draft.document["note"]))

    def test_an_unsupported_hand_edit_is_reported_and_blocks_the_change(self) -> None:
        edited = installed_units()
        edited[1] = {
            **edited[1],
            "text": edited[1]["text"].replace("User=sshop", "User=root"),
        }
        draft = change.review(evidence(automation_row=automation(units=edited)), ON)
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("changed outside Barectl" in refusal for refusal in draft.refusals),
            draft.refusals,
        )

    def test_unreadable_automation_evidence_blocks_the_change(self) -> None:
        draft = change.review(
            change.ScheduleEvidence(Standing.TARGET_STACK, native_state(), wordpress(), None),
            ON,
        )
        self.assertFalse(draft.eligible)
        self.assertIn("The site's scheduled tasks could not be read.", draft.refusals)

    def test_a_non_target_host_and_an_unreadable_site_are_refused(self) -> None:
        not_target = change.review(evidence(standing=Standing.NOT_MANAGEABLE), ON)
        missing = change.review(
            change.ScheduleEvidence(Standing.TARGET_STACK, None, None, None), ON
        )
        self.assertIn(
            "Set up and verify the host foundation before changing a site.",
            not_target.refusals,
        )
        self.assertIn("The site's native configuration could not be read.", missing.refusals)


class DocumentTests(SimpleTestCase):
    def reviewed(self) -> tuple[dict[str, object], NativeBody]:
        evidence_value = evidence()
        draft = change.review(evidence_value, ON)
        return draft.document, change.body(draft.document, BodyContext("unit", "boot", 0))

    def test_the_body_carries_only_the_reviewed_non_secret_selection(self) -> None:
        document, native = self.reviewed()
        self.assertEqual(len(native.arguments), 1)
        payload = json.loads(gzip.decompress(base64.b64decode(native.arguments[0])))
        self.assertEqual(
            set(payload),
            {
                "version",
                "identifier",
                "state",
                "uid",
                "gid",
                "configuration_digest",
                "units",
                "tick_budget_seconds",
            },
        )
        self.assertEqual(payload["state"], "on")
        self.assertEqual(payload["identifier"], "shop")
        self.assertEqual(payload["units"], dict.fromkeys(("slice", "service", "timer"), "absent"))
        self.assertEqual(document["body_sha256"], change.BODY_SHA256)
        self.assertNotIn("details", payload)
        self.assertFalse(native.source.endswith(b"\n"))
        self.assertLessEqual(len(native.source), 192 * 1024)

    def test_a_forged_or_truncated_document_is_refused(self) -> None:
        draft = change.review(evidence(), ON)
        for field in (
            "version",
            "identifier",
            "state",
            "uid",
            "gid",
            "configuration_digest",
            "units",
        ):
            with self.subTest(field=field):
                forged = {key: value for key, value in draft.document.items() if key != field}
                with self.assertRaises(ValueError):
                    change.body(forged, BodyContext("unit", "boot", 1))
        forged = {**draft.document, "state": "maybe"}
        with self.assertRaises(ValueError):
            change.body(forged, BodyContext("unit", "boot", 1))

    def test_the_assembled_body_is_valid_python_and_the_reviewed_size(self) -> None:
        compile(change.BODY_SOURCE, "<automation-body>", "exec")
        self.assertLessEqual(len(change.BODY_BYTES), 192 * 1024)


class BodyOrderTests(SimpleTestCase):
    """The body's own order: never hand over before a successful run, never stop early."""

    def value(self, state: str) -> SimpleNamespace:
        return SimpleNamespace(
            identifier="shop",
            state=state,
            uid=1001,
            gid=1001,
            configuration_digest="a" * 64,
            units=dict.fromkeys(("slice", "service", "timer"), "absent"),
            tick_budget_seconds=150,
        )

    def patched(self, *, verified: bool = True) -> tuple[list[str], dict[str, object]]:
        order: list[str] = []

        def note(name: str) -> None:
            order.append(name)

        def wait_tick(*_args: object) -> bool:
            note("wait-tick")
            return True

        def write_constant(_identifier: str, _path: object, _before: str, value: str) -> None:
            note("write-constant" if value else "clear-constant")

        def verify_constant(*_args: object) -> bool:
            note("verify-constant")
            return verified

        def result(outcome: str, reason: str = "") -> None:
            del reason
            note(f"result:{outcome}")

        patches: dict[str, object] = {
            "publish_units": lambda *args: note("publish"),
            "daemon_reload": lambda: note("reload"),
            "enable_timer": lambda name: note("start-timer"),
            "timer_ready": lambda *args: True,
            "wait_for_tick": wait_tick,
            "_configuration": write_constant,
            "_verify_configuration": verify_constant,
            "disable_and_stop": lambda *args: note("stop"),
            "remove_units": lambda *args: note("remove-units"),
            "unit_digests": lambda *args: dict.fromkeys(("slice", "service", "timer"), "absent"),
            "properties": lambda *args: {"Result": "success"},
            "stage": lambda name: note(f"stage:{name}"),
            "result": result,
        }
        return order, patches

    def apply_patches(self, patches: dict[str, object]) -> ExitStack:
        stack = ExitStack()
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(body, name, value))
        return stack

    def test_turning_on_writes_the_constant_only_after_a_verified_run(self) -> None:
        order, patches = self.patched()
        path = pathlib.Path("/nonexistent/wp-config.php")
        with self.apply_patches(patches):
            body._turn_on(self.value("on"), path, "before")
        self.assertLess(order.index("stage:tick"), order.index("wait-tick"))
        self.assertLess(order.index("wait-tick"), order.index("write-constant"))
        self.assertLess(order.index("write-constant"), order.index("result:succeeded"))

    def test_a_failed_first_run_never_sets_the_constant(self) -> None:
        order, patches = self.patched()
        patches["wait_for_tick"] = lambda *args: False
        with self.apply_patches(patches):
            body._turn_on(self.value("on"), pathlib.Path("/nonexistent/wp-config.php"), "before")
        self.assertNotIn("write-constant", order)
        self.assertIn("result:partial", order)

    def test_turning_off_clears_the_constant_before_it_stops_the_task(self) -> None:
        order, patches = self.patched()
        with self.apply_patches(patches):
            body._turn_off(self.value("off"), pathlib.Path("/nonexistent/wp-config.php"), "before")
        self.assertLess(order.index("clear-constant"), order.index("stop"))
        self.assertLess(order.index("clear-constant"), order.index("remove-units"))
        self.assertLess(order.index("stop"), order.index("remove-units"))
        self.assertIn("result:succeeded", order)


class BodyPayloadTests(SimpleTestCase):
    def test_the_reviewed_unit_digests_are_recomputed_from_the_native_files(self) -> None:
        draft = change.review(evidence(automation_row=automation(units=[])), ON)
        self.assertEqual(
            draft.document["units"], dict.fromkeys(("slice", "service", "timer"), "absent")
        )
        installed = automation(
            units=[
                {
                    "name": convention.service_name("shop", "wpcron"),
                    "kind": "service",
                    "text": convention.render_service("shop", "wpcron"),
                }
            ]
        )
        draft = change.review(evidence(automation_row=installed), ON)
        self.assertEqual(
            draft.document["units"],
            {
                "slice": "absent",
                "service": convention.digest(convention.render_service("shop", "wpcron")),
                "timer": "absent",
            },
        )

    def test_every_reviewed_digest_matches_the_rendered_unit(self) -> None:
        draft = change.review(evidence(automation_row=automation(units=installed_units())), ON)
        self.assertEqual(draft.document["units"], unit_digests())
