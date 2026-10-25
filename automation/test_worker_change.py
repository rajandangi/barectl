"""The queue-worker review, its refusals, its document and the body's order."""

import base64
import gzip
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from automation import worker_change, workers
from automation.bodies import worker as body
from automation.testing import (
    DIGEST,
    native_state,
    site_record,
    worker_payload,
    worker_show,
    worker_units,
)
from bootstrap.standing import Standing
from operations.engine import BodyContext, NativeBody
from operations.inputs import PreparationInputs
from sites.bodies.common import SITE_GATED, SiteRecord

START = PreparationInputs(
    "",
    "shop",
    worker_action="start",
    worker_queues=("default", "mail"),
    worker_processes=2,
    worker_timeout=60,
)
STOP = PreparationInputs("", "shop", worker_action="stop")
RESTART = PreparationInputs("", "shop", worker_action="restart")


def laravel_row(
    *,
    current: str = "bootstrap",
    release: str = "bootstrap",
    state: str = "complete",
    digest: str = DIGEST,
) -> dict[str, object]:
    return {
        "identifier": "shop",
        "application": "laravel",
        "current": current,
        "repository": "",
        "branch": "",
        "php_requirement": "",
        "repository_problem": "",
        "releases": [
            {
                "name": release,
                "commit": "abcdef1",
                "created": 1,
                "state": state,
                "repository": "",
                "branch": "",
            }
        ],
        "shared": {"environment": True, "storage": True, "cache": True},
        "environment": [],
        "deploy_key": "",
        "host_keys": False,
        "problem": "",
        "environment_digest": digest,
    }


def preconditions(
    *,
    pcntl: bool = True,
    jobs: bool = True,
    pending: list[str] | None = None,
    readable: bool = True,
    http: int = 200,
) -> dict[str, object]:
    return {
        "version": 1,
        "sites": [
            {
                "identifier": "shop",
                "pcntl": pcntl,
                "jobs": jobs,
                "pending": pending or [],
                "migrations_readable": readable,
                "http": http,
            }
        ],
    }


def evidence(
    *,
    standing: Standing = Standing.TARGET_STACK,
    site: SiteRecord | None = None,
    laravel: dict[str, object] | None = None,
    workers_value: dict[str, object] | None = None,
    ready: dict[str, object] | None = None,
) -> worker_change.WorkerChangeEvidence:
    return worker_change.WorkerChangeEvidence(
        standing,
        native_state(site if site is not None else site_record(application="laravel")),
        laravel if laravel is not None else {"version": 1, "sites": [laravel_row()]},
        workers_value if workers_value is not None else worker_payload(),
        ready if ready is not None else preconditions(),
    )


class ReviewTests(SimpleTestCase):
    def test_starting_writes_the_retry_interval_before_the_units_and_the_processes(self) -> None:
        draft = worker_change.review(evidence(), START)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].sites, ("shop",))
        self.assertEqual(draft.stages, worker_change.ON_STAGES)
        self.assertLess(draft.stages.index("environment"), draft.stages.index("units"))
        self.assertLess(draft.stages.index("units"), draft.stages.index("start"))
        self.assertEqual(
            draft.document["definition"],
            {"queues": ["default", "mail"], "processes": 2, "timeout": 60},
        )
        self.assertEqual(draft.current_sites, ("shop",))
        self.assertIn("shop", draft.sites_read)

    def test_the_review_states_that_jobs_must_be_safe_to_repeat(self) -> None:
        draft = worker_change.review(evidence(), START)
        text = json.dumps(draft.document)
        self.assertIn("safe to repeat", text)
        self.assertIn("DB_QUEUE_RETRY_AFTER", text)
        self.assertIn("90 seconds", text)

    def test_a_worker_on_a_non_laravel_or_unmanaged_site_is_refused(self) -> None:
        no_laravel = worker_change.WorkerChangeEvidence(
            Standing.TARGET_STACK,
            native_state(site_record()),
            None,
            worker_payload(),
            preconditions(),
        )
        self.assertFalse(worker_change.review(no_laravel, START).eligible)
        for site in (
            site_record(state="partial"),
            site_record(application_problem="The release is incomplete."),
            site_record(problem=SITE_GATED),
        ):
            with self.subTest(site=site):
                draft = worker_change.review(evidence(site=site), START)
                self.assertFalse(draft.eligible)

    def test_a_missing_activation_check_refuses_start_and_restart_but_never_stop(self) -> None:
        for value in (
            preconditions(pcntl=False),
            preconditions(jobs=False),
            preconditions(pending=["2026_01_01_000000_create_jobs"]),
            preconditions(readable=False),
            preconditions(http=0),
        ):
            with self.subTest(value=value):
                blocked = worker_change.review(evidence(ready=value), START)
                self.assertFalse(blocked.eligible)
                stopped = worker_change.review(evidence(ready=value), STOP)
                self.assertTrue(stopped.eligible, stopped.refusals)
        unread = worker_change.WorkerChangeEvidence(
            Standing.TARGET_STACK,
            native_state(site_record(application="laravel")),
            {"version": 1, "sites": [laravel_row()]},
            worker_payload(),
            None,
        )
        self.assertFalse(worker_change.review(unread, START).eligible)
        self.assertTrue(worker_change.review(unread, STOP).eligible)

    def test_an_unverified_or_missing_release_refuses_start_and_restart(self) -> None:
        for row in (laravel_row(state="partial"), laravel_row(current="missing")):
            with self.subTest(laravel=row):
                draft = worker_change.review(
                    evidence(laravel={"version": 1, "sites": [row]}), START
                )
                self.assertFalse(draft.eligible)
        unread = worker_change.WorkerChangeEvidence(
            Standing.TARGET_STACK,
            native_state(site_record(application="laravel")),
            None,
            worker_payload(),
            preconditions(),
        )
        self.assertFalse(worker_change.review(unread, START).eligible)

    def test_stop_is_available_on_a_partly_applied_or_gated_site(self) -> None:
        for site in (
            site_record(state="partial"),
            site_record(application_problem="The release is incomplete."),
            site_record(problem=SITE_GATED),
        ):
            with self.subTest(site=site):
                draft = worker_change.review(evidence(site=site), STOP)
                self.assertTrue(draft.eligible, draft.refusals)

    def test_a_duplicate_worker_blocks_start_and_restart_but_never_stop(self) -> None:
        duplicate = "A hand-made crontab entry already runs queue:work for this site."
        value = worker_payload(duplicate=duplicate)
        blocked = worker_change.review(evidence(workers_value=value), START)
        restarted = worker_change.review(evidence(workers_value=value), RESTART)
        stopped = worker_change.review(evidence(workers_value=value), STOP)
        self.assertFalse(blocked.eligible)
        self.assertIn(duplicate, blocked.refusals)
        self.assertFalse(restarted.eligible)
        self.assertTrue(stopped.eligible, stopped.refusals)

    def test_an_unsupported_hand_edit_is_reported_once_and_stop_still_works(self) -> None:
        edited = worker_units()
        edited[1] = {
            **edited[1],
            "text": edited[1]["text"].replace("User=sshop", "User=root"),
        }
        value = worker_payload(units=edited)
        blocked = worker_change.review(evidence(workers_value=value), START)
        stopped = worker_change.review(evidence(workers_value=value), STOP)
        self.assertFalse(blocked.eligible)
        self.assertTrue(
            any("changed outside Barectl" in refusal for refusal in blocked.refusals),
            blocked.refusals,
        )
        self.assertTrue(stopped.eligible, stopped.refusals)

    def test_restart_needs_installed_workers_and_a_definition(self) -> None:
        absent = worker_payload(units=[], show={})
        draft = worker_change.review(evidence(workers_value=absent), RESTART)
        self.assertFalse(draft.eligible)
        self.assertIn("not installed", " ".join(draft.refusals))

    def test_a_repeated_start_proposes_nothing(self) -> None:
        on = worker_payload(definition=workers.WorkerDefinition(("default", "mail"), 2, 60))
        draft = worker_change.review(evidence(workers_value=on), START)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already running", str(draft.document["note"]))

    def test_a_repeated_stop_proposes_nothing(self) -> None:
        off = worker_payload(
            show={
                "queue1": worker_show(active="inactive", enabled="disabled"),
            }
        )
        draft = worker_change.review(evidence(workers_value=off), STOP)
        self.assertTrue(draft.no_changes)
        self.assertIn("already stopped", str(draft.document["note"]))

    def test_an_unreadable_worker_answer_blocks_every_action(self) -> None:
        draft = worker_change.review(
            worker_change.WorkerChangeEvidence(
                Standing.TARGET_STACK,
                native_state(site_record(application="laravel")),
                {"version": 1, "sites": [laravel_row()]},
                None,
                preconditions(),
            ),
            START,
        )
        self.assertFalse(draft.eligible)
        self.assertIn("queue workers could not be read", " ".join(draft.refusals))


class DocumentTests(SimpleTestCase):
    def reviewed(self, inputs: PreparationInputs = START) -> tuple[dict[str, object], NativeBody]:
        value = worker_payload(definition=workers.WorkerDefinition(("default", "mail"), 2, 60))
        draft = worker_change.review(evidence(workers_value=value), inputs)
        return draft.document, worker_change.body(draft.document, BodyContext("unit", "boot", 0))

    def test_the_body_carries_only_the_reviewed_non_secret_selection(self) -> None:
        document, native = self.reviewed()
        self.assertEqual(len(native.arguments), 1)
        payload = json.loads(gzip.decompress(base64.b64decode(native.arguments[0])))
        self.assertEqual(
            set(payload),
            {
                "version",
                "body_sha256",
                "identifier",
                "action",
                "definition",
                "runtime",
                "https",
                "names",
                "current",
                "uid",
                "gid",
                "environment_digest",
                "units",
            },
        )
        self.assertEqual(payload["action"], "start")
        self.assertEqual(payload["definition"]["processes"], 2)
        self.assertEqual(document["body_sha256"], worker_change.BODY_SHA256)
        self.assertNotIn("details", payload)
        self.assertFalse(native.source.endswith(b"\n"))
        self.assertLessEqual(len(native.source), 192 * 1024)

    def test_a_forged_or_truncated_document_is_refused(self) -> None:
        draft = worker_change.review(evidence(), START)
        for field in (
            "version",
            "identifier",
            "action",
            "runtime",
            "names",
            "current",
            "uid",
            "gid",
            "environment_digest",
            "units",
            "definition",
        ):
            with self.subTest(field=field):
                forged = {key: value for key, value in draft.document.items() if key != field}
                with self.assertRaises(ValueError):
                    worker_change.body(forged, BodyContext("unit", "boot", 1))
        forged = {
            **draft.document,
            "definition": {"queues": ["default"], "processes": 5, "timeout": 60},
        }
        with self.assertRaises(ValueError):
            worker_change.body(forged, BodyContext("unit", "boot", 1))

    def test_a_stop_document_needs_no_definition_or_environment(self) -> None:
        value = worker_payload()
        draft = worker_change.review(evidence(workers_value=value), STOP)
        payload = worker_change.body(draft.document, BodyContext("unit", "boot", 0))
        decoded = json.loads(gzip.decompress(base64.b64decode(payload.arguments[0])))
        self.assertIsNone(decoded["definition"])

    def test_the_assembled_body_is_valid_python_and_the_reviewed_size(self) -> None:
        compile(worker_change.BODY_SOURCE, "<worker-body>", "exec")
        self.assertLessEqual(len(worker_change.BODY_BYTES), 192 * 1024)


class BodyOrderTests(SimpleTestCase):
    def value(self, action: str) -> dict[str, object]:
        return {
            "version": 1,
            "identifier": "shop",
            "action": action,
            "definition": {"queues": ["default"], "processes": 1, "timeout": 60},
            "runtime": "php84",
            "https": True,
            "names": ["shop.example.com"],
            "current": "bootstrap",
            "uid": 1001,
            "gid": 1001,
            "environment_digest": DIGEST,
            "units": dict.fromkeys(("slice", *workers.WORKER_ROLES), "absent"),
        }

    def patched(self) -> tuple[list[str], dict[str, object]]:
        order: list[str] = []

        def note(name: str) -> None:
            order.append(name)

        def note_true(name: str) -> bool:
            note(name)
            return True

        def note_stop(*_args: object) -> None:
            note("stop")
            note("result:succeeded:")

        patches: dict[str, object] = {
            "setting": lambda *_args, **_kwargs: SimpleNamespace(
                identifier="shop",
                names=["shop.example.com"],
                runtime="php84",
                https=True,
                account="sshop",
                directory="/var/www/shop",
            ),
            "open_site_lock": lambda _identifier: 9,
            "os": mock.MagicMock(close=lambda _fd: note("unlock")),
            "site_account": lambda _identifier: [1001, 1001, "/var/www/shop", ""],
            "_current_directory": lambda _settings: SimpleNamespace(is_dir=lambda: True),
            "_current_name": lambda _identifier: "bootstrap",
            "_environment_ready": lambda *_args: True,
            "_write_retry": lambda *_args: note_true("environment"),
            "_rebuild_configuration": lambda _settings: note_true("configuration"),
            "_publish": lambda *_args: note("publish"),
            "_start": lambda *_args: note_true("start"),
            "_restart": lambda *_args: note_true("restart"),
            "_stop": note_stop,
            "_unit_preimages": lambda *_args: True,
            "stage": lambda name: note(f"stage:{name}"),
            "result": lambda outcome, reason="": note(f"result:{outcome}:{reason}"),
        }
        return order, patches

    def apply_patches(self, patches: dict[str, object]) -> ExitStack:
        stack = ExitStack()
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(body, name, value))
        return stack

    def test_start_writes_the_environment_before_it_publishes_and_starts(self) -> None:
        order, patches = self.patched()
        with self.apply_patches(patches):
            body.apply(self.value("start"))
        self.assertLess(order.index("environment"), order.index("configuration"))
        self.assertLess(order.index("configuration"), order.index("publish"))
        self.assertLess(order.index("publish"), order.index("start"))
        self.assertIn("result:succeeded:", order)

    def test_stop_never_touches_the_environment(self) -> None:
        order, patches = self.patched()
        with self.apply_patches(patches):
            body.apply(self.value("stop"))
        self.assertIn("stop", order)
        self.assertNotIn("environment", order)
        self.assertIn("result:succeeded:", order)

    def test_a_failed_environment_write_starts_nothing(self) -> None:
        order, patches = self.patched()
        patches["_write_retry"] = lambda *_args: False
        with self.apply_patches(patches):
            body.apply(self.value("start"))
        self.assertNotIn("publish", order)
        self.assertNotIn("start", order)


class WorkerUnitTests(SimpleTestCase):
    def test_start_resets_the_failed_state_before_it_enables_and_restarts(self) -> None:
        order: list[str] = []
        with ExitStack() as stack:
            for name, value in {
                "reset_failed": lambda name: order.append(f"reset:{name}"),
                "enable_service": lambda name: order.append(f"enable:{name}"),
                "restart_service": lambda name: order.append(f"restart:{name}"),
                "wait_services_active": lambda *_args: True,
            }.items():
                stack.enter_context(mock.patch.object(body, name, value))
            self.assertTrue(body._start("shop", workers.WorkerDefinition(("default",), 1, 60)))
        self.assertEqual(
            order,
            [
                "reset:barectl-site-shop-queue1.service",
                "enable:barectl-site-shop-queue1.service",
                "restart:barectl-site-shop-queue1.service",
            ],
        )

    def test_restart_keeps_the_existing_enablement(self) -> None:
        order: list[str] = []
        with ExitStack() as stack:
            for name, value in {
                "reset_failed": lambda name: order.append(f"reset:{name}"),
                "restart_service": lambda name: order.append(f"restart:{name}"),
                "wait_services_active": lambda *_args: True,
            }.items():
                stack.enter_context(mock.patch.object(body, name, value))
            self.assertTrue(body._restart("shop", workers.WorkerDefinition(("default",), 1, 60)))
        self.assertEqual(
            order,
            [
                "reset:barectl-site-shop-queue1.service",
                "restart:barectl-site-shop-queue1.service",
            ],
        )

    def test_the_retry_interval_is_timeout_plus_thirty_and_the_stop_budget_plus_fifteen(
        self,
    ) -> None:
        for timeout in (30, 60, 900):
            with self.subTest(timeout=timeout):
                value = workers.WorkerDefinition(("default",), 1, timeout)
                self.assertEqual(value.retry_after, timeout + 30)
                self.assertEqual(value.stop_seconds, timeout + 15)
                self.assertGreater(value.retry_after, value.timeout)
                self.assertLess(value.stop_seconds, value.retry_after)
