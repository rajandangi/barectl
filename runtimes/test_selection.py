import base64
import json
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations import engine, native
from operations.engine import BodyContext
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview
from operations.services import request_prepare

from . import change
from .catalog import Architecture, load


class RuntimeSelectionTests(ChangeTestCase):
    def test_requested_selection_is_a_defensive_immutable_copy(self) -> None:
        inputs: dict[str, object] = {"version": 1, "selection": "php84"}
        preparation = request_prepare(self.server, self.user, change.SLUG, inputs=inputs)
        if preparation is None:
            self.fail("No preparation queued.")
        inputs["selection"] = "php85"
        preparation.refresh_from_db()
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php84"})

    def test_unknown_version_extra_fields_and_tool_selections_never_connect(self) -> None:
        from operations import lifecycle

        self.sign_in_with("view_server", "view_changes", "change_site")
        for inputs in (
            {"version": 2, "selection": "php84"},
            {"version": 1, "selection": "php84", "path": "/unreviewed/store"},
            {"version": 1, "selection": "caddy"},
            {"version": 1, "selection": "php84; id"},
            {"version": 1, "selection": 84},
        ):
            with self.subTest(inputs=inputs):
                preparation = lifecycle.queue(
                    ChangePreparation,
                    self.server,
                    requested_by=self.user,
                    kind_slug=change.SLUG,
                    inputs=inputs,
                )
                with mock.patch("discovery.ssh.connect_operation") as connect:
                    self.run_worker()
                preparation.refresh_from_db()
                self.assertEqual(preparation.status, "failed")
                self.assertIn("preparation inputs", preparation.failure)
                connect.assert_not_called()


class ReviewedRuntimeTests(SimpleTestCase):
    def test_body_uses_only_the_exact_architecture_bound_review(self) -> None:
        inputs = PreparationInputs("php84")
        native: dict[str, object] = {
            "boot": "12345678-1234-1234-1234-123456789abc",
            "uptime": 1000,
            "digest": "a" * 64,
            "runtimes": [],
            "admissible": True,
        }
        draft = change.review(
            change.RuntimeEvidence(Architecture.AARCH64, Standing.TARGET_STACK, native), inputs
        )
        self.assertTrue(draft.eligible, draft.refusals)
        body = change.body(draft.document, BodyContext("", "", 0))
        expected = next(b.path for b in load().offered(Architecture.AARCH64) if b.entry == "php84")
        self.assertEqual(body.arguments[:2], ("php84", expected))
        for mutated in (
            {**draft.document, "path": "/nix/store/" + "a" * 32 + "-foreign"},
            {**draft.document, "version": True},
            {**draft.document, "selection": "caddy"},
        ):
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                change.body(mutated, BodyContext("", "", 0))

    def test_an_unrelated_master_fault_does_not_block_a_separate_php_addition(self) -> None:
        recorded = json.loads(
            Path(__file__).with_name("fixtures").joinpath("php84-native-read.json").read_text()
        )
        faulty = recorded["runtimes"][0]
        ini = faulty["files"]["/etc/php-fpm/php84/php.ini"]
        content = base64.b64decode(ini["bytes"]).decode()
        ini["bytes"] = base64.b64encode(
            content.replace(
                "opcache.validate_permission=1", "opcache.validate_permission=0"
            ).encode()
        ).decode()
        values = {**recorded, "runtimes": [faulty], "admissible": True}
        evidence = change.RuntimeEvidence(Architecture.AARCH64, Standing.TARGET_STACK, values)
        selected = change.review(evidence, PreparationInputs("php84"))
        self.assertFalse(selected.eligible)
        separate = change.review(evidence, PreparationInputs("php85"))
        self.assertTrue(separate.eligible, separate.refusals)
        self.assertFalse(separate.no_changes)
        unsafe_shared = change.review(
            change.RuntimeEvidence(
                Architecture.AARCH64, Standing.TARGET_STACK, {**values, "admissible": False}
            ),
            PreparationInputs("php85"),
        )
        self.assertFalse(unsafe_shared.eligible)

    def test_offered_runtime_review_fits_the_single_native_submission(self) -> None:
        for selection in ("php84", "php85", "nodejs_22", "nodejs_24"):
            with self.subTest(selection=selection):
                draft = change.review(
                    change.RuntimeEvidence(
                        Architecture.AARCH64,
                        Standing.TARGET_STACK,
                        {
                            "boot": "12345678-1234-1234-1234-123456789abc",
                            "uptime": 1000,
                            "digest": "a" * 64,
                            "runtimes": [],
                            "admissible": True,
                        },
                    ),
                    PreparationInputs(selection),
                )
                unit = native.new_unit_name()
                context = BodyContext(unit, draft.boot_id, 100000)
                reviewed = ChangeReview(document=draft.document, sites_read="")
                script = engine.payload(
                    change.ADD_RUNTIME,
                    reviewed,
                    context,
                    change.body(draft.document, context),
                    engine.body_path(unit),
                )
                self.assertLessEqual(len(script.encode()), 16384)

    def test_unsupported_architecture_refuses_without_choosing_another_build(self) -> None:
        draft = change.review(
            change.RuntimeEvidence(None, Standing.TARGET_STACK, None), PreparationInputs("php84")
        )
        self.assertFalse(draft.eligible)
        self.assertNotIn("path", draft.document)
