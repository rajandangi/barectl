"""The Deploy and Roll back kinds, and the acknowledgement they require."""

from datetime import timedelta
from typing import cast
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone
from django.utils.datastructures import MultiValueDict

from bootstrap.standing import Standing
from laravel import change, observation, rollback
from laravel.bodies import common as native
from laravel.configuration import ROLLBACK_ACKNOWLEDGEMENT
from operations import lifecycle, services
from operations.consent import Scope
from operations.engine import BodyContext
from operations.forms import ChangeApplyForm
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview, Consent
from runtimes.catalog import Architecture
from sites.bodies.common import SiteRecord

REPOSITORY = "https://github.com/example/app.git"
BOOT = "00000000-0000-0000-0000-000000000000"


def release(index: int, *, created: int | None = None) -> dict[str, object]:
    commit = f"{index:040x}"
    return {
        "name": f"{commit}-{'a' * 16}",
        "commit": commit,
        "created": created if created is not None else 1000 - index,
        "state": "complete",
        "repository": REPOSITORY,
        "branch": "main",
    }


def releases_in(row: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], row["releases"])


def laravel_row(identifier: str = "s4alpha", count: int = 7) -> dict[str, object]:
    releases = [release(index) for index in range(count)]
    return {
        "identifier": identifier,
        "application": "laravel",
        "current": releases[0]["name"],
        "repository": REPOSITORY,
        "branch": "main",
        "php_requirement": "",
        "releases": releases,
        "shared": {"environment": True, "storage": True, "cache": True},
        "problem": "",
    }


def site_record(identifier: str = "s4alpha") -> SiteRecord:
    site: dict[str, object] = {
        "identifier": identifier,
        "names": [f"{identifier}.example.com"],
        "runtime": "php84",
        "node_runtime": "",
        "account": [4000, 4000, f"/var/www/{identifier}", "/usr/sbin/nologin", [4000]],
        "file": f"/etc/caddy/sites/{identifier}.caddy",
        "state": "complete",
        "problem": "",
    }
    return cast(SiteRecord, site)


class DeployReviewTests(SimpleTestCase):
    def evidence(
        self,
        *,
        row: dict[str, object] | None = None,
        resolved: bool = True,
        runtime_version: str = "",
    ) -> change.DeployEvidence:
        return change.DeployEvidence(
            Standing.TARGET_STACK,
            Architecture.X86_64,
            10 * 1024 * 1024 * 1024,
            BOOT,
            500,
            site_record(),
            row if row is not None else laravel_row(),
            "b" * 40 if resolved else None,
            resolved,
            runtime_version,
        )

    def test_a_ready_deploy_is_a_site_change_that_names_its_releases(self) -> None:
        row = laravel_row()
        releases = releases_in(row)
        draft = change.review(self.evidence(row=row), PreparationInputs("", "s4alpha"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.current_sites, ("s4alpha",))
        self.assertNotEqual(draft.sites_read, "")
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertEqual(draft.effects[0].sites, ("s4alpha",))
        # Seven releases, one current, the newest five others kept, one pruned.
        self.assertEqual(draft.document["prune"], [releases[6]["name"]])
        self.assertNotIn(str(row["current"]), cast(list[str], draft.document["prune"]))
        self.assertEqual(draft.document["acknowledgement"], change.MIGRATION_ACKNOWLEDGEMENT)
        self.assertEqual(draft.document["body_sha256"], change.BODY_SHA256)

    def test_a_plain_site_is_refused(self) -> None:
        row = {**laravel_row(), "application": "plain"}
        draft = change.review(self.evidence(row=row), PreparationInputs("", "s4alpha"))
        self.assertIn("This site has no current Laravel release to deploy from.", draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_an_unresolved_branch_is_refused(self) -> None:
        draft = change.review(self.evidence(resolved=False), PreparationInputs("", "s4alpha"))
        self.assertIn("The branch could not be resolved to an exact commit.", draft.refusals)

    def test_missing_shared_state_is_refused(self) -> None:
        row = {**laravel_row(), "shared": {"environment": False, "storage": True, "cache": True}}
        draft = change.review(self.evidence(row=row), PreparationInputs("", "s4alpha"))
        self.assertTrue(any("shared environment" in refusal for refusal in draft.refusals))

    def test_a_composer_php_requirement_the_runtime_misses_is_refused(self) -> None:
        row = {**laravel_row(), "php_requirement": "^8.3"}
        draft = change.review(
            self.evidence(row=row, runtime_version="8.2.29"), PreparationInputs("", "s4alpha")
        )
        self.assertIn(
            "The site's application requires PHP ^8.3, but its runtime is PHP 8.2.29.",
            draft.refusals,
        )
        self.assertEqual(draft.effects, ())

    def test_a_composer_php_requirement_the_runtime_meets_is_eligible(self) -> None:
        row = {**laravel_row(), "php_requirement": "^8.2"}
        draft = change.review(
            self.evidence(row=row, runtime_version="8.4.11"), PreparationInputs("", "s4alpha")
        )
        self.assertTrue(draft.eligible, draft.refusals)

    def test_a_requirement_that_names_no_floor_is_not_refused(self) -> None:
        row = {**laravel_row(), "php_requirement": "<9.0"}
        draft = change.review(
            self.evidence(row=row, runtime_version="8.2.29"), PreparationInputs("", "s4alpha")
        )
        self.assertTrue(draft.eligible, draft.refusals)

    def test_an_unreadable_runtime_version_does_not_refuse_by_itself(self) -> None:
        row = {**laravel_row(), "php_requirement": "^9.0"}
        draft = change.review(self.evidence(row=row), PreparationInputs("", "s4alpha"))
        self.assertTrue(draft.eligible, draft.refusals)

    def test_migrations_can_be_turned_off_for_the_site(self) -> None:
        inputs = PreparationInputs("", "s4alpha", migrations=False)
        draft = change.review(self.evidence(), inputs)
        self.assertFalse(draft.document["migrations"])
        self.assertIn("Off", str(draft.document["details"]))

    def test_the_body_round_trips_a_reviewed_document(self) -> None:
        draft = change.review(self.evidence(), PreparationInputs("", "s4alpha"))
        body = change.body(draft.document, BodyContext("", "", 0))
        self.assertEqual(len(body.arguments), 1)

    def test_the_assembled_bodies_are_valid_python(self) -> None:
        compile(change.BODY_SOURCE, "deploy.py", "exec")
        compile(rollback.BODY_SOURCE, "rollback.py", "exec")
        compile(observation.READ_SOURCE, "read.py", "exec")


class RollbackReviewTests(SimpleTestCase):
    def evidence(self, *, row: dict[str, object] | None = None) -> rollback.RollbackEvidence:
        return rollback.RollbackEvidence(
            Standing.TARGET_STACK,
            Architecture.X86_64,
            BOOT,
            500,
            site_record(),
            row if row is not None else laravel_row(),
        )

    def test_a_retained_release_is_acked_and_never_reverses_schema(self) -> None:
        row = laravel_row()
        target = str(releases_in(row)[2]["name"])
        draft = rollback.review(
            self.evidence(row=row), PreparationInputs("", "s4alpha", (), target)
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["acknowledgement"], ROLLBACK_ACKNOWLEDGEMENT)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertEqual(draft.document["release"], target)

    def test_an_absent_release_is_refused(self) -> None:
        draft = rollback.review(
            self.evidence(), PreparationInputs("", "s4alpha", (), "deadbeef-" + "b" * 16)
        )
        self.assertIn("The chosen release is no longer retained on the server.", draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_the_current_release_is_not_a_roll_back_target(self) -> None:
        current = str(laravel_row()["current"])
        draft = rollback.review(self.evidence(), PreparationInputs("", "s4alpha", (), current))
        self.assertIn(
            "This release is already current; there is nothing to roll back.", draft.refusals
        )


class AcknowledgementTests(SimpleTestCase):
    def test_a_forged_apply_without_the_acknowledgement_is_refused(self) -> None:
        class Fake:
            preparation = object()
            eligible = True
            no_changes = False
            admission_expires_at = timezone.now() + timedelta(minutes=5)
            consent = Consent.SITE
            acknowledgement = "I accept."

        with mock.patch.object(lifecycle, "connection_current", return_value=True):
            self.assertEqual(
                services._refusal(cast(ChangeReview, Fake()), acknowledged=False),
                services.ACKNOWLEDGEMENT_REQUIRED,
            )
            self.assertEqual(services._refusal(cast(ChangeReview, Fake()), acknowledged=True), "")

    def test_the_apply_form_requires_the_checkbox(self) -> None:
        self.assertFalse(ChangeApplyForm(MultiValueDict()).is_valid())
        self.assertTrue(ChangeApplyForm(MultiValueDict({"acknowledged": ["on"]})).is_valid())


class LaravelInputTests(SimpleTestCase):
    def test_deploy_inputs_take_an_identifier(self) -> None:
        inputs = decode_inputs(
            {"version": 1, "identifier": "s4alpha"}, (), InputShape.LARAVEL_DEPLOY
        )
        self.assertEqual(inputs.document(), {"version": 1, "identifier": "s4alpha"})
        self.assertTrue(inputs.migrations)

    def test_deploy_inputs_can_turn_migrations_off(self) -> None:
        inputs = decode_inputs(
            {"version": 1, "identifier": "s4alpha", "migrations": False},
            (),
            InputShape.LARAVEL_DEPLOY,
        )
        self.assertFalse(inputs.migrations)
        self.assertEqual(
            inputs.document(), {"version": 1, "identifier": "s4alpha", "migrations": False}
        )

    def test_a_migrations_switch_that_is_not_boolean_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            decode_inputs(
                {"version": 1, "identifier": "s4alpha", "migrations": "no"},
                (),
                InputShape.LARAVEL_DEPLOY,
            )

    def test_rollback_inputs_take_a_release(self) -> None:
        inputs = decode_inputs(
            {"version": 1, "identifier": "s4alpha", "release": "abc-123"},
            (),
            InputShape.LARAVEL_ROLLBACK,
        )
        self.assertEqual(
            inputs.document(), {"version": 1, "identifier": "s4alpha", "release": "abc-123"}
        )

    def test_a_release_name_cannot_leave_the_release_layout(self) -> None:
        for bad in ("../escape", "a/b", ".", " "):
            with self.assertRaises(ValueError):
                decode_inputs(
                    {"version": 1, "identifier": "s4alpha", "release": bad},
                    (),
                    InputShape.LARAVEL_ROLLBACK,
                )


class ObservationTests(SimpleTestCase):
    def test_a_laravel_inventory_is_validated(self) -> None:
        value = {"version": 1, "sites": [laravel_row()]}
        self.assertTrue(observation.valid_inventory(value))
        row = observation.site(value, "s4alpha")
        self.assertIsNotNone(row)
        self.assertEqual(row["application"] if row else "", "laravel")
        self.assertFalse(observation.valid_inventory({"version": 1, "sites": [{"no": "keys"}]}))

    def test_version_is_read_from_the_release_name(self) -> None:
        self.assertEqual(native.version_of("a" * 40 + "-" + "b" * 32), "a" * 40)
        self.assertEqual(native.version_of("not-a-commit"), "")
