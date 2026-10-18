"""The Deploy and Roll back kinds, and the acknowledgement they require."""

import os
import pathlib
import stat
import tempfile
import types
from datetime import timedelta
from typing import cast, override
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
        "environment": ["APP_ENV", "APP_KEY"],
        "deploy_key": "",
        "host_keys": False,
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


class LaravelReleaseTests(SimpleTestCase):
    """A site-owned release layout is read and classified natively (Phase B #259).

    ``safe`` guards root-owned configuration, but a release belongs to the site user and
    shared Laravel state lives in the site's private area, so the reader accepts both
    under a site boundary only root or the site user can write. A root-owned ``current``
    link cannot be made without privilege, so that rule is asserted in the native
    release-layout scenario. The classification's Caddy group is asserted through the
    ownership the body requests; only a real target can grant it (native scenario).
    """

    identifier = "s4alpha"
    name = "a" * 40 + "-" + "b" * 16

    @override
    def setUp(self) -> None:
        super().setUp()
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        directory = self.root / self.identifier
        self.paths = (
            directory,
            directory / "releases",
            directory / "current",
            directory / "private",
        )
        self.enterContext(mock.patch.object(native, "laravel_paths", return_value=self.paths))
        self.enterContext(
            mock.patch.object(
                native,
                "site_account",
                return_value=[
                    os.getuid(),
                    os.getgid(),
                    str(directory),
                    "/usr/sbin/nologin",
                    [],
                ],
            )
        )

    def build(self) -> pathlib.Path:
        directory, releases, _, private = self.paths
        directory.mkdir(mode=0o755)
        release = releases / self.name
        (release / ".git").mkdir(parents=True)
        (release / "artisan").write_text("<?php\n", encoding="utf-8")
        (release / ".git" / "config").write_text(
            f'[remote "origin"]\n\turl = {REPOSITORY}\n', encoding="utf-8"
        )
        (release / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (release / "composer.json").write_text('{"require": {"php": "^8.3"}}', encoding="utf-8")
        private.mkdir(mode=0o700)
        (private / "laravel.env").write_text("APP_ENV=production\n", encoding="utf-8")
        (private / "storage").mkdir()
        (private / "cache").mkdir()
        return release

    def test_a_site_owned_release_layout_is_read(self) -> None:
        self.build()
        self.assertEqual(native.release_state(self.identifier, self.name), "complete")
        self.assertEqual(native.git_locator(self.identifier, self.name), (REPOSITORY, "main"))
        self.assertEqual(
            native.shared_state(self.identifier),
            {"environment": True, "storage": True, "cache": True},
        )
        self.assertEqual(native.php_requirement(self.identifier, self.name), "^8.3")
        record = native.release_record(self.identifier, self.name)
        self.assertEqual(record["state"], "complete")
        self.assertEqual(record["commit"], "a" * 40)
        self.assertEqual(record["repository"], REPOSITORY)
        self.assertEqual(record["branch"], "main")

    def test_a_release_another_account_owns_is_not_read(self) -> None:
        self.build()
        with mock.patch.object(
            native,
            "site_account",
            return_value=[
                os.getuid() + 4242,
                os.getgid() + 4242,
                "/nonexistent",
                "/usr/sbin/nologin",
                [],
            ],
        ):
            self.assertEqual(native.release_state(self.identifier, self.name), "unsupported")
            self.assertEqual(native.git_locator(self.identifier, self.name), ("", ""))
            self.assertEqual(native.php_requirement(self.identifier, self.name), "")

    def test_a_release_anyone_can_write_is_not_read(self) -> None:
        release = self.build()
        release.chmod(0o777)
        self.assertEqual(native.release_state(self.identifier, self.name), "unsupported")
        self.assertEqual(native.git_locator(self.identifier, self.name), ("", ""))
        self.assertEqual(native.php_requirement(self.identifier, self.name), "")

    def test_git_metadata_behind_a_symlink_is_not_read(self) -> None:
        # The release's own `.git/config` is a real file; a link out of it is not its
        # metadata, so the repository is not read from wherever it points.
        release = self.build()
        config = release / ".git" / "config"
        elsewhere = self.root / "config"
        elsewhere.write_text(config.read_text(encoding="utf-8"), encoding="utf-8")
        config.unlink()
        config.symlink_to(elsewhere)
        repository, _ = native.git_locator(self.identifier, self.name)
        self.assertEqual(repository, "")

    def test_a_current_link_that_is_not_root_owned_is_not_current(self) -> None:
        self.build()
        self.paths[2].symlink_to("releases/" + self.name)
        self.assertIsNone(native.current_name(self.identifier))

    def test_an_absent_site_account_reads_nothing(self) -> None:
        self.build()
        with mock.patch.object(native, "site_account", return_value=None):
            self.assertEqual(native.release_state(self.identifier, self.name), "unsupported")
            self.assertEqual(
                native.shared_state(self.identifier),
                {"environment": False, "storage": False, "cache": False},
            )
            self.assertEqual(native.php_requirement(self.identifier, self.name), "")

    def test_classification_closes_a_release_but_keeps_public_readable(self) -> None:
        """Caddy reads ``public`` only; every other directory is traversal-only."""
        release = self.build()
        (release / "public" / "assets").mkdir(parents=True)
        (release / "public" / "index.php").write_text("<?php\n", encoding="utf-8")
        (release / "public" / "assets" / "app.css").write_text("body {}\n", encoding="utf-8")
        (release / "app").mkdir()
        (release / "app" / "Kernel.php").write_text("<?php\n", encoding="utf-8")
        (release / "storage").symlink_to(self.paths[3] / "storage")
        (release / ".env").symlink_to(self.paths[3] / "laravel.env")
        target = stat.S_IMODE((self.paths[3] / "storage").stat().st_mode)
        owners: list[tuple[str, int, int]] = []

        def recorded(path: pathlib.Path, uid: int, gid: int, **_: object) -> None:
            owners.append((str(path), uid, gid))

        self.enterContext(mock.patch.object(os, "chown", side_effect=recorded))
        self.enterContext(mock.patch.object(native, "caddy_ids", return_value=(71, 71)))
        native.classify(types.SimpleNamespace(identifier=self.identifier), release)

        modes = {
            release: 0o711,
            release / "app": 0o711,
            release / "app" / "Kernel.php": 0o600,
            release / "public": 0o2750,
            release / "public" / "assets": 0o2750,
            release / "public" / "index.php": 0o600,
            release / "public" / "assets" / "app.css": 0o640,
        }
        for path, mode in modes.items():
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), mode, str(path))
        granted = {(path, gid) for path, _, gid in owners}
        self.assertIn((str(release / "public"), 71), granted)
        self.assertIn((str(release / "public" / "assets" / "app.css"), 71), granted)
        self.assertIn((str(release / "app" / "Kernel.php"), os.getgid()), granted)
        self.assertTrue((release / "storage").is_symlink())
        self.assertNotIn(str(release / "storage"), {path for path, _, _ in owners})
        self.assertEqual(stat.S_IMODE((self.paths[3] / "storage").stat().st_mode), target)

    def test_fetch_publishes_a_site_owned_release_directory(self) -> None:
        """``releases/`` is root-controlled: root publishes the entry, the site fills it."""
        self.paths[1].mkdir(parents=True)
        release = self.paths[1] / self.name
        settings = types.SimpleNamespace(identifier=self.identifier)

        def checked_out(*_argv: object, **_kwargs: object) -> None:
            (release / ".git").mkdir(exist_ok=True)
            (release / "composer.json").write_text("{}\n", encoding="utf-8")

        with mock.patch.object(native, "user_command", side_effect=checked_out) as site_user:
            native.fetch(settings, REPOSITORY, "a" * 40, release)
        metadata = release.lstat()
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertEqual(metadata.st_gid, os.getgid())
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)
        self.assertEqual(site_user.call_count, 4)
        with self.assertRaises(ValueError):
            native.fetch(settings, REPOSITORY, "a" * 40, release)
