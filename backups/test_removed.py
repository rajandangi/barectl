"""Kept backups of a removed site: listed, restorable into a matching site (#407).

Remove site keeps a site's repositories; one explicit read lists them, and a restore may
name one as its source only when the point's own files prove the target's kind.
"""

import base64
import gzip
import importlib.resources
import json
from typing import cast, override
from unittest import mock

from django.contrib.auth.models import Permission
from django.test import Client, SimpleTestCase

from bootstrap.standing import Standing
from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript
from operations.consent import consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, Consent
from runtimes.catalog import Architecture
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import check, convention, observation, presentation, removed, restore
from .testing import point, record_backups, record_points

IDENTIFIER = "alpha"
SOURCE = "beta"
FILES = "b" * 64
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def transcript(entries: tuple[tuple[str, Recorded], ...]) -> ReplayShell:
    return ReplayShell(
        Transcript(
            "removed",
            {},
            "26.04",
            "x86_64",
            "ssh-ed25519 SHA256:x",
            (("id -u", Recorded(ssh.CommandResult(0, "0\n"))), *entries),
        )
    )


class RemovedRepositoryReadTests(SimpleTestCase):
    def test_the_read_is_one_shell_pipeline(self) -> None:
        self.assertNotIn("exec for", observation.removed_command())

    def test_the_read_names_every_repository_no_observed_site_owns(self) -> None:
        shell = transcript(
            (
                (
                    observation.removed_command(),
                    Recorded(ssh.CommandResult(0, "alpha\nbeta\n")),
                ),
            )
        )
        self.assertEqual(observation.removed(shell, ("alpha",)), ("beta",))
        self.assertEqual(observation.removed(shell, ("alpha",)), ("beta",))

    def test_an_unreadable_or_invalid_answer_lists_nothing(self) -> None:
        for answer in ("", "Beta\n", "beta\nalpha\n", "a\nb\nc\nd\ne\nf\ng\nh\ni\n"):
            shell = transcript(
                (
                    (
                        observation.removed_command(),
                        Recorded(ssh.CommandResult(0, answer)),
                    ),
                )
            )
            with self.subTest(answer=answer):
                self.assertEqual(observation.removed(shell, ()), () if answer == "" else None)

    def test_a_failed_read_is_unknown(self) -> None:
        shell = transcript(
            (
                (
                    observation.removed_command(),
                    Recorded(ssh.CommandResult(1, "")),
                ),
            )
        )
        self.assertIsNone(observation.removed(shell, ()))


class RemovedPointTests(SimpleTestCase):
    def test_a_listed_removed_repository_shows_its_restorable_points(self) -> None:
        view = presentation.removed_views(
            [
                {
                    "identifier": SOURCE,
                    "problem": "",
                    "points": [
                        point(scope="full", parts=("database", "files")),
                        point(point="fedcba9876543210", scope="database", parts=("database",)),
                    ],
                }
            ]
        )
        self.assertEqual(len(view), 1)
        self.assertEqual(view[0].identifier, SOURCE)
        self.assertTrue(view[0].points[0].restorable_elsewhere)
        self.assertFalse(view[0].points[1].restorable_elsewhere)

    def test_a_repository_the_read_could_not_open_names_its_problem(self) -> None:
        view = presentation.removed_views(
            [
                {
                    "identifier": SOURCE,
                    "problem": "The recovery points could not be read.",
                    "points": [],
                }
            ]
        )
        self.assertEqual(view[0].problem, "The recovery points could not be read.")

    def test_an_invalid_identifier_is_ignored(self) -> None:
        self.assertEqual(presentation.removed_views([{"identifier": "../beta"}]), ())


class PointKindTests(SimpleTestCase):
    def test_a_laravel_marker_proves_the_source_kind(self) -> None:
        shell = transcript(
            (
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/laravel.env"),
                    Recorded(ssh.CommandResult(0, '{"struct_type":"node"}')),
                ),
            )
        )
        self.assertEqual(restore.point_kind(shell, SOURCE, FILES), "laravel")

    def test_a_wordpress_marker_proves_the_source_kind(self) -> None:
        shell = transcript(
            (
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/laravel.env"),
                    Recorded(ssh.CommandResult(1, "")),
                ),
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/wp-config.php"),
                    Recorded(ssh.CommandResult(0, '{"struct_type":"node"}')),
                ),
            )
        )
        self.assertEqual(restore.point_kind(shell, SOURCE, FILES), "wordpress")

    def test_no_private_marker_means_a_plain_site(self) -> None:
        shell = transcript(
            (
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/laravel.env"),
                    Recorded(ssh.CommandResult(1, "")),
                ),
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/wp-config.php"),
                    Recorded(ssh.CommandResult(1, "")),
                ),
            )
        )
        self.assertEqual(restore.point_kind(shell, SOURCE, FILES), "plain")

    def test_an_unreadable_copy_proves_nothing(self) -> None:
        shell = transcript(
            (
                (
                    restore.kind_command(SOURCE, FILES, f"/var/www/{SOURCE}/private/laravel.env"),
                    Recorded(ssh.CommandResult(2, "")),
                ),
            )
        )
        self.assertEqual(restore.point_kind(shell, SOURCE, FILES), "")
        self.assertEqual(restore.point_kind(shell, SOURCE, ""), "")


def evidence(
    *, source: str = SOURCE, kind: str = "laravel", application: str = "laravel"
) -> restore.RestoreEvidence:
    """One restorable full point taken from the kept repository of a removed site."""
    selected = point(scope="full", parts=("database", "files"))
    return restore.RestoreEvidence(
        Architecture.X86_64,
        Standing.TARGET_STACK,
        "mariadb",
        "MariaDB",
        "11.8.2",
        {
            "identifier": IDENTIFIER,
            "names": [f"{IDENTIFIER}.test"],
            "runtime": "php84",
            "https": True,
            "readiness": "/",
            "application": application,
            "serving_form": "plain",
            "state": "complete",
            "problem": "",
            "account": [1001, 1001, f"/var/www/{IDENTIFIER}", "/usr/sbin/nologin", [1001]],
        },
        observation.ObservedBackup(
            IDENTIFIER,
            "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            None,
        ),
        {**selected, "size": 4096},
        "a" * 64,
        FILES,
        ("database", "files"),
        "11.8.2",
        False,
        "",
        2 * 1024 * 1024 * 1024,
        (IDENTIFIER,),
        "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b",
        100,
        source if source != IDENTIFIER else "",
        kind,
    )


class RemovedRestoreReviewTests(SimpleTestCase):
    def draft(self, *, scope: str = "full", **values: object) -> ReviewDraft:
        return restore.review(
            evidence(**values),  # type: ignore[arg-type]
            PreparationInputs("", IDENTIFIER, point="0123456789abcdef", scope=scope, source=SOURCE),
        )

    def test_a_full_point_of_a_matching_removed_site_is_restorable(self) -> None:
        draft = self.draft()
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["source"], SOURCE)
        self.assertEqual(draft.document["repository"], convention.repository(SOURCE))
        self.assertEqual(draft.document["server_key"], convention.server_key(SOURCE))
        self.assertEqual(draft.document["safety_repository"], convention.repository(IDENTIFIER))
        self.assertEqual(draft.document["safety_key"], convention.server_key(IDENTIFIER))
        self.assertEqual(draft.document["filename"], convention.dump_filename(SOURCE))
        details = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in details)
        self.assertIn("kept backups of removed site beta", values)
        restore.body(draft.document, BodyContext("unit", "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b", 0))

    def test_a_different_kind_is_refused(self) -> None:
        draft = self.draft(kind="wordpress")
        self.assertIn(
            "That recovery point was taken from a different kind of site, so it cannot be "
            "restored into this one.",
            draft.refusals,
        )

    def test_a_database_only_point_of_a_removed_site_is_refused(self) -> None:
        draft = self.draft(scope="database")
        self.assertTrue(any("cannot prove which kind" in refusal for refusal in draft.refusals))

    def test_a_forged_source_and_repository_cannot_build_a_body(self) -> None:
        draft = self.draft()
        forged = {**draft.document, "repository": convention.repository(IDENTIFIER)}
        with self.assertRaises(ValueError):
            restore.body(forged, BodyContext("unit", "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b", 0))
        forged = {**draft.document, "source": "../escape"}
        with self.assertRaises(ValueError):
            restore.body(forged, BodyContext("unit", "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b", 0))


class RemovedRestoreRequestTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_changes",
            "view_siteobservation",
            "change_site",
            "change_destructive",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_backups(self.server, identifier=IDENTIFIER, enabled=True)
        record_points(
            self.server,
            (),
            identifier=IDENTIFIER,
            removed=(
                {
                    "identifier": SOURCE,
                    "points": [point(scope="full", parts=("database", "files"))],
                    "problem": "",
                },
            ),
        )
        self.url = f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/restore/prepare/"

    def test_a_listed_removed_repository_can_be_named_as_the_source(self) -> None:
        response = self.client.post(
            self.url,
            {"point": "0123456789abcdef", "scope": "full", "source": SOURCE},
        )
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind_slug, restore.SLUG)
        self.assertEqual(rows[0].inputs["source"], SOURCE)
        self.assertRedirects(response, f"/changes/{rows[0].pk}/")

    def test_a_source_the_last_read_never_listed_is_refused(self) -> None:
        response = self.client.post(
            self.url,
            {"point": "0123456789abcdef", "scope": "full", "source": "gamma"},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._rows(), [])

    def test_the_site_itself_is_never_its_own_removed_source(self) -> None:
        response = self.client.post(
            self.url,
            {"point": "0123456789abcdef", "scope": "full", "source": IDENTIFIER},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._rows(), [])

    def test_the_page_lists_the_removed_backups_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertContains(response, "Backups of a removed site")
        self.assertContains(response, "Restore into this site")
        self.assertContains(response, f'name="source" value="{SOURCE}"')

    def _rows(self) -> list[ChangePreparation]:
        from operations.services import read_changes

        return [row.preparation for row in read_changes(self.server).rows]


def storage() -> observation.OffsiteStorage:
    return observation.OffsiteStorage(
        "s3",
        "barectl-test",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "barectl/abc",
    )


def delete_evidence(
    *, removed_site: bool = True, offsite: observation.OffsiteStorage | None = None
) -> removed.RemovedEvidence:
    return removed.RemovedEvidence(
        Architecture.X86_64,
        Standing.TARGET_STACK,
        "mariadb",
        offsite,
        (IDENTIFIER,),
        "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b",
        100,
        SOURCE,
        True,
        True,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
        removed_site,
        "",
    )


class RemovedDeleteReviewTests(SimpleTestCase):
    def test_deleting_a_removed_sites_backups_is_destructive_and_names_both_paths(self) -> None:
        draft = removed.review(delete_evidence(offsite=storage()), PreparationInputs("", SOURCE))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.DESTRUCTIVE)
        details = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in details)
        self.assertIn(convention.repository(SOURCE), values)
        self.assertIn(
            convention.offsite_repository(
                {
                    "provider": "s3",
                    "bucket": "barectl-test",
                    "region": "us-east-1",
                    "endpoint": "https://s3.us-east-1.amazonaws.com",
                    "prefix": "barectl/abc",
                    "prune": "no",
                },
                SOURCE,
            ),
            values,
        )
        self.assertIn("Deletion is permanent", values)
        native = removed.body(draft.document, BodyContext("unit", BOOT, 0))
        payload = json.loads(gzip.decompress(base64.b64decode(native.arguments[0])))
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["identifier"], SOURCE)
        self.assertEqual(payload["repository"], convention.repository(SOURCE))

    def test_a_site_that_still_exists_is_refused(self) -> None:
        draft = removed.review(delete_evidence(removed_site=False), PreparationInputs("", SOURCE))
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any(
                "not listed as the backups of a removed site" in refusal
                for refusal in draft.refusals
            )
        )

    def test_a_forged_offsite_repository_is_refused_by_the_body(self) -> None:
        draft = removed.review(delete_evidence(offsite=storage()), PreparationInputs("", SOURCE))
        forged = dict(draft.document)
        forged["offsite"] = {
            **cast(dict[str, object], forged["offsite"]),
            "repository": "s3:https://elsewhere/bucket/barectl/abc/" + SOURCE,
        }
        with self.assertRaises(ValueError):
            removed.body(forged, BodyContext("unit", BOOT, 0))


class RemovedDeleteRequestTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_changes",
            "view_siteobservation",
            "change_site",
            "change_destructive",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_backups(self.server, identifier=IDENTIFIER, enabled=True)
        record_points(
            self.server,
            (),
            identifier=IDENTIFIER,
            removed=(
                {
                    "identifier": SOURCE,
                    "points": [point(scope="full", parts=("database", "files"))],
                    "problem": "",
                },
            ),
        )
        self.url = f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/removed/delete/prepare/"

    def test_deleting_a_removed_sites_backups_queues_the_reviewed_kind(self) -> None:
        response = self.client.post(self.url, {"source": SOURCE})
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind_slug, removed.SLUG)
        self.assertEqual(rows[0].inputs, {"version": 1, "identifier": SOURCE})
        self.assertRedirects(response, f"/changes/{rows[0].pk}/")

    def test_a_source_the_last_read_never_listed_is_refused(self) -> None:
        response = self.client.post(self.url, {"source": "gamma"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._rows(), [])

    def test_deleting_needs_the_destructive_permission(self) -> None:
        self.user.user_permissions.remove(Permission.objects.get(codename="change_destructive"))
        response = self.client.post(self.url, {"source": SOURCE})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._rows(), [])

    def test_deleting_a_removed_sites_backups_needs_csrf(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(self.url, {"source": SOURCE})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._rows(), [])

    def test_deleting_is_post_only(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self._rows(), [])

    def test_the_page_offers_delete_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertContains(response, "Delete these backups")
        self.assertContains(response, f'name="source" value="{SOURCE}"')

    def _rows(self) -> list[ChangePreparation]:
        from operations.services import read_changes

        return [row.preparation for row in read_changes(self.server).rows]


class RemovedListingStorageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def test_the_last_explicit_check_carries_the_removed_repositories(self) -> None:
        record_points(
            self.server,
            (),
            identifier=IDENTIFIER,
            removed=({"identifier": SOURCE, "points": [], "problem": ""},),
        )
        self.assertEqual(
            check.latest_removed(self.server), [{"identifier": SOURCE, "points": [], "problem": ""}]
        )

    def test_a_check_of_another_site_still_names_them(self) -> None:
        record_points(self.server, (), identifier="alpha", removed=())
        record_points(self.server, (), identifier="gamma", removed=({"identifier": SOURCE},))
        self.assertEqual(check.latest_removed(self.server), [{"identifier": SOURCE}])
