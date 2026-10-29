"""Connect existing offsite backup storage across servers (#408)."""

import importlib.resources
import json
from datetime import timedelta
from typing import cast, override

from django.utils import timezone

from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript
from operations import confidential, engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture, load

from . import check, connect, convention, observation
from .bodies import observe as observe_body
from .testing import record_backups

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
BUCKET = "barectl-backups"
PREFIX = "barectl/0123456789abcdef"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def inputs() -> PreparationInputs:
    return PreparationInputs(
        provider="s3",
        bucket=BUCKET,
        region="us-east-1",
        prefix=PREFIX,
        sites=(IDENTIFIER,),
    )


def evidence() -> connect.ConnectEvidence:
    return connect.ConnectEvidence(
        RESTIC.path,
        RESTIC.version,
        (IDENTIFIER,),
        None,
        BOOT,
        100,
    )


def storage() -> observation.OffsiteStorage:
    rows = tuple(json.loads(fixture("restic-connected-snapshots.txt")))
    return observation.OffsiteStorage(
        "s3",
        BUCKET,
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        PREFIX,
        True,
        "",
        (observation.ConnectedSource(IDENTIFIER, rows),),
    )


class ConnectReviewTests(ChangeTestCase):
    def test_connecting_is_shared_and_carries_the_keys_and_passphrase(self) -> None:
        draft = connect.review(evidence(), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SHARED)
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertTrue(draft.writes_secrets)
        keys = [
            field["key"] for field in cast("list[dict[str, str]]", draft.document["secret_fields"])
        ]
        self.assertEqual(
            keys, ["access_key", "secret_key", "passphrase", "prune_access_key", "prune_secret_key"]
        )
        self.assertEqual(draft.document["sites"], [IDENTIFIER])
        self.assertIn("read-only", str(draft.document["note"]))

    def test_a_connected_setting_must_be_removed_before_another(self) -> None:
        other = observation.OffsiteStorage(
            "s3", "another-bucket", "us-east-1", "https://s3.us-east-1.amazonaws.com", PREFIX, True
        )
        draft = connect.review(
            connect.ConnectEvidence(RESTIC.path, RESTIC.version, (IDENTIFIER,), other, BOOT, 100),
            inputs(),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("Remove the storage", " ".join(draft.refusals))

    def test_a_forged_connected_document_is_refused(self) -> None:
        draft = connect.review(evidence(), inputs())
        forged = dict(draft.document)
        forged["config"] = {
            **cast("dict[str, str]", draft.document["config"]),
            "endpoint": "https://elsewhere.example.com",
        }
        with self.assertRaises(ValueError):
            connect.body(forged, BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32))

    def test_the_body_stages_the_secret_path_and_the_reviewed_sites(self) -> None:
        draft = connect.review(evidence(), inputs())
        body = connect.body(
            draft.document, BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32)
        )
        self.assertIn(b"import base64,gzip", body.source)
        self.assertTrue(body.arguments)


class ConnectedReadingTests(ChangeTestCase):
    def test_the_recorded_connect_result_rebuilds_its_source_points(self) -> None:
        rows = json.loads(fixture("restic-connected-snapshots.txt"))
        found: dict[str, dict[str, object]] = {}
        observe_body._connection(
            {"kind": "connect", "sources": [{"site": IDENTIFIER, "rows": rows}]}, found
        )
        source = observation.offsite_of(
            {
                "offsite": {
                    "provider": "s3",
                    "bucket": BUCKET,
                    "region": "us-east-1",
                    "endpoint": "https://s3.us-east-1.amazonaws.com",
                    "prefix": PREFIX,
                    "prune": True,
                    "problem": "",
                    "sites": [IDENTIFIER],
                    "sources": [found[IDENTIFIER]],
                }
            }
        )
        if source is None:
            self.fail("The connected storage was not read.")
        self.assertEqual(source.sources[0].identifier, IDENTIFIER)
        points = source.sources[0].points()
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["scope"], "full")
        self.assertEqual(points[0]["application"], "plain")
        self.assertEqual(
            cast("dict[str, str]", points[0]["snapshots"])["database"],
            "cc8dd12b140a7a7fa17b97fa5b7a16007eea2feda5d6bca3045923b71f6285a0",
        )
        self.assertTrue(points[0]["complete"])

    def test_the_recorded_listing_replays_at_the_remote_shell_seam(self) -> None:
        command = check.listing_command("alpha")
        shell = ReplayShell(
            Transcript(
                "connect",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    (
                        command,
                        Recorded(ssh.CommandResult(0, fixture("restic-connected-snapshots.txt"))),
                    ),
                ),
            )
        )
        points = check.points(check.parse_listing(shell.run(command).stdout) or [])
        self.assertEqual(points[0]["application"], "plain")


class ConnectRequestTests(ChangeTestCase):
    def test_the_settings_action_queues_the_reviewed_source(self) -> None:
        server = self.server
        record_backups(server, offsite=storage())
        self.sign_in_with(
            "view_server", "view_changes", "change_site", "manage_secrets", "view_siteobservation"
        )
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/connect/prepare/",
            {
                "provider": "s3",
                "bucket": BUCKET,
                "region": "us-east-1",
                "prefix": PREFIX,
                "sites": IDENTIFIER,
            },
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, connect.SLUG)
        self.assertEqual(preparation.inputs["sites"], [IDENTIFIER])

    def test_a_missing_manage_secrets_permission_is_denied(self) -> None:
        server = self.server
        record_backups(server, offsite=storage())
        self.sign_in_with("view_server", "view_changes", "change_site", "view_siteobservation")
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/connect/prepare/",
            {
                "provider": "s3",
                "bucket": BUCKET,
                "region": "us-east-1",
                "prefix": PREFIX,
                "sites": IDENTIFIER,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_opening_the_connect_page_makes_no_ssh_connection(self) -> None:
        server = self.server
        record_backups(server, enabled=True)
        self.sign_in_with(
            "view_server",
            "view_changes",
            "change_site",
            "manage_secrets",
            "view_siteobservation",
        )
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{server.pk}/settings/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Connect existing backup storage")
        self.assertEqual(self.remote.commands, [])


class ConnectApplyTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        confidential.reset()
        self.addCleanup(confidential.reset)

    def review(self) -> ChangeReview:
        draft = connect.review(evidence(), inputs())
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=draft.kind,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.SHARED,
            writes_secrets=True,
            affected_sites=[IDENTIFIER],
            effects=[{"scope": "shared", "text": "Connect storage.", "sites": [IDENTIFIER]}],
            ssh_alias=self.server.ssh_alias,
            host_key=self.remote.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )

    def test_site_consent_cannot_apply_shared_connected_storage(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_connecting_rechecks_manage_secrets(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {
                "affected_sites": "on",
                "value_access_key": "a",
                "value_secret_key": "b",
                "value_passphrase": "correct-horse-battery",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_connect_apply_needs_the_affected_sites_tick(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {
                "value_access_key": "a",
                "value_secret_key": "b",
                "value_passphrase": "correct-horse-battery",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.exists())

    def test_connecting_needs_csrf(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        from django.test import Client

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())
