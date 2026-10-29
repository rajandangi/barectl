"""Offsite storage on S3 or R2 and copying a point (#403)."""

import importlib.resources
from datetime import timedelta
from typing import TYPE_CHECKING, override

from django.test import Client
from django.utils import timezone

if TYPE_CHECKING:
    pass

from bootstrap.standing import Standing
from operations import confidential, engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture, load

from . import change, convention, observation, offsite

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)
BUCKET = "barectl-backups"
PREFIX = "barectl/0123456789abcdef"


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def detail_rows(document: dict[str, object]) -> dict[str, str]:
    rows = document.get("details")
    if not isinstance(rows, list):
        return {}
    return {
        str(row["label"]): str(row["value"])
        for row in rows
        if isinstance(row, dict) and "label" in row and "value" in row
    }


def secret_keys(document: dict[str, object]) -> list[str]:
    fields = document.get("secret_fields")
    if not isinstance(fields, list):
        return []
    return [str(field["key"]) for field in fields if isinstance(field, dict) and "key" in field]


def storage(**values: object) -> observation.OffsiteStorage:
    return observation.OffsiteStorage(
        "s3",
        BUCKET,
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        PREFIX,
        True,
        "",
        **values,
    )


def storage_evidence(
    *,
    offsite_value: observation.OffsiteStorage | None = None,
    enabled: tuple[str, ...] = (IDENTIFIER,),
    sites: tuple[str, ...] = (IDENTIFIER,),
) -> offsite.StorageEvidence:
    return offsite.StorageEvidence(
        Standing.TARGET_STACK,
        Architecture.X86_64,
        BOOT,
        100,
        RESTIC.version,
        RESTIC.path,
        sites,
        enabled,
        offsite_value,
        "",
    )


def backup_evidence(
    *,
    offsite_value: observation.OffsiteStorage | None = None,
    enabled: bool = True,
) -> change.BackupEvidence:
    return change.BackupEvidence(
        architecture=Architecture.X86_64,
        standing=Standing.TARGET_STACK,
        engine="mariadb",
        site={
            "identifier": IDENTIFIER,
            "names": ["alpha.test"],
            "runtime": "php84",
            "https": True,
            "readiness": "/",
            "application": "plain",
            "state": "complete",
        },
        database=True,
        database_problem="",
        backup=observation.ObservedBackup(
            IDENTIFIER,
            RESTIC.path,
            enabled,
            enabled,
            (),
            True,
            "",
        ),
        problem="",
        boot_id=BOOT,
        uptime_centiseconds=100,
        restic_path=RESTIC.path,
        restic_version=RESTIC.version,
        disk_available=2 * 1024 * 1024 * 1024,
        current_sites=(IDENTIFIER,),
        offsite=offsite_value,
    )


class SetupReviewTests(ChangeTestCase):
    def inputs(self, provider: str = "s3") -> PreparationInputs:
        if provider == "s3":
            return PreparationInputs(provider="s3", bucket=BUCKET, region="us-east-1")
        return PreparationInputs(provider="r2", bucket=BUCKET, account="a" * 32)

    def test_an_s3_setup_is_shared_and_carries_the_keys_and_passphrase(self) -> None:
        draft = offsite.review_setup(storage_evidence(), self.inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SHARED)
        self.assertTrue(draft.writes_secrets)
        keys = secret_keys(draft.document)
        self.assertEqual(
            keys, ["access_key", "secret_key", "passphrase", "prune_access_key", "prune_secret_key"]
        )
        details = detail_rows(draft.document)
        self.assertIn("not immutable", details["Object lock"])
        self.assertIn("separate pruning key", details["Pruning key"])
        self.assertEqual(draft.document["sites"], [IDENTIFIER])

    def test_r2_says_one_token_can_write_and_delete_and_offers_no_pruning_key(self) -> None:
        draft = offsite.review_setup(storage_evidence(), self.inputs("r2"))
        self.assertTrue(draft.eligible, draft.refusals)
        details = detail_rows(draft.document)
        self.assertIn("can also delete", details["Pruning key"])
        keys = secret_keys(draft.document)
        self.assertNotIn("prune_access_key", keys)

    def test_setup_needs_at_least_one_backed_up_site(self) -> None:
        draft = offsite.review_setup(storage_evidence(enabled=()), self.inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("at least one site", " ".join(draft.refusals))

    def test_a_forged_setup_document_is_refused(self) -> None:
        draft = offsite.review_setup(storage_evidence(), self.inputs())
        forged = dict(draft.document)
        forged["health_repository"] = "s3:https://elsewhere/bucket"
        with self.assertRaises(ValueError):
            offsite.body_setup(
                forged, BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32)
            )

    def test_removing_says_the_bucket_contents_stay(self) -> None:
        draft = offsite.review_remove(
            storage_evidence(offsite_value=storage()), PreparationInputs()
        )
        self.assertTrue(draft.eligible, draft.refusals)
        details = detail_rows(draft.document)
        self.assertIn("deletes no offsite backup", details["Existing offsite copies"])
        self.assertIn("keeps every copy", str(draft.document["acknowledgement"]))
        self.assertEqual(draft.effects[0].scope, Scope.SHARED)


class CaptureAndCopyReviewTests(ChangeTestCase):
    def test_a_capture_review_names_the_offsite_destination(self) -> None:
        draft = change.review_backup(
            backup_evidence(offsite_value=storage()), PreparationInputs("", IDENTIFIER)
        )
        self.assertTrue(draft.eligible, draft.refusals)
        plan = draft.document["offsite"]
        if not isinstance(plan, dict):
            self.fail("The capture review named no offsite destination.")
        self.assertEqual(
            plan["repository"],
            f"s3:https://s3.us-east-1.amazonaws.com/{BUCKET}/{PREFIX}/{IDENTIFIER}",
        )
        change.body_backup(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_setting_outside_the_template_blocks_only_backup_changes(self) -> None:
        broken = observation.OffsiteStorage(
            "", "", "", "", "", False, "The offsite storage setting is outside supported settings."
        )
        draft = change.review_backup(
            backup_evidence(offsite_value=broken), PreparationInputs("", IDENTIFIER)
        )
        self.assertFalse(draft.eligible)
        self.assertIn("outside supported settings", " ".join(draft.refusals))

    def test_copy_offsite_again_is_site_consent_for_one_reviewed_point(self) -> None:
        draft = offsite.review_copy(
            backup_evidence(offsite_value=storage()),
            PreparationInputs("", IDENTIFIER, point="0123456789abcdef"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        offsite.body_copy(draft.document, BodyContext("unit", BOOT, 0))

    def test_copy_refuses_without_offsite_storage(self) -> None:
        draft = offsite.review_copy(
            backup_evidence(),
            PreparationInputs("", IDENTIFIER, point="0123456789abcdef"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("offsite storage", " ".join(draft.refusals))

    def test_a_forged_copy_is_refused(self) -> None:
        draft = offsite.review_copy(
            backup_evidence(offsite_value=storage()),
            PreparationInputs("", IDENTIFIER, point="0123456789abcdef"),
        )
        forged = dict(draft.document)
        forged["point"] = "ffffffffffffffff"
        # The reviewed point itself is supported; a different offsite repository is not.
        plan = forged["offsite"]
        if not isinstance(plan, dict):
            self.fail("The review named no offsite copy.")
        forged["offsite"] = {**plan, "repository": "s3:https://elsewhere/bucket/prefix/alpha"}
        with self.assertRaises(ValueError):
            offsite.body_copy(forged, BodyContext("unit", BOOT, 0))


class RecordedOffsiteOutputTests(ChangeTestCase):
    def test_the_recorded_copy_and_check_name_a_saved_snapshot(self) -> None:
        copy_output = fixture("restic-copy.txt")
        self.assertIn("copy started", copy_output)
        self.assertIn("snapshot", copy_output)
        self.assertIn("no errors were found", fixture("restic-check.txt"))

    def test_the_recorded_s3_error_replays_as_a_missing_repository(self) -> None:
        from discovery import ssh
        from discovery.recorded import Recorded, ReplayShell, Transcript

        from . import check

        command = check.listing_command(IDENTIFIER)
        shell = ReplayShell(
            Transcript(
                "backups",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                ((command, Recorded(ssh.CommandResult(10, fixture("restic-s3-error.txt")))),),
            )
        )
        result = shell.run(command)
        self.assertEqual(result.exit_status, 10)
        self.assertIn("repository does not exist", result.stdout)
        self.assertIsNone(check.parse_listing(result.stdout))


class OffsitePresentationTests(ChangeTestCase):
    def test_a_failed_offsite_copy_says_saved_here_offsite_copy_failed(self) -> None:
        from .testing import record_backups, result

        server = self.server
        record_backups(
            server,
            last=result(point="0123456789abcdef"),
            offsite=storage(),
            copy=observation.OffsiteCopy("failed", "offsite_copy", "0123456789abcdef", ""),
        )
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertContains(page, "Offsite copy failed.")
        self.assertContains(page, "Saved here")

    def test_opening_server_settings_makes_no_ssh_connection(self) -> None:
        from .testing import record_backups

        server = self.server
        record_backups(server, offsite=storage())
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{server.pk}/settings/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Backup storage")
        self.assertContains(page, BUCKET)
        self.assertContains(page, "Object lock")
        self.assertEqual(self.remote.commands, [])


class OffsiteApplyTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        confidential.reset()
        self.addCleanup(confidential.reset)

    def review(self, draft: ReviewDraft, consent: str) -> ChangeReview:
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
            consent=consent,
            writes_secrets=True,
            affected_sites=[IDENTIFIER],
            effects=[{"scope": "shared", "text": "Set up storage.", "sites": [IDENTIFIER]}],
            ssh_alias=self.server.ssh_alias,
            host_key=self.remote.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )

    def test_site_consent_cannot_apply_shared_offsite_storage(self) -> None:
        draft = offsite.review_setup(
            storage_evidence(), PreparationInputs(provider="s3", bucket=BUCKET, region="us-east-1")
        )
        review = self.review(draft, Consent.SHARED)
        self.sign_in_with("view_changes", "change_site", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_offsite_storage_apply_rechecks_manage_secrets(self) -> None:
        draft = offsite.review_setup(
            storage_evidence(), PreparationInputs(provider="s3", bucket=BUCKET, region="us-east-1")
        )
        review = self.review(draft, Consent.SHARED)
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"affected_sites": "on", "value_access_key": "a", "value_secret_key": "b"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_offsite_storage_apply_needs_csrf(self) -> None:
        draft = offsite.review_setup(
            storage_evidence(), PreparationInputs(provider="s3", bucket=BUCKET, region="us-east-1")
        )
        review = self.review(draft, Consent.SHARED)
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_setup_apply_needs_the_affected_sites_tick(self) -> None:
        draft = offsite.review_setup(
            storage_evidence(), PreparationInputs(provider="s3", bucket=BUCKET, region="us-east-1")
        )
        review = self.review(draft, Consent.SHARED)
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"value_access_key": "a", "value_secret_key": "b"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.exists())


class OffsiteSettingsRequestTests(ChangeTestCase):
    def test_the_settings_action_queues_the_reviewed_provider(self) -> None:
        from .testing import record_backups

        server = self.server
        record_backups(server)
        self.sign_in_with(
            "view_server", "view_changes", "change_site", "manage_secrets", "view_siteobservation"
        )
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/prepare/",
            {"provider": "s3", "bucket": BUCKET, "region": "us-east-1"},
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, offsite.SETUP_SLUG)
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "provider": "s3", "bucket": BUCKET, "region": "us-east-1"},
        )

    def test_a_missing_manage_secrets_permission_is_denied(self) -> None:
        from .testing import record_backups

        server = self.server
        record_backups(server)
        self.sign_in_with("view_server", "view_changes", "change_site", "view_siteobservation")
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/prepare/",
            {"provider": "s3", "bucket": BUCKET, "region": "us-east-1"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())
