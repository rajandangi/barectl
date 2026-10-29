"""Replace the recovery passphrase through one reviewed change (#408)."""

import importlib.resources
from datetime import timedelta
from typing import cast, override

from django.test import Client
from django.utils import timezone

from bootstrap.standing import Standing
from operations import confidential, engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture, load

from . import convention, keys, observation
from .bodies import keys as keys_body
from .testing import record_backups

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def evidence(with_offsite: bool = False) -> keys.KeysEvidence:
    storage = (
        observation.OffsiteStorage(
            "s3",
            "barectl-backups",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "barectl/0123456789abcdef",
            True,
        )
        if with_offsite
        else None
    )
    return keys.KeysEvidence(
        Standing.TARGET_STACK,
        RESTIC.path,
        (IDENTIFIER,),
        (IDENTIFIER,),
        storage,
        BOOT,
        100,
    )


class ReplaceReviewTests(ChangeTestCase):
    def test_replacing_is_shared_and_carries_both_passphrases(self) -> None:
        draft = keys.review(evidence(with_offsite=True), PreparationInputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SHARED)
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertTrue(draft.writes_secrets)
        fields = [
            field["key"] for field in cast("list[dict[str, str]]", draft.document["secret_fields"])
        ]
        self.assertEqual(fields, ["old_passphrase", "new_passphrase"])
        self.assertEqual(len(cast("list[str]", draft.document["repositories"])), 2)
        self.assertIn(
            "not re-encrypted",
            " ".join(
                row["value"] for row in cast("list[dict[str, str]]", draft.document["details"])
            ),
        )

    def test_replacing_needs_one_enabled_site(self) -> None:
        draft = keys.review(
            keys.KeysEvidence(Standing.TARGET_STACK, RESTIC.path, (), (), None, BOOT, 100),
            PreparationInputs(),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("Enable backups", " ".join(draft.refusals))

    def test_a_forged_passphrase_review_is_refused(self) -> None:
        draft = keys.review(evidence(), PreparationInputs())
        forged = dict(draft.document)
        forged["sites"] = ["not a site"]
        with self.assertRaises(ValueError):
            keys.body(forged, BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32))

    def test_the_body_needs_both_passphrases(self) -> None:
        draft = keys.review(evidence(), PreparationInputs())
        with self.assertRaises(ValueError):
            keys.body(draft.document, BodyContext("unit", BOOT, 0))


class RecordedKeyTests(ChangeTestCase):
    def test_the_recorded_key_list_names_the_current_key(self) -> None:
        self.assertEqual(
            keys_body.current_key(fixture("restic-key-list.json")),
            "0d9e6a0b6a0a1d0e5a5e6e3a9d8b7c6f5e4d3c2b1a09182736455463728190ab",
        )

    def test_a_key_list_without_a_current_key_is_refused(self) -> None:
        self.assertEqual(keys_body.current_key("[]"), "")
        self.assertEqual(keys_body.current_key("not json"), "")


class ReplaceRequestTests(ChangeTestCase):
    def test_the_settings_action_queues_the_reviewed_change(self) -> None:
        server = self.server
        record_backups(server, enabled=True)
        self.sign_in_with(
            "view_server", "view_changes", "change_site", "manage_secrets", "view_siteobservation"
        )
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/passphrase/prepare/", {}
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, keys.SLUG)
        self.assertEqual(preparation.inputs, {"version": 1})

    def test_a_missing_manage_secrets_permission_is_denied(self) -> None:
        server = self.server
        record_backups(server, enabled=True)
        self.sign_in_with("view_server", "view_changes", "change_site", "view_siteobservation")
        response = self.client.post(
            f"/servers/{server.pk}/settings/backup-storage/passphrase/prepare/", {}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())


class ReplaceApplyTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        confidential.reset()
        self.addCleanup(confidential.reset)

    def review(self) -> ChangeReview:
        draft = keys.review(evidence(), PreparationInputs())
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
            effects=[{"scope": "shared", "text": "Replace.", "sites": [IDENTIFIER]}],
            ssh_alias=self.server.ssh_alias,
            host_key=self.remote.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )

    def test_site_consent_cannot_replace_the_recovery_passphrase(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_replacing_rechecks_manage_secrets(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {
                "affected_sites": "on",
                "value_old_passphrase": "correct-horse-battery",
                "value_new_passphrase": "another-correct-horse",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_replacement_apply_needs_the_affected_sites_tick(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {
                "value_old_passphrase": "correct-horse-battery",
                "value_new_passphrase": "another-correct-horse",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.exists())

    def test_replacing_needs_csrf(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())
