"""Result reasons the backup, restore, reopen and integrity bodies print (#495, #502).

Every assertion observes what an operator reads for a reason the server reported, through
the engine's one wording lookup, rather than the shape of the declaration.
"""

import importlib.resources
from typing import override

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.reason_testing import assert_declared_sentences

from . import change, connect, export, keys, offsite, reopen, restore, retention
from .bodies.reasons import (
    CONNECT_REASONS,
    EXPORT_REASONS,
    OFFSITE_COPY_REASONS,
    OFFSITE_SETUP_REASONS,
    PASSPHRASE_REASONS,
    RETENTION_BODY_REASONS,
)


def integrity_source() -> str:
    return importlib.resources.files("backups.bodies").joinpath("integrity.py").read_text()


def body_sources() -> tuple[tuple[str, str], ...]:
    return (
        ("enable", change.ENABLE_SOURCE),
        ("back up now", change.BACKUP_SOURCE),
        ("full site", change.FULL_SOURCE),
        ("reopen", reopen.BODY_SOURCE),
        ("restore", restore.RESTORE_SOURCE),
        ("integrity", integrity_source()),
        ("offsite setup and removal", offsite.SETUP_SOURCE),
        ("copy offsite again", offsite.COPY_SOURCE),
        ("connect existing storage", connect.CONNECT_SOURCE),
        ("replace recovery passphrase", keys.KEYS_SOURCE),
        ("export", export.EXPORT_SOURCE),
        ("set or disable retention", retention.RETENTION_SOURCE),
        ("keep recovery point", retention.KEEP_SOURCE),
    )


class BackupReasonTests(SimpleTestCase):
    def test_a_backup_lock_reads_differently_when_the_site_was_busy_and_the_lock_was_held(
        self,
    ) -> None:
        refused = engine.reason_text("refused", "backup_lock")
        lock_busy = engine.reason_text("lock_busy", "backup_lock")

        self.assertIn("before the backup started", refused)
        self.assertNotIn("mutation lock", refused)
        self.assertIn("mutation lock", lock_busy)
        self.assertNotEqual(refused, lock_busy)

    def test_a_backup_refused_for_free_space_names_the_disk_cause(self) -> None:
        sentence = engine.reason_text("refused", "backup_disk")

        self.assertIn("free space", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_full_backup_refused_because_the_site_is_already_paused_names_the_pause(
        self,
    ) -> None:
        sentence = engine.reason_text("refused", "backup_gate")

        self.assertIn("already paused", sentence)
        self.assertIn("reopen", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_backup_that_stops_at_verification_names_verification(self) -> None:
        for outcome in ("failed", "partial"):
            with self.subTest(outcome=outcome):
                sentence = engine.reason_text(outcome, "backup_verify")
                self.assertIn("verif", sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_paused_full_point_that_stops_names_capture_and_leaves_reopen_meaningful(
        self,
    ) -> None:
        sentence = engine.reason_text("partial", "backup_paused")

        self.assertIn("captur", sentence)
        self.assertIn("Reopen site", sentence)
        self.assertNotIn("Nothing changed", sentence)

    def test_a_partial_capture_never_claims_nothing_changed(self) -> None:
        for reason in (
            "backup_partial",
            "backup_files",
            "backup_idle",
            "backup_paused",
            "backup_gate",
            "backup_verify",
        ):
            with self.subTest(reason=reason):
                sentence = engine.reason_text("partial", reason)
                self.assertNotIn("Nothing changed", sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class RestoreReasonTests(SimpleTestCase):
    def test_a_restore_lock_reads_differently_when_the_site_was_busy_and_the_lock_was_held(
        self,
    ) -> None:
        refused = engine.reason_text("refused", "restore_lock")
        lock_busy = engine.reason_text("lock_busy", "restore_lock")

        self.assertIn("before the restore started", refused)
        self.assertNotIn("mutation lock", refused)
        self.assertIn("mutation lock", lock_busy)
        self.assertNotEqual(refused, lock_busy)

    def test_a_restore_that_stops_names_the_step_that_stopped(self) -> None:
        steps = (
            ("partial", "restore_import", "database import"),
            ("partial", "restore_files", "files"),
            ("partial", "restore_config", "configuration"),
            ("refused", "restore_safety", "safety backup"),
            ("partial", "restore_readiness", "readiness"),
            ("partial", "restore_open", "Reopen site"),
        )
        for outcome, reason, words in steps:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_restore_that_completes_but_cannot_reopen_differs_from_one_stopped_mid_import(
        self,
    ) -> None:
        reopened = engine.reason_text("partial", "restore_open")
        imported = engine.reason_text("partial", "restore_import")

        self.assertNotEqual(reopened, imported)
        self.assertIn("Reopen site", reopened)
        self.assertIn("database import", imported)
        self.assertNotIn("database import", reopened)

    def test_a_partial_restore_never_claims_nothing_changed(self) -> None:
        for reason in (
            "restore_paused",
            "restore_idle",
            "restore_import",
            "restore_files",
            "restore_config",
            "restore_data",
            "restore_readiness",
            "restore_open",
        ):
            with self.subTest(reason=reason):
                sentence = engine.reason_text("partial", reason)
                self.assertNotIn("Nothing changed", sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class IntegrityReasonTests(SimpleTestCase):
    def test_an_integrity_failure_names_the_pack_readback_or_offsite_cause(self) -> None:
        causes = (
            ("failed", "integrity_pack", "pack"),
            ("failed", "integrity_readback", "read"),
            ("refused", "integrity_offsite", "offsite"),
        )
        for outcome, reason, words in causes:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class DeclaredReasonAssertions(SimpleTestCase):
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return ()

    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        assert_declared_sentences(
            self,
            (self.declared(),),
            skip_parse=frozenset({"backup_paused", "restore_paused"}),
        )
        for reason in self.declared():
            self.assertTrue(reasons.accepted(reason.name))


class OffsiteReasonTests(DeclaredReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return (*OFFSITE_SETUP_REASONS, *OFFSITE_COPY_REASONS)

    def test_setting_up_or_removing_offsite_storage_names_its_own_step(self) -> None:
        expected = {
            ("failed", "offsite_repository"): "repository",
            ("refused", "offsite_key"): "keys",
            ("refused", "offsite_bucket"): "bucket",
            ("failed", "offsite_remove"): "removal step",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_copying_offsite_again_names_the_copy_or_repository_step(self) -> None:
        copy = engine.reason_text("failed", "offsite_copy")
        repository = engine.reason_text("refused", "offsite_repository")

        self.assertIn("offsite copy", copy)
        self.assertIn("repository", repository)
        self.assertNotEqual(copy, repository)
        self.assertNotIn("without reporting how far it got", copy)
        self.assertNotIn("without reporting how far it got", repository)


class ConnectReasonTests(DeclaredReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return CONNECT_REASONS

    def test_connecting_existing_storage_names_review_key_settings_repository_or_password(
        self,
    ) -> None:
        expected = {
            ("failed", "connect_review"): "review",
            ("refused", "connect_key"): "access keys",
            ("refused", "connect_settings"): "settings",
            ("failed", "connect_repository"): "repository",
            ("refused", "connect_password"): "passphrase",
        }
        sentences: set[str] = set()
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)
                sentences.add(sentence)
        self.assertEqual(len(sentences), len(expected))


class PassphraseReasonTests(DeclaredReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return PASSPHRASE_REASONS

    def test_replacing_the_passphrase_names_review_value_new_old_repository_or_server_key(
        self,
    ) -> None:
        expected = {
            ("failed", "passphrase_review"): "review",
            ("refused", "passphrase_value"): "passphrase",
            ("failed", "passphrase_new"): "new passphrase",
            ("refused", "passphrase_old"): "current passphrase",
            ("refused", "passphrase_repository"): "repository",
            ("failed", "passphrase_server_key"): "server key",
            ("refused", "passphrase_key"): "key",
        }
        sentences: set[str] = set()
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)
                sentences.add(sentence)
        self.assertEqual(len(sentences), len(expected))


class ExportReasonTests(DeclaredReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return EXPORT_REASONS

    def test_an_export_that_stops_names_its_own_step(self) -> None:
        expected = {
            ("refused", "export_stage"): "staging",
            ("refused", "export_files"): "files",
            ("refused", "export_size"): "size",
            ("refused", "export_database"): "database",
            ("refused", "export_evidence"): "review",
            ("refused", "export_repository"): "repository",
            ("refused", "export_lock"): "lock",
            ("refused", "export_secret"): "private configuration",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class RetentionReasonTests(DeclaredReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return RETENTION_BODY_REASONS

    def test_retention_that_stops_names_the_evidence_site_or_verify_step(self) -> None:
        self.assertIn("evidence", engine.reason_text("refused", "evidence"))
        self.assertIn("site", engine.reason_text("refused", "backup_site"))
        self.assertIn("verif", engine.reason_text("partial", "backup_verify"))
        self.assertIn("clock", engine.reason_text("refused", "cleanup_clock"))

    def test_keeping_a_recovery_point_names_its_cause(self) -> None:
        causes = (
            ("refused", "evidence", "evidence"),
            ("lock_busy", "backup_lock", "lock"),
            ("failed", "backup_unknown", "tool"),
            ("partial", "backup_verify", "verif"),
        )
        for outcome, reason, words in causes:
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class VocabularyTests(SimpleTestCase):
    def test_no_reason_these_bodies_print_falls_back_to_the_class_sentence(self) -> None:
        generic = set(reasons.OUTCOME_SENTENCES.values())
        for label, text in body_sources():
            for reason, classes in reasons.printed_pairs(text).items():
                if not reason:
                    continue
                for result_class in classes:
                    if result_class == "succeeded":
                        continue
                    with self.subTest(body=label, reason=reason, outcome=result_class):
                        sentence = engine.reason_text(result_class, reason)
                        self.assertTrue(sentence)
                        self.assertNotIn(sentence, generic)

    def test_the_manifest_has_no_drift(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])

    def test_dynamic_capture_and_restore_reasons_have_their_own_sentence(self) -> None:
        dynamic = (
            ("refused", "backup_password"),
            ("refused", "backup_dump"),
            ("failed", "backup_unknown"),
            ("refused", "offsite_key"),
            ("failed", "offsite_copy"),
            ("failed", "offsite_repository"),
            ("refused", "restore_engine"),
            ("refused", "restore_dump"),
            ("refused", "restore_gate"),
            ("partial", "restore_idle"),
        )
        generic = set(reasons.OUTCOME_SENTENCES.values())
        for outcome, reason in dynamic:
            with self.subTest(reason=reason, outcome=outcome):
                sentence = engine.reason_text(outcome, reason)
                self.assertTrue(sentence)
                self.assertNotIn(sentence, generic)

    def test_the_integrity_body_vocabulary_is_registered(self) -> None:
        for reason in ("integrity_pack", "integrity_readback", "integrity_offsite"):
            with self.subTest(reason=reason):
                self.assertTrue(reasons.accepted(reason))
