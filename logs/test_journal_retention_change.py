"""The reviewed log retention change, its native body and its verification (#551).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md.
"""

import hashlib
import io
import os
import stat
import tempfile
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from logs import journal_retention_change
from logs.bodies import journal_retention as native
from logs.journal_retention import (
    DISK_CAP_CHOICES,
    MANAGED,
    MAX_AGE_CHOICES,
    NOT_CONFIGURED,
    OUTSIDE,
    RETENTION_PATH,
    RetentionObservation,
    render,
)
from operations import engine
from operations.consent import Scope
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    RemoteOperation,
    Result,
)
from operations.recovery_testing import assert_policy_failure

from .journal_retention_change import (
    BODY_SHA256,
    SLUG,
    JournalRetentionEvidence,
    body,
    encode_document,
    inspect,
    review,
    verify,
)

BOOT = "12345678-1234-1234-1234-123456789abc"


def evidence(**overrides: object) -> JournalRetentionEvidence:
    values: dict[str, object] = {
        "standing": Standing.TARGET_STACK,
        "boot_id": BOOT,
        "uptime_centiseconds": 1000,
        "observation": RetentionObservation(MANAGED, "", "1G", "1month"),
        "previous": render("1G", "1month"),
        "previous_disk_cap": "1G",
        "previous_max_age": "1month",
    }
    values.update(overrides)
    return JournalRetentionEvidence(**values)  # type: ignore[arg-type]


def inputs(disk_cap: str = "2G", max_age: str = "3months") -> PreparationInputs:
    return PreparationInputs(disk_cap=disk_cap, max_age=max_age)


def document(
    *,
    disk_cap: str = "2G",
    max_age: str = "3months",
    previous: str | None = None,
    previous_disk_cap: str = "",
    previous_max_age: str = "",
) -> dict[str, object]:
    return {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "path": RETENTION_PATH,
        "disk_cap": disk_cap,
        "max_age": max_age,
        "retention": render(disk_cap, max_age),
        "previous": previous,
        "previous_disk_cap": previous_disk_cap,
        "previous_max_age": previous_max_age,
    }


class InputTests(SimpleTestCase):
    def test_the_pair_round_trips_as_the_reviewed_document(self) -> None:
        decoded = decode_inputs(
            {"version": 1, "disk_cap": "500M", "max_age": "6months"},
            (),
            InputShape.JOURNAL_RETENTION,
        )
        self.assertEqual((decoded.disk_cap, decoded.max_age), ("500M", "6months"))
        self.assertEqual(
            decoded.document(),
            {"version": 1, "disk_cap": "500M", "max_age": "6months"},
        )

    def test_every_supported_pair_decodes(self) -> None:
        for disk_cap in DISK_CAP_CHOICES:
            for max_age in MAX_AGE_CHOICES:
                with self.subTest(disk_cap=disk_cap, max_age=max_age):
                    decoded = decode_inputs(
                        {"version": 1, "disk_cap": disk_cap, "max_age": max_age},
                        (),
                        InputShape.JOURNAL_RETENTION,
                    )
                    self.assertEqual(decoded.disk_cap, disk_cap)
                    self.assertEqual(decoded.max_age, max_age)

    def test_forged_free_text_boolean_and_out_of_list_values_are_refused(self) -> None:
        for value in (
            {"version": 1, "disk_cap": "1G"},
            {"version": 1, "disk_cap": "1G", "max_age": "3months", "extra": "x"},
            {"version": 1, "disk_cap": True, "max_age": "3months"},
            {"version": 1, "disk_cap": "1G", "max_age": False},
            {"version": 1, "disk_cap": 1, "max_age": "3months"},
            {"version": 1, "disk_cap": "5G", "max_age": "3months"},
            {"version": 1, "disk_cap": "1G", "max_age": "2weeks"},
            {"version": 1, "disk_cap": " 1G", "max_age": "3months"},
            {"version": 2, "disk_cap": "1G", "max_age": "3months"},
            {"version": 1, "disk_cap": "1G", "max_age": "3months", "selection": "x"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.JOURNAL_RETENTION)


class ReviewTests(SimpleTestCase):
    def test_the_review_names_the_file_values_restart_and_no_vacuum_boundary(self) -> None:
        draft = review(evidence(), inputs("2G", "3months"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.kind, SLUG)
        self.assertEqual(draft.stages, ("preflight", "publish", "verify"))
        self.assertEqual(draft.document["version"], 1)
        self.assertEqual(draft.document["body_sha256"], BODY_SHA256)
        self.assertEqual(draft.document["disk_cap"], "2G")
        self.assertEqual(draft.document["max_age"], "3months")
        self.assertEqual(draft.document["disk_cap_label"], "2 GiB")
        self.assertEqual(draft.document["max_age_label"], "3 months")
        self.assertEqual(draft.document["retention"], render("2G", "3months"))
        self.assertEqual(draft.document["previous"], render("1G", "1month"))
        details = cast(list[dict[str, str]], draft.document["details"])
        text = " ".join(f"{item['label']} {item['value']}" for item in details)
        self.assertIn(RETENTION_PATH, text)
        self.assertIn("root:root, 0644", text)
        self.assertIn("1 GiB", text)
        self.assertIn("2 GiB", text)
        self.assertIn("3 months", text)
        self.assertIn("Restart systemd-journald", text)
        self.assertIn("No logs are deleted and no vacuum runs", text)
        self.assertIn("reclaims space itself", text)

    def test_the_review_is_one_shared_server_effect_without_data_loss(self) -> None:
        draft = review(evidence(), inputs())
        effects = draft.effects
        self.assertEqual(len(effects), 1)
        self.assertIs(effects[0].scope, Scope.SERVER)
        self.assertFalse(effects[0].destroys_data)
        self.assertEqual(effects[0].sites, ())
        self.assertEqual(draft.kind, "set_journal_retention")

    def test_an_unchanged_pair_is_a_no_change_review(self) -> None:
        draft = review(evidence(), inputs("1G", "1month"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already follows", str(draft.document["note"]))

    def test_an_outside_state_is_refused_with_its_plain_reason(self) -> None:
        draft = review(
            evidence(
                observation=RetentionObservation(
                    OUTSIDE, "A later configuration overrides the retention setting."
                ),
                previous=None,
            ),
            inputs(),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("outside supported settings", " ".join(draft.refusals))
        self.assertIn("later configuration overrides", " ".join(draft.refusals))

    def test_a_host_not_on_the_target_stack_is_refused(self) -> None:
        draft = review(evidence(standing=Standing.FRESH), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("host foundation", " ".join(draft.refusals))

    def test_an_unreadable_fixed_read_is_refused(self) -> None:
        draft = review(evidence(observation=None), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("could not be read", " ".join(draft.refusals))

    def test_an_unreadable_clock_or_effective_value_is_refused(self) -> None:
        for item in (
            evidence(boot_id=""),
            evidence(uptime_centiseconds=None),
            evidence(previous_disk_cap="10% extra"),
            evidence(previous_max_age="\n"),
        ):
            with self.subTest(item=item):
                draft = review(item, inputs())
                self.assertFalse(draft.eligible)
                self.assertIn("could not be read", " ".join(draft.refusals))

    def test_a_candidate_larger_than_the_argument_bound_is_refused(self) -> None:
        with mock.patch.object(journal_retention_change, "MAX_ARGUMENT", 10):
            draft = review(evidence(), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("larger than one change", " ".join(draft.refusals))

    def test_the_inspection_reconstructs_the_review_from_one_foundation_read(self) -> None:
        collected: CollectedSnapshot = replace(
            COLLECTED,
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            # A torn earlier collect must not supply the review's previous facts.
            journal_retention=RetentionObservation(MANAGED, "", "1G", "1month"),
        )
        values = {
            "boot": BOOT,
            "uptime": "2500",
            "journal_retention_file": (
                "0 0 644 1 file " + hashlib.sha256(render("2G", "3months").encode()).hexdigest()
            ),
            "journal_system_max_use": "2G",
            "journal_max_retention": "3months",
        }
        with (
            mock.patch("discovery.observations.collect", return_value=collected) as collected_read,
            mock.patch("bootstrap.foundation.read", return_value=values) as foundation_read,
        ):
            observed = inspect(cast(RemoteShell, object()), inputs())
        collected_read.assert_called_once()
        foundation_read.assert_called_once()
        self.assertEqual(observed.standing, Standing.TARGET_STACK)
        self.assertEqual(observed.boot_id, BOOT)
        self.assertEqual(observed.uptime_centiseconds, 2500)
        self.assertEqual(observed.observation, RetentionObservation(MANAGED, "", "2G", "3months"))
        self.assertEqual(observed.previous, render("2G", "3months"))
        self.assertEqual(observed.previous_disk_cap, "2G")
        self.assertEqual(observed.previous_max_age, "3months")

    def test_a_missing_foundation_read_makes_the_observation_unreadable(self) -> None:
        collected: CollectedSnapshot = replace(
            COLLECTED,
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            journal_retention=RetentionObservation(NOT_CONFIGURED),
        )
        with (
            mock.patch("discovery.observations.collect", return_value=collected),
            mock.patch("bootstrap.foundation.read", return_value=None),
        ):
            observed = inspect(cast(RemoteShell, object()), inputs())
        self.assertIsNone(observed.observation)
        self.assertIsNone(observed.previous)


class BodyDocumentTests(SimpleTestCase):
    def test_the_reviewed_document_builds_one_native_argument(self) -> None:
        native_body = body(document(), BodyContext("", "", 0))
        self.assertTrue(native_body.source.startswith(b"#!/bin/sh\n"))
        self.assertEqual(len(native_body.arguments), 1)
        self.assertEqual(native_body.arguments[0], encode_document(document()))

    def test_a_forged_document_is_refused_before_apply(self) -> None:
        forged = (
            {**document(), "version": 2},
            {**document(), "version": True},
            {**document(), "body_sha256": "0" * 64},
            {**document(), "disk_cap": "5G"},
            {**document(), "max_age": "2weeks"},
            {**document(), "retention": "[Journal]\nSystemMaxUse=4G\nMaxRetentionSec=1year\n"},
            {**document(), "path": "/etc/systemd/journald.conf.d/90-later.conf"},
            {**document(), "previous": "not the reviewed file"},
            {**document(), "previous_disk_cap": "10% extra"},
            {**document(), "previous_max_age": True},
        )
        for value in forged:
            with self.subTest(value=value), self.assertRaises(ValueError):
                body(value, BodyContext("", "", 0))
        # The reviewed previous file must be exactly one rendered pair.
        with self.assertRaises(ValueError):
            body(
                document(previous="[Journal]\nSystemMaxUse=1G\nMaxRetentionSec=1month\n# x\n"),
                BodyContext("", "", 0),
            )


class VerifyTests(SimpleTestCase):
    def stored(self) -> ChangeReview:
        return cast(ChangeReview, mock.Mock(document=document()))

    def test_verification_succeeds_only_for_the_reviewed_managed_pair(self) -> None:
        for retention, expected in (
            (RetentionObservation(MANAGED, "", "2G", "3months"), True),
            (RetentionObservation(MANAGED, "", "1G", "3months"), False),
            (RetentionObservation(MANAGED, "", "2G", "1month"), False),
            (RetentionObservation(NOT_CONFIGURED), False),
            (RetentionObservation(OUTSIDE, "later override"), False),
        ):
            collected: CollectedSnapshot = replace(COLLECTED, journal_retention=retention)
            with (
                self.subTest(retention=retention),
                mock.patch("discovery.observations.collect", return_value=collected),
            ):
                self.assertIs(verify(cast(RemoteShell, object()), self.stored()), expected)

    def test_verification_is_unavailable_when_the_read_failed(self) -> None:
        collected: CollectedSnapshot = replace(COLLECTED, journal_retention=None)
        with mock.patch("discovery.observations.collect", return_value=collected):
            self.assertIsNone(verify(cast(RemoteShell, object()), self.stored()))


class NativeBodyTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / "60-barectl-log-retention.conf"
        self.patch = mock.patch.multiple(
            native,
            DIRECTORY=self.directory,
            PATH=self.path,
            ROOT_UID=os.getuid(),
            ROOT_GID=os.getgid(),
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.restart_mock = mock.Mock()
        self.restart = mock.patch.object(native, "restart", self.restart_mock)
        self.restart.start()
        self.addCleanup(self.restart.stop)

    def run_body(
        self,
        value: dict[str, object],
        merged: list[tuple[str, str]],
    ) -> str:
        with mock.patch.object(native, "merged", side_effect=merged) as read:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(native.main([encode_document(value)]), 0)
        self.assertEqual(read.call_count, len(merged))
        return output.getvalue()

    def test_a_new_file_is_written_atomically_restarted_and_read_back(self) -> None:
        result = self.run_body(
            document(),
            [("", ""), ("2G", "3months"), ("2G", "3months")],
        )
        self.assertIn('"class": "succeeded"', result)
        self.assertEqual(self.path.read_text(), render("2G", "3months"))
        info = self.path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_gid, os.getgid())
        self.restart_mock.assert_called_once()

    def test_a_missing_drop_in_directory_is_created(self) -> None:
        directory = self.directory / "journald.conf.d"
        path = directory / "60-barectl-log-retention.conf"
        with mock.patch.multiple(native, DIRECTORY=directory, PATH=path):
            result = self.run_body(
                document(),
                [("", ""), ("2G", "3months"), ("2G", "3months")],
            )
        self.assertIn('"class": "succeeded"', result)
        self.assertEqual(path.read_text(), render("2G", "3months"))
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)

    def test_a_changed_previous_file_is_refused_before_any_write(self) -> None:
        self.path.write_text(render("1G", "1month"))
        result = self.run_body(
            document(previous=None),
            [],
        )
        self.assertIn('"reason": "precondition"', result)
        self.assertEqual(self.path.read_text(), render("1G", "1month"))

    def test_a_changed_effective_value_is_refused_before_any_write(self) -> None:
        result = self.run_body(
            document(),
            [("10%", "")],
        )
        self.assertIn('"reason": "precondition"', result)
        self.assertFalse(self.path.exists())

    def test_a_later_override_restores_the_previous_file_and_refuses(self) -> None:
        previous = render("1G", "1month")
        self.path.write_text(previous)
        result = self.run_body(
            document(previous=previous, previous_disk_cap="1G", previous_max_age="1month"),
            [("1G", "1month"), ("2G", "3months"), ("9G", "1month")],
        )
        self.assertIn('"class": "refused"', result)
        self.assertIn('"reason": "journal_retention"', result)
        self.assertEqual(self.path.read_text(), previous)

    def test_a_failed_restart_restores_the_previous_file_and_refuses(self) -> None:
        previous = render("1G", "1month")
        self.path.write_text(previous)
        self.restart_mock.side_effect = [ValueError("restart failed"), None]
        result = self.run_body(
            document(previous=previous, previous_disk_cap="1G", previous_max_age="1month"),
            [("1G", "1month"), ("2G", "3months")],
        )
        self.assertIn('"class": "refused"', result)
        self.assertEqual(self.path.read_text(), previous)

    def test_a_failed_restoration_reports_partial_with_one_recovery_action(self) -> None:
        previous = render("1G", "1month")
        self.path.write_text(previous)
        self.restart_mock.side_effect = [ValueError("restart failed"), ValueError("restore failed")]
        result = self.run_body(
            document(previous=previous, previous_disk_cap="1G", previous_max_age="1month"),
            [("1G", "1month"), ("2G", "3months")],
        )
        self.assertIn('"class": "partial"', result)
        self.assertIn('"reason": "journal_retention"', result)
        sentence = engine.reason_text(Result.PARTIAL, "journal_retention")
        preparation = ChangePreparation(pk=1, kind_slug=SLUG)
        review = ChangeReview(
            preparation=preparation,
            kind_slug=SLUG,
            consent=Consent.SHARED,
            document={"stages": list(journal_retention_change.STAGES)},
        )
        run = ChangeRun(
            pk=1,
            review=review,
            status=RemoteOperation.Status.FAILED,
            execution=Result.PARTIAL,
            result_reason="journal_retention",
            server_name="Contract server",
            failure=sentence,
        )
        assert_policy_failure(self, run, sentence=sentence)

    def test_a_forged_argument_prints_only_a_refusal_and_writes_nothing(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(native.main(["not-the-reviewed-document"]), 0)
        self.assertIn('"class": "refused"', output.getvalue())
        self.assertIn('"reason": "evidence"', output.getvalue())
        self.assertFalse(self.path.exists())
        self.restart_mock.assert_not_called()

    def test_the_body_never_vacuums_or_deletes_journals(self) -> None:
        source = journal_retention_change.BODY_SOURCE
        self.assertNotIn("--vacuum", source)
        self.assertNotIn("journalctl", source)

    def test_the_merged_configuration_takes_the_last_assignment(self) -> None:
        text = (
            "# /etc/systemd/journald.conf\n"
            "SystemMaxUse=500M\n"
            "# /etc/systemd/journald.conf.d/50-barectl.conf\n"
            "Storage=persistent\n"
            "SystemMaxUse=1G\n"
            "MaxRetentionSec=1month\n"
            "MaxRetentionSec=3months\n"
        )
        with mock.patch.object(native, "run", return_value=text):
            self.assertEqual(native.merged(), ("1G", "3months"))

    def test_the_body_renders_the_same_pairs_as_the_pure_seam(self) -> None:
        for disk_cap in DISK_CAP_CHOICES:
            for max_age in MAX_AGE_CHOICES:
                with self.subTest(disk_cap=disk_cap, max_age=max_age):
                    self.assertEqual(native.render(disk_cap, max_age), render(disk_cap, max_age))
