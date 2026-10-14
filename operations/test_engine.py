"""The change engine's workflow: one submission per review, reconciliation instead of
replay, effect-derived consent enforced at the boundaries, and the operator's message for
every outcome class (docs/adr/0035-one-change-engine-with-effect-derived-consent.md).

The fast tests replay the adapter's recorded ``systemctl show`` and journal output for
each outcome; the native suites keep proving the adapter against real systemd until the
new harness replaces them.
"""

import hashlib
import json
from dataclasses import replace
from datetime import timedelta
from typing import override

from django.contrib.auth.models import Group
from django.db.models import ProtectedError
from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, COLLECTED_AT, FakeServer
from discovery.models import DiscoveryAttempt
from discovery.root_read import run_root
from discovery.snapshot import save_snapshot
from operations.models import RemoteOperation
from servers.registration import RemovalBlocked, remove_server

from . import engine, native
from .consent import DeclaredEffect, Scope
from .fakes import (
    BOOT_ID,
    PREPARE_PERMISSIONS,
    RECORDED_SYSTEMD_BOOT_ID,
    RECORDED_SYSTEMD_UNIT,
    ChangeTestCase,
    EngineSystemd,
    finished_unit,
)
from .models import ChangePreparation, ChangeReview, ChangeRun, Consent, Result, Verification

Status = RemoteOperation.Status
EXITED = "barectl-apply-" + "a" * 32 + ".service"

# A second registered kind, whose review declares two affected sites and the fixed read
# that lists them, to exercise the engine's Shared machinery natively without a site app.
SITES_READ = "printf 'alpha\\nbeta\\n' | LC_ALL=C sort"
SITES_OUTPUT = "alpha\nbeta\n"
SITES_DIGEST = hashlib.sha256(b"alpha\nbeta\n").hexdigest()
FIXTURE_BODY = b"#!/bin/sh\nexit 0"


def _fixture_review(evidence: object) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_sites",
        intent="Exercise the engine's shared consent machinery.",
        effects=(DeclaredEffect(Scope.SHARED, "Touches the shared master.", ("alpha", "beta")),),
        stages=("Take the mutation lock and admit the reviewed change", "Do the shared work"),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        sites_read=SITES_READ,
        document={"version": 1, "body_sha256": hashlib.sha256(FIXTURE_BODY).hexdigest()},
    )


def _fixture_body(document: dict[str, object], context: engine.BodyContext) -> engine.NativeBody:
    return engine.NativeBody(FIXTURE_BODY)


SITE_KIND = engine.ChangeKind(
    slug="fixture_sites",
    label="Fixture shared change",
    inspect=lambda shell: None,
    review=_fixture_review,
    body=_fixture_body,
    verify=lambda shell, review: True,
)


class SiteKindTestCase(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        engine.register_kind(SITE_KIND)
        self.addCleanup(engine._KINDS.pop, "fixture_sites", None)
        from discovery.ssh import CommandResult

        self.remote.results[SITES_READ] = CommandResult(0, SITES_OUTPUT)

    @override
    def assert_read_only(self) -> None:
        # The fixture kind's fixed affected-sites read is part of preparing a review.
        self.remote.commands[:] = [
            command for command in self.remote.commands if command != SITES_READ
        ]
        super().assert_read_only()


class EngineAdapterTests(SimpleTestCase):
    def test_unanswered_root_reads_never_become_closure_probe_evidence(self) -> None:
        remote = FakeServer()
        systemd = EngineSystemd()
        systemd.answer(remote)
        for command in ("id -u", "ss -Hlnpt '( sport = :80 or sport = :443 )'"):
            with self.subTest(command=command):
                result = run_root(remote, command)
                self.assertNotEqual(result.exit_status, 0)
                self.assertEqual(result.stdout, "")
        self.assertEqual(systemd.probes, 0)


class EngineWorkflowTests(ChangeTestCase):
    def test_verified_resource_change_queues_fresh_discovery(self) -> None:
        from .cleanup import SLUG

        kind = engine.kind_of(SLUG)
        if kind is None:
            self.fail("Cleanup must be registered.")
        engine._KINDS[kind.slug] = replace(kind, refresh_discovery=True)
        self.addCleanup(engine._KINDS.__setitem__, kind.slug, kind)
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        before = DiscoveryAttempt.objects.count()
        self.sign_in_with("view_server", "view_changes", "change_shared", "add_discoveryattempt")
        self.client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.run_worker()
        run = ChangeRun.objects.get(review=review)
        self.assertEqual(run.status, Status.SUCCEEDED)
        self.assertEqual(DiscoveryAttempt.objects.count(), before + 1)
        queued = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(queued.connection_id, run.connection_id)
        self.assertEqual(queued.requested_by_id, run.requested_by_id)
        self.assertEqual(queued.status, Status.SUCCEEDED, queued.failure)

    def test_a_reviewed_change_runs_once_natively_and_is_audited(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        run = self.apply(review)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Result.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assert_replayed_collected_unit(run)
        self.assertEqual(len(self.systemd.submissions), 1)
        self.assertIn("--collect", self.systemd.submissions[0])
        # The run refers to the one stored review; it copies nothing.
        self.assertEqual(run.review, review)
        self.assertNotIn(EXITED, self.systemd.units)

    def test_duplicate_requests_converge_on_one_run(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.sign_in_with("view_changes", "change_shared")
        first = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        second = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(ChangeRun.objects.count(), 1)

    def test_a_failed_unit_reports_the_unknown_extent(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.result_class = "failed"
        run = self.apply(review)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Result.FAILED)
        self.assertIn("what changed is unknown", run.failure)
        self.assert_replayed_collected_unit(run)

    def test_a_timed_out_unit_is_distinguished(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.result_class = "timed_out"
        run = self.apply(review)
        self.assertEqual(run.execution, Result.TIMED_OUT)
        self.assertIn("30min limit", run.failure)
        self.assert_replayed_collected_unit(run)

    def test_a_held_lock_stops_before_any_change(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.result_class = "lock_busy"
        run = self.apply(review)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Result.LOCK_BUSY)
        self.assertIn("held Barectl's mutation lock", run.failure)
        self.assertIn(EXITED, self.systemd.units)
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "The run stopped before making any requested change.")
        self.assert_replayed_collected_unit(run)

    def test_a_rejected_submission_created_nothing(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.reject = True
        run = self.apply(review)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Result.NOT_SUBMITTED)
        self.assertIn("systemd refused the submission", run.failure)

    def test_the_account_is_rechecked_before_submission(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.sign_in_with("view_changes", "change_shared")
        self.client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.user.user_permissions.clear()
        self.run_worker()
        run = ChangeRun.objects.get()
        self.assertEqual(run.status, Status.FAILED)
        self.assertIn("no longer allowed to apply", run.failure)
        self.assertFalse(self.systemd.submissions)

    def test_a_changed_host_key_submits_nothing(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.remote.host_key = "ssh-ed25519 SHA256:different"
        run = self.apply(review)
        self.assertIn("presented a different host key", run.failure)
        self.assertFalse(self.systemd.submissions)

    def test_the_retained_units_are_checked_before_submitting(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        # A cleanup stays available at the shared namespace's limit: it clears the units.
        self.systemd.retained = native.RETAINED_LIMIT
        run = self.apply(self.change())
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        # Beyond its own ceiling, even a cleanup is refused before submitting.
        self.systemd.units[EXITED] = finished_unit(1)
        self.systemd.retained = native.CLEANUP_CEILING
        run = self.apply(self.change())
        self.assertIn("more than a reviewed cleanup may add to", run.failure)
        self.assertEqual(run.execution, Result.NOT_SUBMITTED)
        self.assertFalse(self.systemd.submissions[1:])


class RetainedNamespaceTests(SiteKindTestCase):
    def test_a_kind_without_a_ceiling_is_refused_at_the_limit(self) -> None:
        self.systemd.retained = native.RETAINED_LIMIT
        review = self.change("fixture_sites")
        run = self.apply(review)
        self.assertIn("keeps 100 or more finished barectl runs", run.failure)
        self.assertEqual(run.execution, Result.NOT_SUBMITTED)
        self.assertFalse(self.systemd.submissions)


class EngineReconciliationTests(ChangeTestCase):
    def lost(self) -> ChangeRun:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.lose_acknowledgement = True
        run = self.apply(review)
        self.assertEqual(run.status, Status.RECONCILING)
        return run

    def test_a_lost_acknowledgement_reconciles_without_submitting_again(self) -> None:
        run = self.lost()
        self.assertEqual(len(self.systemd.submissions), 1)
        self.assertIn("does not know whether the server received it", run.failure)
        # The check reads the journal of the same unit and closes the run.
        self.systemd.lose_acknowledgement = False
        checked = self.check(run)
        self.assertEqual(checked.status, Status.SUCCEEDED, checked.failure)
        self.assertEqual(len(self.systemd.submissions), 1)
        self.assert_replayed_collected_unit(checked)

    def test_missing_evidence_without_a_result_line_stays_reconciling(self) -> None:
        run = self.lost()
        self.systemd.units[run.unit_name].result_class = None
        checked = self.check(run)
        self.assertEqual(checked.status, Status.RECONCILING)
        self.assertEqual(checked.execution, Result.NOT_FOUND)
        self.assertIn("no result line in its journal", checked.failure)

    def test_closing_unknown_needs_proof_and_an_acknowledgement(self) -> None:
        run = self.lost()
        self.systemd.units[run.unit_name].result_class = None
        self.systemd.probe_populated = 1
        acknowledged = self.check(run)
        self.sign_in_with("view_changes", "change_shared")
        # Without the acknowledgement, the check leaves the run reconciling.
        run = self.check(acknowledged)
        self.assertEqual(run.status, Status.RECONCILING)
        self.client.post(f"/runs/{run.pk}/acknowledge/", {"understood": "on"})
        self.run_worker()
        run = ChangeRun.objects.get(pk=run.pk)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("still has processes", run.closure_blocked)
        # Past the admission deadline, with the lock free and nothing running, it closes.
        self.systemd.probe_populated = 0
        self.systemd.uptime_centiseconds = 10**9
        self.client.post(f"/runs/{run.pk}/acknowledge/", {"understood": "on"})
        self.run_worker()
        run = ChangeRun.objects.get(pk=run.pk)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Result.OUTCOME_UNKNOWN)
        self.assertIn("Outcome unknown", run.failure)
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "this run may have changed the server")
        self.assertContains(page, "Acknowledged by")

    def test_a_held_lock_probe_does_not_close_the_run(self) -> None:
        run = self.lost()
        self.systemd.units[run.unit_name].result_class = None
        self.systemd.probe_exit = native.Probe.LOCK_CONFLICT
        self.systemd.uptime_centiseconds = 10**9
        run = self.check(run)
        self.sign_in_with("view_changes", "change_shared")
        self.client.post(f"/runs/{run.pk}/acknowledge/", {"understood": "on"})
        self.run_worker()
        run = ChangeRun.objects.get(pk=run.pk)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("held Barectl's mutation lock", run.closure_blocked)

    def test_only_a_reconciling_run_can_be_checked(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        run = self.apply(self.change())
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(f"/runs/{run.pk}/check/")
        self.assertRedirects(response, f"/runs/{run.pk}/")
        self.assertEqual(ChangeRun.objects.get(pk=run.pk).status, Status.SUCCEEDED)

    def test_an_abandoned_dispatched_run_reconciles(self) -> None:
        run = self.lost()
        RemoteOperation.objects.filter(pk=run.pk).update(
            started_at=timezone.now() - timedelta(minutes=11)
        )
        self.systemd.lose_acknowledgement = False
        # Any engine service entry recovers abandoned operations first.
        from . import services

        services.read_run(run.pk)
        run = ChangeRun.objects.get(pk=run.pk)
        self.assertEqual(run.status, Status.RECONCILING)


class SharedConsentTests(SiteKindTestCase):
    def test_a_shared_review_lists_and_digests_its_affected_sites(self) -> None:
        review = self.change("fixture_sites")
        self.assertEqual(review.consent, Consent.SHARED)
        self.assertEqual(review.affected_sites, ["alpha", "beta"])
        self.assertEqual(review.sites_read, SITES_READ)
        self.assertTrue(review.sites_digest)
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, "alpha, beta")
        self.assertContains(page, "rechecked under the mutation lock")

    def test_review_refuses_when_the_sites_read_disagrees_with_declared_effects(self) -> None:
        from discovery.ssh import CommandResult

        self.remote.results[SITES_READ] = CommandResult(0, "alpha\ngamma\n")
        preparation = self.prepare("fixture_sites")
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertIsNone(ChangeReview.objects.filter(preparation=preparation).first())
        self.assertIn("could not read", preparation.failure.lower())

    def test_review_refuses_a_failed_sites_read_even_when_it_prints_the_reviewed_list(self) -> None:
        from discovery.ssh import CommandResult

        self.remote.results[SITES_READ] = CommandResult(1, SITES_OUTPUT)
        preparation = self.prepare("fixture_sites")
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertIsNone(ChangeReview.objects.filter(preparation=preparation).first())
        self.assertIn("could not read", preparation.failure.lower())

    def test_a_shared_apply_requires_acknowledging_the_listed_sites(self) -> None:
        review = self.change("fixture_sites")
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(f"/changes/{review.preparation_id}/apply/", {})
        self.assertRedirects(response, f"/changes/{review.preparation_id}/")
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_changed_sites_digest_under_the_lock_refuses_and_changes_nothing(self) -> None:
        review = self.change("fixture_sites")
        self.systemd.result_class = "refused"
        self.systemd.reason = "affected_sites"
        run = self.apply(review)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Result.REFUSED)
        self.assertEqual(run.result_reason, "affected_sites")
        self.assertIn("affected sites changed, review again", run.failure.lower())
        self.assertIn("Affected sites changed, review again", run.failure)
        self.assert_replayed_collected_unit(run)
        self.assertEqual(len(self.systemd.submissions), 1)
        # The payload really carries the reviewed digest under the lock, before the body.
        payload = self.systemd.submissions[0]
        self.assertIn(SITES_DIGEST, payload)
        self.assertIn('"class":"refused","reason":"affected_sites"', payload)
        self.assertIn("sites=$(printf", payload)
        self.assertIn("LC_ALL=C sort) ||", payload)
        self.assertGreater(payload.index("digest=$(printf"), payload.index("sites=$(printf"))
        lock = payload.index("flock -n 9")
        sites = payload.index(SITES_DIGEST)
        self.assertLess(lock, sites)

    def test_a_sites_digest_is_only_checked_when_the_review_names_sites(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()  # the cleanup kind names no site
        self.assertEqual(review.sites_read, "")
        self.assertFalse(review.sites_digest)
        self.apply(review)
        self.assertNotIn(SITES_READ, self.systemd.submissions[0])
        self.assertNotIn("affected_sites", self.systemd.submissions[0])


class EngineAccessTests(ChangeTestCase):
    def test_a_viewer_cannot_prepare_and_sees_no_control(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        self.sign_in_with("view_server", "view_changes")
        page = self.client.get(f"/servers/{self.server.pk}/changes/")
        self.assertContains(page, "may view changes but not prepare them")
        self.assertNotIn("Prepare clear finished barectl runs", page.content.decode())

        response = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_not_manageable_standing_hides_and_refuses_direct_preparation(self) -> None:
        self.sign_in_with(*PREPARE_PERMISSIONS)
        attempt = DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=RemoteOperation.Status.SUCCEEDED,
            finished_at=COLLECTED_AT,
        )
        standing = HostJudgment(
            Standing.NOT_MANAGEABLE,
            ("Another web stack is installed: Apache.",),
            (),
            (),
        )
        save_snapshot(attempt, replace(COLLECTED, standing=standing), COLLECTED_AT)

        page = self.client.get(f"/servers/{self.server.pk}/changes/")
        self.assertNotIn("Prepare clear finished barectl runs", page.content.decode())
        response = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"}
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_a_site_operator_cannot_apply_a_shared_change(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.sign_in_with("view_server", "view_changes", "change_site")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertNotIn("Apply review", page.content.decode())
        self.assertIn(
            "needs the permission applying this consent level requires", page.content.decode()
        )
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_the_worker_rechecks_the_prepare_permission(self) -> None:
        self.sign_in_with("view_server", "view_changes", "change_site")
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"})
        self.user.user_permissions.clear()
        self.run_worker()
        preparation = ChangePreparation.objects.get()
        self.assertIn("no longer allowed to prepare", preparation.failure)

    def test_the_group_presets_grant_the_scopes(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.user.groups.add(Group.objects.get(name="Site operator"))
        self.client.force_login(self.user)
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertNotIn("Apply review", page.content.decode())
        self.user.groups.add(Group.objects.get(name="Administrator"))
        self.client.force_login(self.user)
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertIn("Apply review", page.content.decode())


class EngineRecordTests(ChangeTestCase):
    def test_a_runs_reference_protects_its_review(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        run = self.apply(review)
        with self.assertRaises(ProtectedError):
            review.delete()
        self.assertEqual(run.review, ChangeReview.objects.get(pk=review.pk))

    def test_removal_keeps_the_run_and_its_review_as_audit(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        unapplied = self.change()
        run = self.apply(review)
        remove_server(self.server)
        kept = ChangeRun.objects.get(pk=run.pk)
        self.assertIsNone(kept.server)
        self.assertEqual(kept.review, review)
        self.assertEqual(kept.server_name, "Web")
        # The unapplied review went with its preparation; the run's did not.
        self.assertFalse(ChangeReview.objects.filter(pk=unapplied.pk).exists())
        review.refresh_from_db()
        self.assertIsNone(review.preparation)

    def test_removal_waits_for_an_active_run(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.lose_acknowledgement = True
        run = self.apply(review)
        self.assertEqual(run.status, Status.RECONCILING)
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        self.assertTrue(ChangeRun.objects.filter(pk=run.pk).exists())

    def test_an_expired_review_is_not_applied(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        ChangeReview.objects.filter(pk=review.pk).update(
            admission_expires_at=timezone.now() - timedelta(minutes=1)
        )
        review.refresh_from_db()
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertRedirects(response, f"/changes/{review.preparation_id}/")
        self.assertFalse(ChangeRun.objects.exists())
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, "admission deadline has passed")

    def test_a_read_review_without_changes_is_not_applied(self) -> None:
        review = self.change()  # nothing finished: a read review without changes
        self.sign_in_with("view_changes", "change_shared")
        self.client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertFalse(ChangeRun.objects.exists())
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertNotIn("Apply review", page.content.decode())


class ResultLineTests(SimpleTestCase):
    def test_progress_accepts_only_the_latest_declared_stage(self) -> None:
        stages = ["preflight", "Nix", "verify"]
        self.assertEqual(
            engine.parse_progress("barectl-stage preflight\nbarectl-stage Nix\n", stages),
            "Nix",
        )
        self.assertEqual(engine.parse_progress("barectl-stage unknown\n", stages), "")
        self.assertEqual(engine.parse_progress("barectl-stage Nix\n", "Nix"), "")

    def test_collected_units_replay_recorded_systemd_output(self) -> None:
        from importlib.resources import files

        fixture_root = files("operations").joinpath("fixtures")
        pins = json.loads(fixture_root.joinpath("systemd-259.5-pins.json").read_text())
        self.assertEqual(
            (pins["ubuntu_release"], pins["architecture"], pins["systemd_package"]),
            ("26.04", "aarch64", "systemd 259.5-0ubuntu3.4"),
        )
        recorded = fixture_root.joinpath("systemd-259.5-unit-not-found.txt").read_text()
        self.assertEqual(hashlib.sha256(recorded.encode()).hexdigest(), pins["transcript_sha256"])
        self.assertEqual(pins["recorded_boot_id"], RECORDED_SYSTEMD_BOOT_ID)
        self.assertEqual(pins["recorded_unit"], RECORDED_SYSTEMD_UNIT)
        unit = native.new_unit_name()
        evidence = native.parse_inspection(
            recorded.replace(RECORDED_SYSTEMD_BOOT_ID, BOOT_ID).replace(
                RECORDED_SYSTEMD_UNIT, unit
            ),
            unit,
        )
        self.assertFalse(evidence.found)
        self.assertEqual((evidence.active_state, evidence.sub_state), ("inactive", "dead"))

    def test_the_last_result_line_is_parsed_strictly(self) -> None:
        for text, expected in (
            (
                'barectl-result {"class": "succeeded"}\n',
                engine.ResultLine("succeeded", ""),
            ),
            (
                'noise\nbarectl-result {"class": "refused", "reason": "affected_sites"}\n',
                engine.ResultLine("refused", "affected_sites"),
            ),
            ("no line here\n", None),
        ):
            with self.subTest(text=text):
                self.assertEqual(engine.parse_result_line(text), expected)

    def test_a_malformed_line_is_unreadable_not_absent(self) -> None:
        for bad in (
            "barectl-result not json\n",
            'barectl-result {"class": "invented"}\n',
            'barectl-result {"class": []}\n',
            'barectl-result {"class": "refused", "reason": "invented"}\n',
            'barectl-result {"class": "refused", "reason": []}\n',
            "barectl-result []\n",
        ):
            with self.subTest(bad=bad), self.assertRaises(native.Unreadable):
                engine.parse_result_line(bad)

    def test_the_engine_exit_contract_is_small(self) -> None:
        self.assertEqual(
            [code.name for code in native.Code],
            ["SUCCESS", "REFUSED", "PARTIAL", "FAILED", "LOCK_BUSY"],
        )
        self.assertEqual(
            {result.value for result in Result},
            {
                "not_submitted",
                "submitted",
                "not_found",
                "running",
                "succeeded",
                "refused",
                "partial",
                "failed",
                "lock_busy",
                "timed_out",
                "outcome_unknown",
            },
        )


class EnginePayloadTests(SimpleTestCase):
    def test_admission_precedes_the_sites_digest_and_the_body(self) -> None:
        from .models import ADMISSION_CENTISECONDS

        kind = engine.ChangeKind(
            slug="payload",
            label="Payload order",
            inspect=lambda shell: None,
            review=_fixture_review,
            body=lambda document, context: engine.NativeBody(b"the-body-step"),
            verify=lambda shell, review: True,
        )
        review = ChangeReview(
            kind_slug="payload",
            intent="",
            eligible=True,
            consent="shared",
            sites_read="printf x | sha256sum",
            sites_digest="a" * 64,
            boot_id=BOOT_ID,
            document={"body_sha256": hashlib.sha256(b"the-body-step").hexdigest()},
        )
        unit = native.new_unit_name()
        payload = engine.payload(
            kind,
            review,
            engine.BodyContext(unit, BOOT_ID, 590025),
            engine.NativeBody(b"the-body-step"),
            engine.body_path(unit),
        )
        lock = payload.index("flock -n 9")
        boot = payload.index("/proc/sys/kernel/random/boot_id")
        capacity = payload.index("n=$(systemctl list-units")
        sites = payload.index("printf x | sha256sum")
        body = payload.index("exec /usr/bin/sh")
        apt = payload.index("apt-daily.service")
        self.assertLess(lock, boot)
        self.assertLess(boot, capacity)
        self.assertLess(capacity, sites)
        self.assertLess(sites, body)
        self.assertLess(lock, apt)
        self.assertLess(apt, body)
        self.assertIn('"reason":"apt_active"', payload)
        self.assertIn('"class":"refused","reason":"affected_sites"', payload)
        self.assertIn('"class":"lock_busy"', payload)
        self.assertEqual(ADMISSION_CENTISECONDS, 15 * 60 * 100)


class ConnectionAdmissionTests(ChangeTestCase):
    def test_changed_connection_refuses_review_before_connecting(self) -> None:
        from servers.models import Server

        review = self.change()
        self.sign_in_with("view_server", "view_changes", "change_shared")
        Server.objects.filter(pk=self.server.pk).update(connection_revision=1)
        self.remote.commands.clear()
        from operations.services import request_apply

        result = request_apply(review, self.user, acknowledged=True)
        self.assertIn("connection changed", result.problem)
        self.assertIsNone(result.run)
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.exists())
        self.assertEqual(self.remote.commands, [])
        self.assertContains(
            self.client.get(f"/changes/{review.preparation_id}/"),
            "The connection changed. Prepare a new review.",
        )

    def test_queued_run_refuses_stale_review_before_ssh(self) -> None:
        from operations.services import request_apply
        from servers.models import Server

        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.sign_in_with("view_server", "view_changes", "change_shared")
        result = request_apply(review, self.user, acknowledged=True)
        self.assertIsNotNone(result.run)
        Server.objects.filter(pk=self.server.pk).update(connection_revision=1)
        self.remote.targets.clear()
        self.run_worker()
        run = ChangeRun.objects.get(review=review)
        self.assertEqual(run.status, Status.FAILED)
        self.assertIn("connection changed", run.failure)
        self.assertEqual(self.remote.targets, [])
        self.assertEqual(self.systemd.submissions, [])

    def test_reconciliation_and_removed_audit_keep_the_original_saved_target(self) -> None:
        from servers.models import Server
        from servers.registration import SaveOutcome, save_server

        self.sign_in_with("view_server", "change_server", "add_discoveryattempt")
        self.server.connection_mode = "agent"
        self.server.address = "original.example"
        self.server.username = "root"
        self.server.port = 2222
        self.assertIs(save_server(self.server, user=self.user), SaveOutcome.QUEUED)
        self.run_worker()
        self.systemd.units[EXITED] = finished_unit(1)
        from operations.services import request_apply, request_prepare

        self.sign_in_with(*PREPARE_PERMISSIONS)
        preparation = request_prepare(self.server, self.user, "cleanup_runs")
        self.assertIsNotNone(preparation)
        self.run_worker()
        review = ChangeReview.objects.get(preparation=preparation)
        self.systemd.lose_acknowledgement = True
        self.sign_in_with("view_changes", "change_shared")
        requested = request_apply(review, self.user, acknowledged=True)
        if requested.run is None:
            self.fail(requested.problem)
        self.run_worker()
        run = ChangeRun.objects.get(pk=requested.run.pk)
        self.assertEqual(run.status, Status.RECONCILING)
        # An out-of-band local change must never redirect outcome inspection.
        Server.objects.filter(pk=self.server.pk).update(
            address="different.example",
            connection_revision=2,
        )
        self.remote.targets.clear()
        self.systemd.lose_acknowledgement = False
        checked = self.check(run)
        self.assertEqual(checked.status, Status.SUCCEEDED)
        self.assertTrue(self.remote.targets)
        self.assertEqual({target.hostname for target in self.remote.targets}, {"original.example"})
        self.assertEqual({target.port for target in self.remote.targets}, {2222})
        self.assertEqual(len(self.systemd.submissions), 1)
        self.server.refresh_from_db()
        remove_server(self.server)
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "root@original.example:2222")
        self.assertContains(page, "connection revision 1")
