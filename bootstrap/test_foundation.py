from dataclasses import replace
from unittest import TestCase

from operations.consent import consent_of
from operations.models import Consent
from runtimes.catalog import Architecture

from . import foundation
from .standing import judge
from .test_standing import fresh_evidence


class FoundationReviewTests(TestCase):
    def test_ready_host_reviews_pinned_server_wide_foundation(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(fresh_evidence()),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
        )
        draft = foundation.review(evidence)
        self.assertTrue(draft.eligible)
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(
            draft.stages, ("preflight", "Nix", "catalog", "Caddy", "journald", "verify")
        )
        self.assertIn("releases.nixos.org", str(draft.document))
        self.assertIn("30001", str(draft.document))
        profiles = draft.document["profiles"]
        self.assertIsInstance(profiles, dict)
        if isinstance(profiles, dict):
            self.assertEqual(len(profiles), 3)

    def test_finished_host_proposes_no_changes(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(replace(fresh_evidence(), foundation=("present",) * 5)),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=True,
        )
        self.assertTrue(foundation.review(evidence).no_changes)

    def test_a_review_with_an_unknown_schema_version_is_refused_before_submission(self) -> None:
        context = foundation.BodyContext("", "", 0)
        evidence = foundation.FoundationEvidence(
            standing=judge(fresh_evidence()),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
        )
        document = foundation.review(evidence).document
        foundation.body(document, context)
        for version in (True, 2, "1", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                foundation.body({**document, "version": version}, context)
