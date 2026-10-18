import json
from dataclasses import replace
from unittest import TestCase

from operations.consent import consent_of
from operations.engine import BodyContext
from operations.models import Consent
from runtimes.catalog import Architecture, load

from . import foundation
from .standing import judge
from .standing_testing import fresh_evidence


class FoundationReviewTests(TestCase):
    def test_unknown_existing_profile_refuses_before_a_retry_body_is_available(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(fresh_evidence()),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
            profiles=(("composer", "/nix/store/unknown"),),
        )
        draft = foundation.review(evidence)
        self.assertFalse(draft.eligible)
        self.assertIn("unknown catalog build", " ".join(draft.refusals))
        with self.assertRaises(ValueError):
            foundation.body(draft.document, BodyContext("", "", 0))

    def test_foundation_reviews_the_pinned_haproxy_tool(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(fresh_evidence()),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
        )
        draft = foundation.review(evidence)
        profiles = draft.document["profiles"]
        self.assertIsInstance(profiles, dict)
        if isinstance(profiles, dict):
            self.assertEqual(
                profiles.get("haproxy"),
                "/nix/store/h44a0ci9fhbsdkwb8wrqbqs8mla04ifm-haproxy-3.3.11",
            )
        native = foundation.body(draft.document, BodyContext("", "", 0))
        self.assertIn(
            "/nix/store/h44a0ci9fhbsdkwb8wrqbqs8mla04ifm-haproxy-3.3.11", native.arguments
        )

    def test_missing_profiles_select_only_offered_builds(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(fresh_evidence()),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
        )
        draft = foundation.review(evidence)
        self.assertEqual(
            draft.document["profiles"],
            {
                build.entry: build.path
                for build in load().offered(Architecture.X86_64)
                if build.entry in foundation.PROFILES
            },
        )
        self.assertEqual(draft.document["retained_profiles"], {})

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
            self.assertEqual(len(profiles), 4)

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
        context = BodyContext("", "", 0)
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

    def test_an_older_main_configuration_reviews_as_a_caddy_refresh(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(
                replace(
                    fresh_evidence(),
                    foundation=("present", "present", "incomplete", "present", "incomplete"),
                )
            ),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
            nix_supported=True,
            caddy_shape="older",
        )
        draft = foundation.review(evidence)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["caddy_mode"], "refresh")
        native = foundation.body(draft.document, BodyContext("", "", 0))
        self.assertIn("refresh", native.arguments)

    def test_the_main_configuration_recognizes_the_earlier_automatic_https_setting(self) -> None:
        def adapted(*, disable: bool) -> str:
            server: dict[str, object] = {
                "listen": [":80"],
                "strict_sni_host": True,
                "routes": [{"handle": [{"handler": "static_response", "status_code": 404}]}],
            }
            if disable:
                server["automatic_https"] = {"disable": True}
            return json.dumps(
                {
                    "admin": {"listen": "unix//run/caddy/admin.sock|0600"},
                    "apps": {"http": {"servers": {"srv0": server}}},
                }
            )

        self.assertFalse(foundation.supported_caddy(adapted(disable=True)))
        self.assertTrue(foundation.recognized_caddy(adapted(disable=True)))
        self.assertTrue(foundation.supported_caddy(adapted(disable=False)))

    def test_supported_nix_without_later_stages_can_resume_without_reinstalling(self) -> None:
        evidence = foundation.FoundationEvidence(
            standing=judge(
                replace(
                    fresh_evidence(),
                    nix_shape="supported",
                    foundation=("present", "absent", "absent", "absent", "absent"),
                )
            ),
            architecture=Architecture.X86_64,
            boot_id="12345678-1234-1234-1234-123456789abc",
            uptime_centiseconds=1000,
            precondition_digest="a" * 64,
            complete=False,
            nix_supported=True,
            caddy_shape="absent",
        )
        draft = foundation.review(evidence)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.document["nix_mode"], "keep")
