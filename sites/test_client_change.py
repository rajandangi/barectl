"""The site cache PHP client change: review, consent, refusals and body validation (#390)."""

from typing import cast

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import Consent
from runtimes.catalog import Architecture
from runtimes.extensions import build as redis_build
from runtimes.extensions import shared_object

from .bodies.common import NativeState
from .client_change import ClientEvidence, body, review


def native(client: str = "") -> NativeState:
    return cast(
        NativeState,
        {
            "version": 1,
            "boot": "00000000-0000-4000-8000-000000000000",
            "uptime": 1234,
            "next_id": 4000,
            "next_proxy_id": 4100,
            "digest": "a" * 64,
            "disk_digest": "b" * 64,
            "validation": "valid",
            "pool_validation": "valid",
            "master_present": True,
            "current_sites": ["shop"],
            "evidence": {},
            "sites": [
                {
                    "identifier": "shop",
                    "names": ["shop.example.com"],
                    "runtime": "php84",
                    "node_runtime": "",
                    "https": True,
                    "readiness": "/",
                    "certificate": None,
                    "pool": None,
                    "account": None,
                    "file": "/etc/caddy/sites/shop.caddy",
                    "state": "complete",
                    "problem": "",
                    "application": "plain",
                    "application_version": "",
                    "application_problem": "",
                    "serving_form": "plain",
                    "client": client,
                }
            ],
        },
    )


def evidence(client: str = "") -> ClientEvidence:
    build = redis_build(Architecture.AARCH64, "php84")
    if build is None:
        raise AssertionError("The catalog lost the redis extension.")
    return ClientEvidence(
        Standing.TARGET_STACK,
        Architecture.AARCH64,
        native(client),
        build.path,
        shared_object(build),
        build.version,
    )


class ClientReviewTests(SimpleTestCase):
    def test_enabling_names_the_locked_extension_and_is_site_consent(self) -> None:
        inputs = PreparationInputs(identifier="shop", php_client=True)
        draft = review(evidence(), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.current_sites, ("shop",))
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        rows = cast(list[dict[str, object]], draft.document["details"])
        details = {row["label"]: row["value"] for row in rows}
        self.assertEqual(details["Cache PHP client"], "phpredis 6.3.0")
        self.assertIn("/lib/php/extensions/redis.so", str(details["Locked extension"]))
        self.assertEqual(draft.document["enabled"], True)
        self.assertEqual(draft.document["current"], "")

    def test_an_already_enabled_client_proposes_nothing_and_disabling_removes_it(self) -> None:
        enabled = review(
            evidence("phpredis"), PreparationInputs(identifier="shop", php_client=True)
        )
        self.assertTrue(enabled.no_changes)
        self.assertEqual(enabled.effects, ())
        disabled = review(
            evidence("phpredis"), PreparationInputs(identifier="shop", php_client=False)
        )
        self.assertTrue(disabled.eligible, disabled.refusals)
        self.assertFalse(disabled.no_changes)
        self.assertEqual(disabled.document["enabled"], False)
        self.assertEqual(disabled.document["extension"], "")

    def test_a_release_without_the_extension_refuses_to_enable_it(self) -> None:
        missing = ClientEvidence(Standing.TARGET_STACK, Architecture.AARCH64, native(), "", "", "")
        draft = review(missing, PreparationInputs(identifier="shop", php_client=True))
        self.assertFalse(draft.eligible)
        self.assertIn("does not supply the object cache's PHP client", " ".join(draft.refusals))
        self.assertEqual(draft.effects, ())

    def test_a_site_outside_the_convention_is_refused(self) -> None:
        data = native()
        data["sites"][0]["state"] = "unsupported"
        data["sites"][0]["problem"] = "The site pool has settings outside the supported bounds."
        draft = review(
            ClientEvidence(Standing.TARGET_STACK, Architecture.AARCH64, data, "p", "e", "6.3.0"),
            PreparationInputs(identifier="shop", php_client=True),
        )
        self.assertFalse(draft.eligible)


class ClientBodyTests(SimpleTestCase):
    def document(self) -> dict[str, object]:
        return review(evidence(), PreparationInputs(identifier="shop", php_client=True)).document

    def test_a_reviewed_document_builds_the_native_body(self) -> None:
        document = self.document()
        native_body = body(document, BodyContext("", "", 0))
        self.assertTrue(native_body.source.startswith(b"#!/bin/sh\n"))
        self.assertEqual(len(native_body.arguments), 1)

    def test_tampering_with_the_client_build_is_refused(self) -> None:
        for change in (
            {"enabled": False},
            {"enabled": "yes"},
            {"extension": "/nix/store/" + "a" * 32 + "-php-redis-6.3.0/lib/php/extensions/x.so"},
            {"build": "/nix/store/" + "a" * 32 + "-other-1.0"},
            {"runtime": "php85"},
            {"precondition_digest": "not-a-digest"},
            {"body_sha256": "0" * 64},
        ):
            with self.subTest(change=change):
                document = self.document() | change
                with self.assertRaises(ValueError):
                    body(document, BodyContext("", "", 0))

    def test_the_preparation_document_round_trips_the_client_flag(self) -> None:
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                inputs = PreparationInputs(identifier="shop", php_client=enabled)
                document = inputs.document()
                self.assertEqual(
                    document,
                    {"version": 1, "identifier": "shop", "php_client": enabled},
                )
                self.assertEqual(
                    decode_inputs(document, (), InputShape.SITE_CLIENT).php_client, enabled
                )

    def test_the_client_input_shape_refuses_a_foreign_identifier_or_flag(self) -> None:
        self.assertEqual(
            decode_inputs(
                {"version": 1, "identifier": "shop", "php_client": True},
                (),
                InputShape.SITE_CLIENT,
            ).php_client,
            True,
        )
        for value in (
            {"version": 1, "identifier": "Shop", "php_client": True},
            {"version": 1, "identifier": "shop", "php_client": "true"},
            {"version": 1, "identifier": "shop"},
            {"version": 2, "identifier": "shop", "php_client": True},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.SITE_CLIENT)
