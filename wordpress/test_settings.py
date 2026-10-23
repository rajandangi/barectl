"""A WordPress site's extra constants (Phase B #383)."""

import base64
import gzip
import json
from typing import cast
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from sites.bodies.common import NativeState
from wordpress import convention, settings
from wordpress import observation as wordpress_observation

DIGEST = "a" * 64
SALTS = tuple("s" * 64 for _ in convention.SALTS)


def _payload(body: object) -> dict[str, object]:
    from operations.engine import NativeBody

    if not isinstance(body, NativeBody):
        raise TypeError("Not a native body.")
    value = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
    if not isinstance(value, dict):
        raise TypeError("The payload is not a JSON object.")
    return cast(dict[str, object], value)


def configuration(constants: tuple[tuple[str, str], ...] = ()) -> str:
    return convention.render_private_configuration("shop", SALTS, constants)


class WordPressConstantConventionTests(SimpleTestCase):
    def test_extra_constants_follow_the_fixed_block(self) -> None:
        text = configuration((("MAIL_HOST", "smtp.example.com"), ("MAIL_PASSWORD", "a'b\\c")))
        self.assertEqual(convention.private_configuration_problem(text, "shop"), "")
        self.assertEqual(
            convention.extra_constants(text, "shop"),
            [("MAIL_HOST", "smtp.example.com"), ("MAIL_PASSWORD", "a'b\\c")],
        )
        details = convention.constant_details(text, "shop")
        self.assertEqual([row["key"] for row in details], ["MAIL_HOST", "MAIL_PASSWORD"])
        self.assertNotIn("smtp.example.com", str(details))
        self.assertNotIn("a'b", str(details))

    def test_only_changed_constants_move_and_the_fixed_block_stays(self) -> None:
        before = configuration((("MAIL_HOST", "old.example.com"), ("MAIL_PASSWORD", "secret")))
        after = convention.apply_constants(
            before,
            [
                {"key": "MAIL_HOST", "action": "set", "value": "new.example.com"},
                {"key": "MAIL_PASSWORD", "action": "remove"},
                {"key": "MAIL_PORT", "action": "set", "value": "587"},
            ],
            "shop",
        )
        fixed = before.splitlines()[: len(configuration().splitlines())]
        self.assertEqual(after.splitlines()[: len(fixed)], fixed)
        self.assertIn("define( 'MAIL_HOST', 'new.example.com' );", after)
        self.assertIn("define( 'MAIL_PORT', '587' );", after)
        self.assertNotIn("MAIL_PASSWORD", after)
        self.assertEqual(convention.private_configuration_problem(after, "shop"), "")

    def test_barectl_owned_and_reserved_names_are_not_editable(self) -> None:
        for key in ("AUTH_KEY", "DB_NAME", "DISABLE_WP_CRON", "WP_REDIS_HOST", "ABSPATH"):
            with self.subTest(key=key):
                self.assertTrue(convention.reserved_constant(key))
                self.assertFalse(convention.valid_constant_key(key))
        with self.assertRaises(ValueError):
            convention.render_constant("DISABLE_WP_CRON", "true")

    def test_the_settings_read_accepts_only_names_and_digests(self) -> None:
        self.assertTrue(
            wordpress_observation.valid_inventory(
                {
                    "version": 1,
                    "sites": [
                        {
                            "identifier": "shop",
                            "digest": "a" * 64,
                            "constants": [{"key": "MAIL_HOST", "digest": "b" * 64}],
                        }
                    ],
                }
            )
        )
        self.assertFalse(
            wordpress_observation.valid_inventory(
                {
                    "version": 1,
                    "sites": [
                        {
                            "identifier": "shop",
                            "digest": "a" * 64,
                            "constants": [{"key": "MAIL_HOST", "digest": "b" * 64, "value": "x"}],
                        }
                    ],
                }
            )
        )

    def test_a_malformed_extra_line_is_unsupported(self) -> None:
        text = configuration() + "define( 'MAIL_HOST', 'x');\n"
        self.assertNotEqual(convention.private_configuration_problem(text, "shop"), "")


def native(application: str = "wordpress") -> NativeState:
    return {
        "version": 1,
        "boot": "00000000-0000-0000-0000-000000000000",
        "uptime": 100,
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
                "account": [4001, 4001, "/var/www/shop", "/usr/sbin/nologin", [4001]],
                "file": "/etc/caddy/sites/shop.caddy",
                "state": "complete",
                "problem": "",
                "application": application,
                "application_version": "7.1.3",
                "application_problem": "",
            }
        ],
        "current_sites": ["shop"],
        "digest": "c" * 64,
        "disk_digest": "b" * 64,
        "evidence": {},
        "next_id": 4002,
        "next_proxy_id": 4003,
        "validation": "not_requested",
        "pool_validation": "not_requested",
        "master_present": True,
    }


def inventory() -> dict[str, object]:
    return {
        "version": 1,
        "sites": [
            {
                "identifier": "shop",
                "digest": "f" * 64,
                "constants": [
                    {"key": "MAIL_HOST", "digest": DIGEST},
                    {"key": "OLD_KEY", "digest": "e" * 64},
                ],
            }
        ],
    }


def evidence() -> settings.SettingsEvidence:
    return settings.SettingsEvidence(Standing.TARGET_STACK, native(), inventory())


class WordPressSettingsReviewTests(SimpleTestCase):
    def test_a_set_needs_one_confidential_field_and_a_remove_needs_none(self) -> None:
        draft = settings.review(
            evidence(),
            PreparationInputs(
                "", "shop", settings_changes=(("MAIL_HOST", "set"), ("OLD_KEY", "remove"))
            ),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.writes_secrets)
        self.assertEqual(
            draft.document["secret_fields"],
            [{"key": "MAIL_HOST", "secret": True, "label": "New value for MAIL_HOST"}],
        )
        removal = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("OLD_KEY", "remove"),))
        )
        self.assertFalse(removal.writes_secrets)
        self.assertEqual(removal.document["secret_fields"], [])

    def test_barectl_owned_names_are_refused_at_review(self) -> None:
        draft = settings.review(
            evidence(),
            PreparationInputs("", "shop", settings_changes=(("AUTH_KEY", "set"),)),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("AUTH_KEY is owned by Barectl and cannot be edited.", draft.refusals)

    def test_a_plain_php_site_is_refused(self) -> None:
        draft = settings.review(
            settings.SettingsEvidence(Standing.TARGET_STACK, native("plain"), inventory()),
            PreparationInputs("", "shop", settings_changes=(("MAIL_HOST", "set"),)),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("This site is not a WordPress application.", draft.refusals)

    def test_the_input_shape_decodes_only_keys_and_actions(self) -> None:
        inputs = decode_inputs(
            {
                "version": 1,
                "identifier": "shop",
                "changes": [{"key": "MAIL_HOST", "action": "set"}],
            },
            (),
            InputShape.WORDPRESS_SETTINGS,
        )
        self.assertEqual(inputs.settings_changes, (("MAIL_HOST", "set"),))
        with self.assertRaises(ValueError):
            decode_inputs(
                {
                    "version": 1,
                    "identifier": "shop",
                    "changes": [{"key": "MAIL_HOST", "action": "set", "value": "x"}],
                },
                (),
                InputShape.WORDPRESS_SETTINGS,
            )

    def test_a_removal_only_body_needs_no_staged_value(self) -> None:
        draft = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("OLD_KEY", "remove"),))
        )
        body = settings.body(draft.document, BodyContext("", "", 0))
        self.assertIn('"secret_path": ""', json.dumps(_payload(body), sort_keys=True))

    def test_the_body_accepts_its_reviewed_document_only(self) -> None:
        draft = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("MAIL_HOST", "set"),))
        )
        with mock.patch.object(settings, "BODY_BYTES", b"#!/bin/sh\n"):
            context = BodyContext("", "", 0, "/run/barectl/secrets/" + "a" * 32)
            self.assertIsNotNone(settings.body(draft.document, context))
