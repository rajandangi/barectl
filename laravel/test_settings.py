"""A Laravel site's Environment review and file edits (Phase B #383)."""

import base64
import gzip
import json
from typing import cast
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from bootstrap.standing import Standing
from laravel import observation as laravel_observation
from laravel import settings
from laravel.bodies.common import (
    NON_SECRET_KEYS,
    apply_environment,
    environment_entries_from_text,
    environment_value,
)
from operations.engine import BodyContext, NativeBody
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.views import _submitted_secret
from sites.bodies.common import NativeState
from sites.change import membership_command

CANARY = "Barectl-Canary-8a3f1d20"
DIGEST = "a" * 64


def native() -> NativeState:
    return cast(
        NativeState,
        {
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
                    "application": "laravel",
                    "application_version": "13.0.0",
                    "application_problem": "",
                }
            ],
            "current_sites": ["shop"],
            "disk_digest": "b" * 64,
            "digest": "c" * 64,
            "evidence": {},
            "next_id": 4002,
            "next_proxy_id": 4003,
            "validation": "not_requested",
            "pool_validation": "not_requested",
            "master_present": True,
        },
    )


def inventory() -> dict[str, object]:
    return {
        "version": 1,
        "sites": [
            {
                "identifier": "shop",
                "application": "laravel",
                "current": "bootstrap-aaaa",
                "repository": "https://example.com/app.git",
                "branch": "main",
                "php_requirement": "",
                "repository_problem": "",
                "releases": [
                    {
                        "name": "bootstrap-aaaa",
                        "commit": "a" * 40,
                        "created": 1,
                        "state": "complete",
                        "repository": "https://example.com/app.git",
                        "branch": "main",
                    }
                ],
                "shared": {"environment": True, "storage": True, "cache": True},
                "environment": ["APP_URL", "MAIL_PASSWORD", "OLD_KEY"],
                "environment_details": [
                    {"key": "APP_URL", "digest": DIGEST, "value": "https://shop.example.com"},
                    {"key": "MAIL_PASSWORD", "digest": "d" * 64},
                    {"key": "OLD_KEY", "digest": "e" * 64},
                ],
                "environment_digest": "f" * 64,
                "deploy_key": "",
                "host_keys": False,
                "problem": "",
            }
        ],
    }


def evidence() -> settings.EnvironmentEvidence:
    return settings.EnvironmentEvidence(Standing.TARGET_STACK, native(), inventory())


class EnvironmentConventionTests(SimpleTestCase):
    def test_only_changed_lines_move_and_a_quoted_value_stays_literal(self) -> None:
        before = (
            "# Laravel's environment\n"
            "APP_NAME=Laravel\n"
            "APP_URL=https://old.example.com\n"
            "DB_PASSWORD=\n"
            "MAIL_PASSWORD='old value'\n"
        )
        after = apply_environment(
            before,
            [
                {"key": "APP_URL", "action": "set", "value": "https://new.example.com"},
                {"key": "MAIL_PASSWORD", "action": "set", "value": "a b'c\\d"},
                {"key": "NEW_KEY", "action": "set", "value": CANARY},
                {"key": "DB_PASSWORD", "action": "remove"},
            ],
        )
        self.assertIn("# Laravel's environment\nAPP_NAME=Laravel\n", after)
        self.assertIn("APP_URL=https://new.example.com\n", after)
        self.assertIn("MAIL_PASSWORD='a b\\'c\\\\d'\n", after)
        self.assertIn(f"NEW_KEY={CANARY}\n", after)
        self.assertNotIn("DB_PASSWORD", after)
        entries = dict(environment_entries_from_text(after))
        self.assertEqual(entries["MAIL_PASSWORD"], "a b'c\\d")
        self.assertEqual(entries["NEW_KEY"], CANARY)
        self.assertNotIn("OLD_KEY", entries)

    def test_a_value_with_a_line_break_is_refused(self) -> None:
        for value in ("a\nb", "a\rb", "a\x00b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                environment_value(value)

    def test_discovery_keeps_only_digests_for_secret_values(self) -> None:
        value = inventory()
        site = cast(list[dict[str, object]], value["sites"])[0]
        details = cast(list[dict[str, object]], site["environment_details"])
        details[1]["value"] = CANARY
        rows = laravel_observation.settings_from(value)
        by_key = {row.key: row for row in rows}
        self.assertEqual(by_key["MAIL_PASSWORD"].value, "")
        self.assertEqual(by_key["APP_URL"].value, "https://shop.example.com")

    def test_the_non_secret_list_is_fixed(self) -> None:
        self.assertIn("APP_URL", NON_SECRET_KEYS)
        self.assertNotIn("MAIL_PASSWORD", NON_SECRET_KEYS)
        self.assertNotIn("APP_KEY", NON_SECRET_KEYS)


class EnvironmentReviewTests(SimpleTestCase):
    def test_a_mixed_edit_is_one_site_effect_with_one_secret_per_set_key(self) -> None:
        draft = settings.review(
            evidence(),
            PreparationInputs(
                "",
                "shop",
                settings_changes=(
                    ("APP_URL", "set"),
                    ("MAIL_PASSWORD", "set"),
                    ("OLD_KEY", "remove"),
                ),
            ),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertTrue(draft.writes_secrets)
        fields = cast(list[dict[str, object]], draft.document["secret_fields"])
        self.assertEqual([field["key"] for field in fields], ["APP_URL", "MAIL_PASSWORD"])
        self.assertEqual(draft.sites_read, membership_command("php84"))
        self.assertEqual(draft.document["environment_digest"], "f" * 64)
        changes = cast(list[dict[str, object]], draft.document["changes"])
        self.assertEqual([change["action"] for change in changes], ["set", "set", "remove"])

    def test_a_removal_only_edit_needs_no_confidential_value(self) -> None:
        draft = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("OLD_KEY", "remove"),))
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.writes_secrets)
        self.assertEqual(draft.document["secret_fields"], [])

    def test_removing_an_absent_key_is_refused(self) -> None:
        draft = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("NOPE", "remove"),))
        )
        self.assertFalse(draft.eligible)
        self.assertIn("NOPE is not in this site's environment.", draft.refusals)

    def test_object_cache_keys_are_managed_and_cannot_be_edited_here(self) -> None:
        import hashlib

        from cache.laravel import laravel_values

        value = inventory()
        row = cast(list[dict[str, object]], value["sites"])[0]
        details = [
            {
                "key": key,
                "digest": hashlib.sha256(item.encode()).hexdigest(),
            }
            for key, item in laravel_values("shop").items()
        ]
        row["environment_details"] = details
        managed = settings.EnvironmentEvidence(Standing.TARGET_STACK, native(), value)
        refused = settings.review(
            managed,
            PreparationInputs("", "shop", settings_changes=(("CACHE_STORE", "set"),)),
        )
        self.assertFalse(refused.eligible)
        self.assertIn("managed by the object cache", " ".join(refused.refusals))
        allowed = settings.review(
            managed,
            PreparationInputs("", "shop", settings_changes=(("APP_URL", "set"),)),
        )
        self.assertTrue(allowed.eligible, allowed.refusals)

    def test_a_plain_php_site_is_refused(self) -> None:
        state = native()
        plain = inventory()
        site = cast(list[dict[str, object]], plain["sites"])[0]
        site["application"] = "plain"
        draft = settings.review(
            settings.EnvironmentEvidence(Standing.TARGET_STACK, state, plain),
            PreparationInputs("", "shop", settings_changes=(("APP_URL", "set"),)),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("This site has no Laravel release to configure.", draft.refusals)


class EnvironmentBodyTests(SimpleTestCase):
    def document(self) -> dict[str, object]:
        draft = settings.review(
            evidence(),
            PreparationInputs("", "shop", settings_changes=(("MAIL_PASSWORD", "set"),)),
        )
        return draft.document

    def payload(self, body: object) -> dict[str, object]:
        if not isinstance(body, NativeBody):
            raise TypeError("Not a native body.")
        value = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        if not isinstance(value, dict):
            raise TypeError("The payload is not a JSON object.")
        return value

    def test_the_body_never_carries_a_value_and_consumes_the_staged_path(self) -> None:
        path = "/run/barectl/secrets/" + "a" * 32
        body = settings.body(self.document(), BodyContext("", "", 0, path))
        value = self.payload(body)
        self.assertEqual(value["secret_path"], path)
        self.assertNotIn(CANARY, body.source.decode("utf-8", "replace"))
        self.assertNotIn(CANARY, json.dumps(body.arguments))
        with self.assertRaises(ValueError):
            settings.body(self.document(), BodyContext("", "", 0))

    def test_a_removal_only_body_needs_no_staged_value(self) -> None:
        draft = settings.review(
            evidence(), PreparationInputs("", "shop", settings_changes=(("OLD_KEY", "remove"),))
        )
        body = settings.body(draft.document, BodyContext("", "", 0))
        self.assertEqual(self.payload(body)["secret_path"], "")
        self.assertFalse(self.payload(body)["secret_fields"])

    def test_the_input_shape_keeps_values_out(self) -> None:
        inputs = decode_inputs(
            {
                "version": 1,
                "identifier": "shop",
                "changes": [{"key": "MAIL_PASSWORD", "action": "set"}],
            },
            (),
            InputShape.LARAVEL_ENVIRONMENT,
        )
        self.assertEqual(inputs.settings_changes, (("MAIL_PASSWORD", "set"),))
        self.assertEqual(
            inputs.document(),
            {
                "version": 1,
                "identifier": "shop",
                "changes": [{"key": "MAIL_PASSWORD", "action": "set"}],
            },
        )
        for value in (
            {
                "version": 1,
                "identifier": "shop",
                "changes": [{"key": "MAIL_PASSWORD", "action": "set", "value": CANARY}],
            },
            {"version": 1, "identifier": "shop", "changes": []},
            {"version": 1, "identifier": "shop", "changes": [{"key": "bad", "action": "set"}]},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.LARAVEL_ENVIRONMENT)

    def test_only_the_reviewed_fields_reach_the_confidential_payload(self) -> None:
        review = mock.Mock()
        review.document = {
            "secret_fields": [{"key": "MAIL_PASSWORD", "secret": True, "label": "New value"}]
        }
        request = RequestFactory().post(
            "/changes/1/apply/",
            {"value_MAIL_PASSWORD": CANARY, "value_EXTRA": "forged"},
        )
        value = json.loads(_submitted_secret(request, review))
        self.assertEqual(value, {"values": {"MAIL_PASSWORD": CANARY}})
