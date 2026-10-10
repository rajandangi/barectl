"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import base64
from typing import ClassVar, override

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import TestCase

from bootstrap.models import ApplyRun, PlanPreparation
from discovery.fakes import run_worker
from servers.models import Server

from .access_reset_services import request_access_reset


class RequestTests(TestCase):
    public_key: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.public_key = base64.b64encode(
            rsa.generate_private_key(public_exponent=65537, key_size=4096)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")

    def test_observer_cannot_queue_administrator_recovery(self) -> None:
        user = User.objects.create_user("observer")
        server = Server.objects.create(name="Server", ssh_alias="server")
        self.assertIsNone(request_access_reset(server, user.pk, "shop", "owner", self.public_key))
        self.assertFalse(PlanPreparation.objects.exists())

    def test_duplicate_browser_intent_never_rotates_password_again(self) -> None:
        user = User.objects.create_superuser("operator")
        server = Server.objects.create(name="Server", ssh_alias="server")
        first = request_access_reset(server, user.pk, "shop", "owner", self.public_key)
        self.assertIsNotNone(first)
        self.assertEqual(
            request_access_reset(server, user.pk, "shop", "owner", self.public_key), first
        )
        self.assertEqual(PlanPreparation.objects.count(), 1)
        if first is None:
            self.fail("The original reset intent is absent.")
        intent = first.access_intent
        intent.status = "succeeded"
        intent.save(update_fields=["status"])
        self.assertEqual(
            request_access_reset(server, user.pk, "shop", "owner", self.public_key), first
        )
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_revoked_requester_stops_the_intent_before_any_apply(self) -> None:
        user = User.objects.create_superuser("operator")
        server = Server.objects.create(name="Server", ssh_alias="server")
        preparation = request_access_reset(server, user.pk, "shop", "owner", self.public_key)
        self.assertIsNotNone(preparation)
        user.is_active = False
        user.save(update_fields=["is_active"])
        run_worker()
        if preparation is None:
            self.fail("The intent was not requested.")
        intent = preparation.access_intent
        intent.refresh_from_db()
        self.assertEqual(intent.status, "failed")
        self.assertFalse(ApplyRun.objects.exists())


class AccountEvidenceTests(TestCase):
    def test_exact_administrator_identity_is_passive_and_bounded(self) -> None:
        from .access_reset_native import parse_account

        password_digest = "a" * 64
        row = "\t".join(
            (
                "1",
                b"owner".hex().upper(),
                b"owner@example.com".hex().upper(),
                b'a:1:{s:13:"administrator";b:1;}'.hex().upper(),
                password_digest,
                b"Raj".hex().upper(),
            )
        )
        found = parse_account(row + "\n", "owner")
        self.assertEqual(
            (found.account_id, found.email, found.first_name), (1, "owner@example.com", "Raj")
        )
        self.assertEqual(found.password_digest, password_digest)
        for invalid in (
            row + "\n" + row,
            row.replace("6F776E6572", "666F726569676E"),
            row.replace("61646D696E6973747261746F72", "73756273637269626572"),
        ):
            with self.assertRaises(ValueError):
                parse_account(invalid, "owner")
