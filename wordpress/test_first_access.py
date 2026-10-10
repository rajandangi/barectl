"""Browser key and one-use encrypted delivery boundaries."""

import base64
import json
from datetime import timedelta
from typing import ClassVar, override

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from bootstrap.models import Action, Execution, Verification
from servers.models import Server
from servers.testing import record_run

from . import first_access
from .first_access_models import FirstAccessDelivery


class FirstAccessTests(TestCase):
    public: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        public = rsa.generate_private_key(public_exponent=65537, key_size=4096).public_key()
        cls.public = base64.b64encode(
            public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")

    @override
    def setUp(self) -> None:
        self.user = User.objects.create_superuser(
            "owner", "owner@example.com", "test-only-password"
        )
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.native_run = record_run(self.server, Action.WORDPRESS_INSTALL)
        self.native_run.requested_by = self.user
        self.native_run.invocation_id = "a" * 32
        self.native_run.save(update_fields=["requested_by", "invocation_id"])
        self.cipher = base64.b64encode(b"x" * 512).decode("ascii")
        self.delivery = FirstAccessDelivery.objects.create(
            run=self.native_run,
            requested_by=self.user,
            key_sha256=first_access.key_digest(self.public),
            ciphertext=self.cipher,
            expires_at=timezone.now() + timedelta(hours=1),
            retrieved_at=timezone.now(),
        )

    def test_only_canonical_rsa4096_spki_with_65537_is_admitted(self) -> None:
        self.assertEqual(len(first_access.validate_key(self.public)), 550)
        for invalid in ("", self.public + "\n", self.public[:-1], "A" * 1025):
            with self.subTest(invalid=invalid[:30]), self.assertRaises(ValueError):
                first_access.validate_key(invalid)
        for bits in (2048, 3072):
            public = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
            encoded = base64.b64encode(
                public.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode("ascii")
            with self.assertRaises(ValueError):
                first_access.validate_key(encoded)

    def test_reveal_consumes_once_and_never_returns_a_plaintext_or_private_key_field(self) -> None:
        result = first_access.reveal(self.user, self.native_run.pk)
        self.assertEqual(
            result, {"ciphertext": self.cipher, "key_sha256": self.delivery.key_sha256}
        )
        self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.ciphertext, "")
        self.assertIsNotNone(self.delivery.consumed_at)
        view = first_access.read_delivery(self.user, self.native_run.pk)
        self.assertIsNotNone(view)
        if view is not None:
            self.assertEqual(view.state, "consumed")

    def test_another_requester_expiry_revocation_or_unverified_run_cannot_reveal(self) -> None:
        other = User.objects.create_superuser("other", "other@example.com", "test-only-password")
        self.assertIsNone(first_access.reveal(other, self.native_run.pk))
        self.assertIsNone(first_access.read_delivery(other, self.native_run.pk))
        for field, value in (
            ("verification", Verification.FAILED),
            ("execution", Execution.PARTIAL),
        ):
            setattr(self.native_run, field, value)
            self.native_run.save(update_fields=[field])
            self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertIsNone(
            first_access.reveal(User.objects.get(pk=self.user.pk), self.native_run.pk)
        )
        self.delivery.expires_at = timezone.now() - timedelta(seconds=1)
        self.delivery.save(update_fields=["expires_at"])
        self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        self.delivery.refresh_from_db()
        self.assertIsNone(self.delivery.consumed_at)

    def journal(self, **changed: object) -> str:
        record: dict[str, object] = {
            "_SYSTEMD_UNIT": self.native_run.unit_name,
            "_SYSTEMD_INVOCATION_ID": self.native_run.invocation_id,
            "_TRANSPORT": "stdout",
            "_UID": "0",
            "MESSAGE": f"{first_access.MARKER} {self.delivery.key_sha256} {self.cipher}",
        }
        record.update(changed)
        return "residue absent\njournal ok\n" + json.dumps(record) + "\n"

    def test_ciphertext_is_bound_to_exact_root_unit_invocation_and_key(self) -> None:
        parse = first_access._journal_ciphertext
        self.assertEqual(
            parse(
                self.journal(),
                self.native_run,
                self.delivery.key_sha256,
                self.native_run.invocation_id,
            ),
            self.cipher,
        )
        variants = (
            self.journal(_UID="1003"),
            self.journal(_SYSTEMD_UNIT="other.service"),
            self.journal(_SYSTEMD_INVOCATION_ID="b" * 32),
            self.journal(_TRANSPORT="syslog"),
            self.journal(MESSAGE=f"{first_access.MARKER} {'b' * 64} {self.cipher}"),
            self.journal() + self.journal().splitlines()[-1] + "\n",
        )
        for text in variants:
            with self.subTest(text=text[:100]), self.assertRaises(ValueError):
                parse(
                    text, self.native_run, self.delivery.key_sha256, self.native_run.invocation_id
                )

    def test_native_script_uses_stdin_and_explicit_oaep_sha256_without_plaintext_output(
        self,
    ) -> None:
        script = first_access.install_script(self.public)
        self.assertIn('printf "%s\\n" "$p" | "$@" >/dev/null 2>&1', script)
        self.assertIn('printf %s "$p" | /usr/bin/openssl pkeyutl', script)
        self.assertIn("rsa_padding_mode:oaep", script)
        self.assertIn("rsa_oaep_md:sha256", script)
        self.assertIn("rsa_mgf1_md:sha256", script)
        self.assertNotIn("export p=", script)
        self.assertNotIn('printf %s "$p" >', script)

    def test_reveal_endpoint_requires_post_csrf_owner_and_disables_caching(self) -> None:
        url = f"/wordpress/first-access/{self.native_run.pk}/"
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 405)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(url).status_code, 403)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ciphertext"], self.cipher)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(self.client.post(url).status_code, 404)

    def test_reveal_checks_fresh_permissions_even_when_the_supplied_user_was_cached(self) -> None:
        self.assertTrue(self.user.has_perms(first_access.PERMISSIONS))
        User.objects.filter(pk=self.user.pk).update(is_superuser=False)
        self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        self.assertIsNone(first_access.read_delivery(self.user, self.native_run.pk))
        self.delivery.refresh_from_db()
        self.assertIsNone(self.delivery.consumed_at)

    def test_invalid_ciphertext_and_unknown_action_are_not_delivery(self) -> None:
        self.delivery.ciphertext = "invalid"
        self.delivery.save(update_fields=["ciphertext"])
        self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        self.delivery.ciphertext = self.cipher
        self.delivery.save(update_fields=["ciphertext"])
        self.native_run.action = Action.WORDPRESS_FINISH
        self.native_run.save(update_fields=["action"])
        self.assertIsNone(first_access.reveal(self.user, self.native_run.pk))
        self.assertIsNone(first_access.read_delivery(self.user, self.native_run.pk))
        self.delivery.refresh_from_db()
        self.assertIsNone(self.delivery.consumed_at)
