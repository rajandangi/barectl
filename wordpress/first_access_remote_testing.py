"""Native encrypted first access.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import base64
import re
import subprocess
from datetime import timedelta
from typing import override

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.utils import timezone

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery.fakes import run_worker
from discovery.native_testing import setting
from discovery.services import request_discovery

from . import first_access, inputs
from .first_access_models import FirstAccessDelivery
from .install_remote_testing import IDENTIFIER, LINEAGE, NAME, InstallationServerCase
from .services import request_install_preparation


class FirstAccessAcceptanceCase(InstallationServerCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = base64.b64encode(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii")

    @override
    def review(self) -> ConfigurationPlan:
        request_discovery(self.server)
        run_worker()
        preparation = request_install_preparation(
            self.server,
            self.user,
            IDENTIFIER,
            inputs.Metadata(NAME, "Shop & Sons", "owner", "owner@example.com"),
            first_access_spki=self.public_key,
            first_access_expires_at=timezone.now() + timedelta(minutes=30),
        )
        self.assertIsNotNone(preparation)
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, "succeeded", preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def test_native_install_encrypts_one_password_without_plaintext_in_journal_or_records(
        self,
    ) -> None:
        plan = self.review()
        self.assertTrue(plan.eligible, " ".join(plan.refusals.values_list("text", flat=True)))
        run = self.request(plan)
        run_worker()
        run = ApplyRun.objects.get(pk=run.pk)
        journal = self.journal(run.unit_name)
        self.assertEqual(
            (run.execution, run.verification),
            (Execution.SUCCEEDED, Verification.PASSED),
            f"{run.failure}\n{journal[-3000:]}",
        )
        delivery = FirstAccessDelivery.objects.get(run=run)
        self.assertFalse(delivery.unavailable)
        self.assertEqual(delivery.key_sha256, first_access.key_digest(self.public_key))
        encrypted = first_access.reveal(self.user, run.pk)
        if encrypted is None:
            raise AssertionError(
                "The requesting account could not reveal its encrypted first access."
            )
        plaintext = self.private_key.decrypt(
            base64.b64decode(encrypted["ciphertext"], validate=True),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ).decode("ascii")
        self.assertTrue(re.fullmatch(r"[A-Za-z0-9]{32}", plaintext) is not None)
        self.assertFalse(plaintext in journal, "The native journal contains a plaintext password.")
        self.assertFalse(plaintext in str(run.__dict__), "The run contains a plaintext password.")
        self.assertFalse(
            plaintext in str(delivery.__dict__), "The delivery contains a plaintext password."
        )
        self.assertEqual(journal.count(first_access.MARKER), 1)
        self.assertEqual(self.tables(), "12")
        self.assertEqual(
            self.administer(
                f"curl --silent --max-time 20 --cacert {LINEAGE}/fullchain.pem "
                f"--resolve {NAME}:443:127.0.0.1 "
                f"--output /dev/null --write-out '%{{http_code}}' https://{NAME}/wp-login.php"
            ),
            "200",
        )
        response = subprocess.run(  # noqa: S603 - disposable native HTTPS ground truth
            [  # noqa: S607 - the configured disposable-container tool
                "docker",
                "exec",
                "-i",
                setting("CONTAINER"),
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--cacert",
                f"{LINEAGE}/fullchain.pem",
                "--resolve",
                f"{NAME}:443:127.0.0.1",
                "--cookie",
                "wordpress_test_cookie=WP%20Cookie%20check",
                "--data-urlencode",
                "log=owner",
                "--data-urlencode",
                "pwd@-",
                "--data-urlencode",
                f"redirect_to=https://{NAME}/wp-admin/",
                "--data",
                "testcookie=1",
                "--dump-header",
                "-",
                "--output",
                "/dev/null",
                f"https://{NAME}/wp-login.php",
            ],
            input=plaintext,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(response.returncode, 0)
        headers = response.stdout.replace("\r", "").splitlines()
        self.assertTrue(
            any(line.startswith("Set-Cookie: wordpress_logged_in_") for line in headers)
        )
        self.assertTrue(any(line == f"Location: https://{NAME}/wp-admin/" for line in headers))
        self.assertIsNone(first_access.reveal(self.user, run.pk))
        delivery.refresh_from_db()
        self.assertEqual(delivery.ciphertext, "")
