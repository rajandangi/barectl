"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import base64
import subprocess
from typing import override

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.contrib.auth.models import Permission, User

from bootstrap.apply_remote_testing import is_submission
from bootstrap.models import Execution, Verification
from discovery.fakes import run_worker
from discovery.native_testing import setting
from operations.models import RemoteOperation

from . import first_access
from .access_reset_services import request_access_reset
from .inspection_remote_testing import InspectionServerCase
from .install_remote_testing import IDENTIFIER, LINEAGE, NAME


class AccessResetNativeTests(InspectionServerCase):
    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.user.user_permissions.add(
            Permission.objects.get(codename="manage_wordpress_credentials")
        )

    def test_explicit_reset_preserves_site_and_delivers_only_encrypted_password(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        encoded = base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")
        self.administer(
            "mariadb --no-defaults --protocol=socket -e "
            "\"DELETE FROM sshop.wp_usermeta WHERE user_id=1 AND meta_key='first_name'; "
            "INSERT INTO sshop.wp_usermeta(user_id,meta_key,meta_value) "
            "VALUES (1,'first_name','Raj')\""
        )
        before = self.tree()
        preparation = request_access_reset(self.server, self.user.pk, IDENTIFIER, "owner", encoded)
        self.assertIsNotNone(preparation)
        run_worker()
        if preparation is None:
            self.fail("The reset was not requested.")
        intent = preparation.access_intent
        intent.refresh_from_db()
        self.assertEqual(intent.status, "succeeded", intent.failure)
        run = intent.run
        self.assertIsNotNone(run)
        if run is None:
            self.fail("The reset has no native run.")
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure + self.journal_tail(run),
        )
        self.assertEqual(run.wordpress_access.first_name, "Raj")
        other = User.objects.create_superuser("other-operator")
        self.assertIsNone(first_access.reveal(other, run.pk))
        delivery = first_access.reveal(self.user, run.pk)
        self.assertIsNotNone(delivery)
        if delivery is None:
            self.fail("The encrypted password is unavailable.")
        password = key.decrypt(
            base64.b64decode(delivery["ciphertext"], validate=True),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ).decode("ascii")
        self.assertEqual(len(password), 32)
        self.assertTrue(
            password not in self.journal(run.unit_name), "Plaintext reached the journal."
        )
        self.assertIsNone(first_access.reveal(self.user, run.pk))
        self.assert_unchanged(before)
        self.assertEqual(
            request_access_reset(self.server, self.user.pk, IDENTIFIER, "owner", encoded),
            preparation,
        )
        run_worker()
        self.assertEqual(preparation.access_intent.run_id, run.pk)
        response = subprocess.run(  # noqa: S603 - disposable native HTTPS ground truth
            [  # noqa: S607 - the fixture Docker CLI
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
            check=False,
            input=password,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(response.returncode, 0, "The HTTPS login request failed.")
        headers = response.stdout.replace("\r", "").splitlines()
        self.assertTrue(
            any(line.startswith("Set-Cookie: wordpress_logged_in_") for line in headers),
            "The delivered password did not authenticate over HTTPS.",
        )
        self.assertTrue(any(line == f"Location: https://{NAME}/wp-admin/" for line in headers))

    def test_nonadministrator_refuses_without_password_change(self) -> None:
        from . import access_reset_native

        encoded = self._public_key()
        before = access_reset_native.parse_account(
            self.administer(access_reset_native.account_script(IDENTIFIER, "owner")), "owner"
        ).password_digest
        self.administer(
            "mariadb --no-defaults --protocol=socket -e "
            '"UPDATE sshop.wp_usermeta SET meta_value=\'a:1:{s:10:\\"subscriber\\";b:1;}\' '
            "WHERE meta_key='wp_capabilities'\""
        )
        preparation = request_access_reset(self.server, self.user.pk, IDENTIFIER, "owner", encoded)
        self.assertIsNotNone(preparation)
        run_worker()
        if preparation is None:
            self.fail("The explicit request was not recorded.")
        intent = preparation.access_intent
        intent.refresh_from_db()
        self.assertEqual(intent.status, "failed")
        self.assertIsNone(intent.run)
        self.assertEqual(
            self.administer(
                "mariadb --no-defaults --protocol=socket -N -B -e "
                "'SELECT SHA2(user_pass,256) FROM sshop.wp_users WHERE user_login=\"owner\"'"
            ).strip(),
            before,
        )

    def test_account_drift_under_native_lock_never_resets_password(self) -> None:
        from datetime import timedelta

        from django.utils import timezone

        from bootstrap.models import Action, ConfigurationPlan
        from bootstrap.services import request_preparation

        from . import access_reset_native
        from .access_reset_models import AccessResetRequest

        preparation = request_preparation(self.server, self.user, Action.WORDPRESS_ACCESS)
        self.assertIsNotNone(preparation)
        if preparation is None:
            self.fail("The native review was not requested.")
        AccessResetRequest.objects.create(
            preparation=preparation,
            identifier=IDENTIFIER,
            admin_login="owner",
            first_access_spki=self._public_key(),
            first_access_expires_at=timezone.now() + timedelta(hours=1),
        )
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, self.texts(plan))
        before = access_reset_native.parse_account(
            self.administer(access_reset_native.account_script(IDENTIFIER, "owner")), "owner"
        ).password_digest
        self.administer(
            "mariadb --no-defaults --protocol=socket -e "
            "\"DELETE FROM sshop.wp_usermeta WHERE user_id=1 AND meta_key='first_name'; "
            "INSERT INTO sshop.wp_usermeta(user_id,meta_key,meta_value) "
            "VALUES (1,'first_name','Changed')\""
        )
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        self.assertEqual(run.execution, Execution.DRIFT, run.failure + self.journal_tail(run))
        self.assertEqual(
            access_reset_native.parse_account(
                self.administer(access_reset_native.account_script(IDENTIFIER, "owner")), "owner"
            ).password_digest,
            before,
        )
        self.assertIsNone(first_access.reveal(self.user, run.pk))

    def _public_key(self) -> str:
        return base64.b64encode(
            rsa.generate_private_key(public_exponent=65537, key_size=4096)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")

    def test_intervening_account_change_cannot_verify_original_ciphertext(self) -> None:
        from datetime import timedelta

        from django.utils import timezone

        from bootstrap.models import Action, ConfigurationPlan
        from bootstrap.services import request_preparation

        from .access_reset_models import AccessResetRequest

        preparation = request_preparation(self.server, self.user, Action.WORDPRESS_ACCESS)
        self.assertIsNotNone(preparation)
        if preparation is None:
            self.fail("The native review was not requested.")
        AccessResetRequest.objects.create(
            preparation=preparation,
            identifier=IDENTIFIER,
            admin_login="owner",
            first_access_spki=self._public_key(),
            first_access_expires_at=timezone.now() + timedelta(hours=1),
        )
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, self.texts(plan))
        changed = False
        submitted = False

        def interfere(command: str) -> bool:
            nonlocal changed, submitted
            if is_submission(command):
                submitted = True
            elif submitted and not changed and "SELECT u.ID" in command:
                changed = True
                self.administer(
                    "mariadb --no-defaults --protocol=socket -e "
                    "\"UPDATE sshop.wp_users SET user_pass='external-administrator-change' "
                    "WHERE user_login='owner'\""
                )
            return False

        with self.losing(interfere, after=False):
            run = self.request(plan)
            run_worker()
        run.refresh_from_db()
        self.assertTrue(changed, "The independent administrator change was not injected.")
        self.assertEqual(
            (run.execution, run.verification),
            (Execution.SUCCEEDED, Verification.FAILED),
            run.failure + self.journal_tail(run),
        )
        self.assertIsNone(first_access.reveal(self.user, run.pk))
