"""Fresh explicit WordPress creation through one intent, with candidate admission."""

import base64
from typing import override
from unittest import skipUnless

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import override_settings, tag

from bootstrap.models import ApplyRun
from bootstrap.php_source_testing import PhpSourceCase, trust_fixture
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from disposable import acme
from tls.native_testing import PURGE, SHORT_AUTHORITY
from wordpress import first_access, qualification_testing

from .creation import CreationInput, request_creation
from .models import HostingCreation, HostingCreationStep


@tag("ssh")
@skipUnless(acme.CONFIGURED, "Requires disposable native server and ACME fixtures.")
@override_settings(
    ACME_AUTHORITIES=[SHORT_AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.SHORT_DIRECTORY
)
class WordPressCreationAcceptanceTests(PhpSourceCase):
    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    @override
    def setUp(self) -> None:
        super().setUp()
        trust_fixture(self, self.administer)
        self.enterContext(
            qualification_testing.source_candidate_qualified(
                self.release.version, self.architecture, self.release.php
            )
        )
        self.administer(PURGE)
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
            "nginx nginx-common gpg gpg-agent curl libsodium23 libgd3 "
            ">/dev/null; rm -rf /etc/nginx; true"
        )
        addresses = acme.server_addresses()
        acme.add_a(self, "fresh-wordpress.test", [addresses.ipv4])
        acme.add_aaaa(self, "fresh-wordpress.test", [addresses.ipv6])

    def test_one_explicit_wordpress_request_prepares_every_requirement_and_first_access(
        self,
    ) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        key = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        request_discovery(self.server)
        run_worker()
        revision = DiscoveryAttempt.objects.filter(server=self.server).latest("pk").snapshot.pk
        user = User.objects.get(username="operator")
        creation = request_creation(
            self.server,
            user.pk,
            CreationInput(
                ("fresh-wordpress.test",),
                discovery_revision=revision,
                application="wordpress",
                title="Fresh site",
                admin_login="owner",
                admin_email="owner@example.com",
                first_access_spki=key,
            ),
        )
        self.assertIsNotNone(creation)
        if creation is None:
            self.fail("The explicit WordPress request did not queue.")
        run_worker()
        creation.refresh_from_db()
        failure = creation.failure
        if creation.status != HostingCreation.Status.SUCCEEDED:
            last = ApplyRun.objects.order_by("-pk").first()
            if last is not None:
                failure += "\n" + self.administer(
                    f"journalctl --no-pager -n 45 -u {last.unit_name}; true"
                )
        self.assertEqual(creation.status, HostingCreation.Status.SUCCEEDED, failure)
        self.assertEqual(creation.php_supply, "sury")
        run_id = HostingCreationStep.objects.get(
            creation=creation, stage="wordpress_install"
        ).run_id
        self.assertIsNotNone(run_id)
        delivery = first_access.read_delivery(user, run_id or 0)
        self.assertIsNotNone(delivery)
        if delivery is None:
            self.fail("First-access delivery is missing.")
        self.assertEqual(delivery.state, "available")
        self.assertEqual(delivery.key_sha256, first_access.key_digest(key))
        self.assertEqual(
            self.administer(
                "curl --silent --show-error --max-time 20 "
                "--resolve fresh-wordpress.test:443:127.0.0.1 "
                "--output /dev/null --write-out '%{http_code}' "
                "https://fresh-wordpress.test/wp-login.php"
            ),
            "200",
        )
