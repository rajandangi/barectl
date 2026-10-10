"""Actual fresh-server hosting through one authorized creation intent."""

from unittest import skipUnless

from django.contrib.auth.models import User
from django.test import tag

from bootstrap.models import Action
from bootstrap.php_source_testing import CONFIGURED, PhpSourceCase, trust_fixture
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from sites.convention import SitePaths

from .creation import CreationInput, identifier_for, request_creation
from .models import HostingCreation


@tag("ssh")
@skipUnless(CONFIGURED, "Requires a disposable native server.")
class CreationAcceptanceTests(PhpSourceCase):
    def test_one_generic_creation_installs_requirements_and_never_installs_wordpress(self) -> None:
        trust_fixture(self, self.administer)
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx nginx-common "
            "libsodium23 >/dev/null; rm -rf /etc/nginx; "
            'test -z "$(find /usr/lib -name libsodium.so.23 -print -quit)"'
        )
        request_discovery(self.server)
        run_worker()
        revision = DiscoveryAttempt.objects.filter(server=self.server).latest("pk").snapshot.pk
        user = User.objects.get(username="operator")
        wanted = CreationInput(("fresh.example.test",), discovery_revision=revision)
        creation = request_creation(self.server, user.pk, wanted)
        self.assertIsNotNone(creation)
        if creation is None:
            self.fail("The fresh creation intent did not queue.")
        repeated = request_creation(self.server, user.pk, wanted)
        self.assertEqual(repeated, creation)
        run_worker()
        creation.refresh_from_db()
        self.assertEqual(creation.status, HostingCreation.Status.SUCCEEDED, creation.failure)
        self.assertFalse(creation.steps.filter(stage=Action.WORDPRESS_INSTALL).exists())
        self.assertEqual(
            self.administer("dpkg-query -W -f='${db:Status-Status}' libsodium23"), "installed"
        )
        identifier = identifier_for(wanted.names[0])
        paths = SitePaths(identifier, self.release.php, revision=4)
        served = self.administer(
            "curl --silent --show-error --max-time 10 --header 'Host: fresh.example.test' "
            "http://127.0.0.1/"
        )
        self.assertIn(identifier, served)
        self.assertEqual(self.administer(f"test -S {paths.socket}; echo ready").strip(), "ready")
        self.assertEqual(self.administer(f"find {paths.public} -name wp-login.php -print"), "")
        self.assertEqual(
            self.administer("readlink -f /usr/bin/php").strip(), f"/usr/bin/php{self.release.php}"
        )
        self.assertEqual(HostingCreation.objects.filter(server=self.server).count(), 1)
