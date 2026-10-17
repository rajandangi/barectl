"""Create consent is derived from actual native master membership at the public client."""

import tempfile
from pathlib import Path

from django.contrib.auth.models import Permission, User
from django.test import override_settings, tag

from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.services import read_discovery
from operations.models import ChangePreparation, ChangeRun, Consent, Result, Verification
from servers.models import Server
from servers.registration import save_server

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteConsent(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4client"

    def test_site_operator_applies_empty_master_but_shared_create_requires_permission_and_ack(
        self,
    ) -> None:
        target = self.target()
        with tempfile.TemporaryDirectory() as directory:
            configuration = Path(directory) / "config"
            configuration.write_text(
                f"Host client\n  HostName {target.hostname}\n  Port {target.port}\n"
                f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
                f"  UserKnownHostsFile {target.known_hosts_files[0]}\n"
            )
            with override_settings(
                SSH_CONFIG_PATH=str(configuration),
                SSH_KNOWN_HOSTS_PATH=str(target.known_hosts_files[0]),
                VITE_MANIFEST_PATH=TEST_MANIFEST,
            ):
                user = User.objects.create_user(username="site-operator")
                for name in ("view_server", "view_siteobservation", "view_changes", "change_site"):
                    user.user_permissions.add(Permission.objects.get(codename=name))
                self.client.force_login(user)
                server = Server(name="Client", ssh_alias="client")
                registrar = User.objects.create_superuser(username="registrar")
                save_server(server, user=registrar)
                run_worker()
                first = self.prepare(server, "s4clientalpha")
                self.assertTrue(first.review.eligible, first.review.document)
                self.assertEqual(first.review.consent, Consent.SITE)
                self.assertEqual(
                    self.client.post(f"/changes/{first.pk}/apply/", {}).status_code, 302
                )
                run_worker()
                applied = ChangeRun.objects.get(review=first.review)
                self.assertEqual(applied.execution, Result.SUCCEEDED, applied.failure)
                self.assertEqual(applied.verification, Verification.PASSED, applied.failure)
                observed = read_discovery(server)
                self.assertIsNotNone(observed.attempt)
                if observed.attempt is None:
                    self.fail("The authorized change did not queue its observation.")
                self.assertEqual(observed.attempt.status, "succeeded", observed.attempt.failure)
                self.assertEqual(observed.attempt.requested_by_id, user.pk)
                self.assertEqual(observed.attempt.authority, "operations.view_changes")
                second = self.prepare(server, "s4clientbeta")
                self.assertEqual(second.review.consent, Consent.SHARED)
                self.assertEqual(second.review.affected_sites, ["s4clientalpha", "s4clientbeta"])
                response = self.client.post(
                    f"/changes/{second.pk}/apply/", {"affected_sites": "on"}
                )
                self.assertEqual(response.status_code, 403)
                self.assertFalse(ChangeRun.objects.filter(review=second.review).exists())
                self.native("test ! -e /var/www/s4clientbeta; ! getent passwd ss4clientbeta")
                user.user_permissions.add(Permission.objects.get(codename="change_shared"))
                self.assertEqual(
                    self.client.post(f"/changes/{second.pk}/apply/", {}).status_code, 302
                )
                self.assertFalse(ChangeRun.objects.filter(review=second.review).exists())
                self.assertEqual(
                    self.client.post(
                        f"/changes/{second.pk}/apply/", {"affected_sites": "on"}
                    ).status_code,
                    302,
                )
                run_worker()
                shared = ChangeRun.objects.get(review=second.review)
                self.assertEqual(shared.execution, Result.SUCCEEDED, shared.failure)
                self.assertEqual(shared.verification, Verification.PASSED, shared.failure)

    def prepare(self, server: Server, identifier: str) -> ChangePreparation:
        response = self.client.post(
            f"/servers/{server.pk}/sites/http/prepare/",
            {
                "identifier": identifier,
                "names": identifier + ".example.com",
                "php_version": "php85",
            },
        )
        self.assertEqual(response.status_code, 302)
        run_worker()
        return ChangePreparation.objects.filter(server=server).latest("pk")
