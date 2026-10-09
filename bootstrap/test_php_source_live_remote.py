"""The approved PHP source as its publisher serves it now; docs/quality.md#live-php-source-check."""

from unittest import skipUnless
from unittest.mock import patch

from django.test import tag

from discovery import ssh
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import native, php_trust
from .models import Action, ConfigurationPlan, Execution, Privilege, Verification
from .php_source_testing import CONFIGURED, PhpSourceCase


@tag("php-source-live")
@skipUnless(CONFIGURED, "Requires the disposable native server.")
class LivePhpSourceTests(PhpSourceCase):
    def test_publisher_metadata_is_current_and_installs_a_branch(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refresh = self.apply(ConfigurationPlan.objects.latest("pk"))
        journal = self.administer(f"journalctl -q --no-pager -o cat -u {refresh.unit_name}")
        self.assertEqual(refresh.verification, Verification.PASSED, journal[-4000:])
        with ssh.connect_alias(self.server.ssh_alias) as shell:
            privilege = (
                Privilege.ROOT
                if shell.run(native.USER_ID).stdout.strip() == "0"
                else Privilege.SUDO
            )
            evidence = php_trust.collect(shell, self.release, self.architecture, privilege)
        self.assertTrue(evidence.admitted, evidence.refusals)
        with patch("bootstrap.php_supply.qualified", return_value=True):
            self.client.post(
                f"/servers/{self.server.pk}/plans/prepare/",
                {"action": Action.PHP, "php_version": "8.4", "php_supply": "sury"},
            )
            run_worker()
        run = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(run.status, RemoteOperation.Status.SUCCEEDED, run.failure)
        self.assertEqual(
            self.administer("php8.4 -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"), "8.4"
        )
