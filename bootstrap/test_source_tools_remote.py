"""Fresh server source prerequisites through reviewed Ubuntu package admission."""

from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.test import tag

from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import profiles
from .apply import request_apply
from .models import Action, ConfigurationPlan, Verification
from .php_source_testing import CONFIGURED, PhpSourceCase
from .services import request_preparation


@tag("ssh")
@skipUnless(CONFIGURED, "Requires the disposable native server.")
class SourceToolsTests(PhpSourceCase):
    def test_missing_tools_are_installed_without_php_or_source_setup(self) -> None:
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq gpg gpg-agent curl >/dev/null; "
            "test ! -x /usr/bin/gpg-agent"
        )
        user = get_user_model().objects.get(username="operator")
        preparation = request_preparation(self.server, user, Action.PHP_SOURCE_PREREQUISITES)
        self.assertIsNotNone(preparation)
        run_worker()
        if preparation is None:
            self.fail("The source-tools preparation did not queue.")
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(plan.php_supply, "ubuntu")
        self.assertEqual(plan.source_tools_selection.supply, "sury")
        self.assertFalse(plan.source_tools_selection.installed)
        run = request_apply(plan, user).run
        self.assertIsNotNone(run)
        run_worker()
        if run is None:
            self.fail("The source-tools apply did not queue.")
        run.refresh_from_db()
        self.assertEqual(run.status, RemoteOperation.Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        self.administer(profiles.source_tools(self.release).check.command)
        self.assertEqual(
            self.administer(
                "dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' 2>/dev/null "
                "| awk '$2 == \"ii\" {print $1}'"
            ),
            "",
        )
        self.assertEqual(
            self.administer("find /etc/apt/sources.list.d -name php.sources -print"), ""
        )
        again = request_preparation(self.server, user, Action.PHP_SOURCE_PREREQUISITES)
        self.assertIsNotNone(again)
        run_worker()
        if again is None:
            self.fail("The satisfied tools preparation did not queue.")
        self.assertTrue(ConfigurationPlan.objects.get(preparation=again).no_changes)
