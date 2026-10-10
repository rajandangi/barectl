"""Node defaults and site pins across a real kernel reboot."""

import os
from typing import override
from unittest import skipUnless

from django.contrib.auth.models import Permission
from django.test import tag

from bootstrap.models import ConfigurationPlan, Execution, Verification
from bootstrap.vm_native_testing import VmAcceptanceTestCase
from discovery import ssh
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import catalog, runtime
from .changes import request_runtime_change
from .services import request_runtime_preparation


@tag("vm")
@skipUnless(os.environ.get("BARECTL_VM_TEST"), "Run docker/vm-server/run-tests.sh")
class NodeRebootTests(VmAcceptanceTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(
            Permission.objects.get(
                content_type__app_label="discovery", codename="view_siteobservation"
            ),
            *Permission.objects.filter(
                content_type__app_label="sites",
                codename__in=("view_siteplan", "prepare_siteplan", "apply_siteplan"),
            ),
        )

    def test_real_kernel_reboot_preserves_default_pin_commands_and_native_reconstruction(
        self,
    ) -> None:
        change = request_runtime_change(self.server, self.user.pk, catalog.DEFAULT)
        self.assertIsNotNone(change)
        run_worker()
        if change is None:
            self.fail("The default request was refused.")
        change.refresh_from_db()
        self.assertEqual(change.status, "succeeded", change.failure)
        self.administer(
            "useradd --home-dir /var/www/shop --no-create-home "
            "--shell /usr/sbin/nologin --user-group sshop; "
            "install -d -o root -g root -m 0755 /var/www/shop; "
            "install -d -o sshop -g sshop -m 0755 /var/www/shop/public; "
            "printf 'application bytes' >/var/www/shop/public/kept"
        )
        preparation = request_runtime_preparation(
            self.server, self.user, "22.23.3", identifier="shop"
        )
        self.assertIsNotNone(preparation)
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        run = self.apply(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        before = self.administer(
            "sha256sum /etc/mise/config.toml /var/www/shop/.node-version /var/www/shop/public/kept"
        )
        old_boot = self.reboot_when("true")
        self.rebooted(old_boot)
        self.assertNotEqual(self.boot()[0], old_boot[0])
        self.assertEqual(
            self.administer(
                "sha256sum /etc/mise/config.toml /var/www/shop/.node-version "
                "/var/www/shop/public/kept"
            ),
            before,
        )
        self.assertEqual(
            self.administer("node --version; npm --version; npx --version").split(),
            ["v24.21.0", "11.19.0", "11.19.0"],
        )
        self.assertEqual(
            self.administer(f"{catalog.executable('22.23.3')} --version").strip(), "v22.23.3"
        )
        ConfigurationPlan.objects.all().delete()
        with ssh.connect_alias("disposable-second") as shell:
            observed = runtime.observe_runtime(shell)
        self.assertEqual(observed.failure, "")
        self.assertIsNotNone(observed.inventory)
        if observed.inventory is None:
            self.fail("Fresh native reconstruction was unavailable after reboot.")
        self.assertEqual(observed.inventory.default, catalog.DEFAULT)
        self.assertEqual(set(observed.inventory.installed), set(catalog.VERSIONS))
        self.assertEqual(observed.inventory.sites, {"shop": "22.23.3"})
