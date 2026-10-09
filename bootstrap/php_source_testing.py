"""The disposable PHP source fixture; docs/ssh-connections.md#php-source-fixture."""

import os
import shlex
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import override
from unittest import TestCase as UnitTestCase
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from servers.models import Server

from . import php_supply, releases
from .models import Action, ApplyRun, ConfigurationPlan

CONFIGURED = bool(os.environ.get("BARECTL_SSH_TEST_CONTAINER"))
TRUST = "/srv/php-source-fixture/trust"


def trust_fixture(case: UnitTestCase, administer: Callable[[str], str]) -> None:
    """Approve the fixture's throwaway key in place of the publisher's for one test."""
    fingerprint, digest = administer(f"cat {TRUST}").split()
    case.enterContext(patch.object(php_supply, "PRIMARY_FINGERPRINT", fingerprint))
    case.enterContext(patch.object(php_supply, "KEY_SHA256", digest))


class PhpSourceCase(TestCase):
    """A disposable server without PHP or the approved source."""

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        config = self.directory / "ssh_config"
        config.write_text(
            "Host disposable\n"
            f"  HostName {os.environ['BARECTL_SSH_TEST_HOST']}\n"
            f"  Port {os.environ['BARECTL_SSH_TEST_PORT']}\n"
            f"  User {os.environ['BARECTL_SSH_TEST_USER']}\n"
            f"  UserKnownHostsFile {os.environ['BARECTL_SSH_TEST_KNOWN_HOSTS']}\n"
            f"  IdentityFile {os.environ['BARECTL_SSH_TEST_KEY']}\n"
        )
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        user = get_user_model().objects.create_superuser("operator")
        self.client.force_login(user)
        self.server = Server.objects.create(name="Disposable", ssh_alias="disposable")
        self.release = releases.RELEASES[os.environ.get("BARECTL_SSH_TEST_RELEASE", "24.04")]
        self.architecture = self.administer("dpkg --print-architecture").strip()
        self.clear()
        # This is administrator fixture preparation, not part of source setup.
        self.administer(
            "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "--no-install-recommends gpg >/dev/null; "
            "p=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' 2>/dev/null "
            "| awk '$2 != \"un\" {print $1}'); "
            'if [ -n "$p" ]; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $p '
            ">/dev/null; fi"
        )
        self.addCleanup(self.clear)

    def administer(self, script: str) -> str:
        result = subprocess.run(  # noqa: S603 - disposable fixture commands
            ["docker", "exec", os.environ["BARECTL_SSH_TEST_CONTAINER"], "sh", "-c", script],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return result.stdout

    def clear(self) -> None:
        self.administer(
            "systemctl stop 'barectl-apply-*' 2>/dev/null; "
            "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; "
            f"rm -f {shlex.join((php_supply.SOURCE_FILE, php_supply.KEY_FILE))} "
            f"{php_supply.PREFERENCE_FILE}; "
            "rm -f /etc/apt/preferences.d/php-source-conflict; true"
        )

    def plan(self) -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.PHP_SOURCE})
        run_worker()
        return ConfigurationPlan.objects.latest("pk")

    def apply(self, plan: ConfigurationPlan) -> ApplyRun:
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.client.post(f"/plans/{plan.pk}/apply/")
        run_worker()
        return ApplyRun.objects.get(plan=plan)
