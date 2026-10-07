"""Reviewed source publication on disposable native Ubuntu, with explicit gpg prerequisite."""

import os
import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import override
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings, tag

from dashboard.testing import TEST_MANIFEST
from discovery import ssh
from discovery.fakes import run_worker
from discovery.ssh import CommandResult, ConnectionFailed, RemoteShell
from operations.models import RemoteOperation
from servers.models import Server
from servers.ssh_config import ConnectionTarget

from . import native, php_supply, php_trust, releases
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanRefusal,
    Privilege,
    Verification,
)

CONFIGURED = bool(os.environ.get("BARECTL_SSH_TEST_CONTAINER"))


class FutureClockShell(RemoteShell):
    def __init__(self, shell: RemoteShell, clock: int) -> None:
        self.shell = shell
        self.clock = clock

    @property
    @override
    def host_key(self) -> str:
        return self.shell.host_key

    @override
    def run(self, command: str) -> CommandResult:
        result = self.shell.run(command)
        if "gpgv --status-fd" in command and result.stdout.startswith("CLOCK|"):
            return CommandResult(
                result.exit_status,
                f"CLOCK|{self.clock}\n" + result.stdout.partition("\n")[2],
                result.truncated,
            )
        return result


class DisconnectedWatcher(RemoteShell):
    def __init__(self, shell: RemoteShell) -> None:
        self.shell = shell
        self.lost = False
        self.inflight = False

    @property
    @override
    def host_key(self) -> str:
        return self.shell.host_key

    @override
    def run(self, command: str) -> CommandResult:
        if command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show"):
            unit = re.search(r"barectl-apply-[0-9a-f-]+", command)
            if unit is not None:
                result = self.shell.run(f"systemctl show -p MainPID --value {unit[0]}")
                self.inflight = result.exit_status == 0 and result.stdout.strip() not in {"", "0"}
            self.lost = True
            raise ConnectionFailed("The connection ended.")
        return self.shell.run(command)


@tag("ssh")
@skipUnless(CONFIGURED, "Requires the disposable native server.")
class PhpSourcePublicationTests(TestCase):
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

    def test_guarded_source_publication_does_not_refresh_or_install_php(self) -> None:
        before = self.administer(
            "sha256sum /var/lib/dpkg/status; "
            "find /var/lib/apt/lists -maxdepth 1 -type f -exec sha256sum {} + | sort"
        )
        plan = self.plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        run = self.apply(plan)
        self.assertEqual(run.status, RemoteOperation.Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        after = self.administer(
            "sha256sum /var/lib/dpkg/status; "
            "find /var/lib/apt/lists -maxdepth 1 -type f -exec sha256sum {} + | sort"
        )
        self.assertEqual(before, after)
        self.assertEqual(
            self.administer(f"sha256sum {php_supply.KEY_FILE}").split()[0], php_supply.KEY_SHA256
        )
        self.assertIn("Signed-By:", self.administer(f"cat {php_supply.SOURCE_FILE}"))
        self.assertEqual(
            self.administer("find /etc/apt/keyrings -maxdepth 1 -name '.php-source.*' -print"), ""
        )
        self.assertTrue(self.plan().no_changes)

    def test_finish_preserves_existing_resources_and_creates_only_missing_preference(self) -> None:
        run = self.apply(self.plan())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        retained = self.administer(
            f"stat -c '%i %Y' {php_supply.KEY_FILE} {php_supply.SOURCE_FILE}"
        )
        self.administer(f"rm {php_supply.PREFERENCE_FILE}")
        finish = self.apply(self.plan())
        self.assertEqual(finish.execution, Execution.SUCCEEDED, finish.failure)
        self.assertEqual(
            retained,
            self.administer(f"stat -c '%i %Y' {php_supply.KEY_FILE} {php_supply.SOURCE_FILE}"),
        )

    def test_source_and_preference_drift_refuse_under_native_lock(self) -> None:
        plan = self.plan()
        self.administer(
            "printf '%s\\n' 'Package: php*' 'Pin: version *' 'Pin-Priority: 1001' "
            ">/etc/apt/preferences.d/php-source-conflict"
        )
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertEqual(self.administer(f"test ! -e {php_supply.SOURCE_FILE}; echo $?"), "0\n")
        refused = self.plan()
        self.assertFalse(refused.eligible)
        self.assertTrue(
            refused.refusals.filter(reason=PlanRefusal.Reason.APT_CONFIGURATION).exists()
        )

    def test_native_payload_is_one_bounded_transient_submission(self) -> None:
        plan = self.plan()
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan=plan)
        from . import php_source

        script = php_source.payload(run, plan)
        argv = native.submission(run.unit_name, script)
        self.assertLess(len(script.encode()), native.MAX_PAYLOAD)
        self.assertEqual(argv[0], "/usr/bin/systemd-run")

    def test_missing_ca_bundle_refuses_setup_without_installing_prerequisites(self) -> None:
        before = self.administer("sha256sum /var/lib/dpkg/status")
        self.administer("mv /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.off")
        try:
            plan = self.plan()
            self.assertFalse(plan.eligible)
            self.assertTrue(plan.refusals.filter(reason=PlanRefusal.Reason.PREREQUISITE).exists())
            self.assertEqual(before, self.administer("sha256sum /var/lib/dpkg/status"))
            self.assertEqual(self.administer(f"test ! -e {php_supply.SOURCE_FILE}; echo $?"), "0\n")
        finally:
            self.administer(
                "mv /etc/ssl/certs/ca-certificates.off /etc/ssl/certs/ca-certificates.crt"
            )

    def test_source_refresh_and_selected_branch_reach_native_runtime(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refresh = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refresh.verification, Verification.PASSED, refresh.failure)
        retained = ""
        for branch in ("8.4", "8.3", "8.5"):
            with self.subTest(branch=branch):
                with patch("bootstrap.php_supply.qualified", return_value=True):
                    self.client.post(
                        f"/servers/{self.server.pk}/plans/prepare/",
                        {"action": Action.PHP, "php_version": branch, "php_supply": "sury"},
                    )
                    run_worker()
                plan = ConfigurationPlan.objects.latest("pk")
                self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
                run = self.apply(plan)
                self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
                self.assertEqual(run.verification, Verification.PASSED, run.failure)
                self.assertEqual(
                    self.administer(
                        f"php{branch} -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"
                    ),
                    branch,
                )
                self.assertEqual(
                    self.administer(
                        f"php{branch} -r 'echo (int)extension_loaded(\"Zend OPcache\");'"
                    ),
                    "1",
                )
                for action, modules in (
                    (Action.PHP_MYSQL, ("mysqli", "pdo_mysql")),
                    (Action.PHP_PGSQL, ("pgsql", "pdo_pgsql")),
                ):
                    with patch("bootstrap.php_supply.qualified", return_value=True):
                        self.client.post(
                            f"/servers/{self.server.pk}/databases/prepare/",
                            {"action": action, "php_version": branch, "php_supply": "sury"},
                        )
                        run_worker()
                    driver = self.apply(ConfigurationPlan.objects.latest("pk"))
                    self.assertEqual(driver.execution, Execution.SUCCEEDED, driver.failure)
                    self.assertEqual(driver.verification, Verification.PASSED, driver.failure)
                    for module in modules:
                        self.assertEqual(
                            self.administer(
                                f"php{branch} -r 'echo (int)extension_loaded(\"{module}\");'"
                            ),
                            "1",
                        )
                if retained:
                    self.assertEqual(
                        self.administer("find /etc/php/8.4 -type f -exec sha256sum {} + | sort"),
                        retained,
                    )
                retained = self.administer("find /etc/php/8.4 -type f -exec sha256sum {} + | sort")
        self.assertEqual(self.administer("find /run -maxdepth 1 -name 'barectl-apt-*' -print"), "")
        with ssh.connect_alias(self.server.ssh_alias) as shell:
            self.assertEqual(
                php_trust.observed_supply(shell, self.release, self.architecture), "sury"
            )

    def test_unsigned_appended_date_cannot_extend_native_authenticated_index_age(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refreshed = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refreshed.verification, Verification.PASSED, refreshed.failure)
        index = php_trust.release_file(self.release)
        date = self.administer(f"grep '^Date: ' {index}").strip().removeprefix("Date: ")
        future = int((parsedate_to_datetime(date) + timedelta(days=7, seconds=1)).timestamp())
        with ssh.connect_alias(self.server.ssh_alias) as shell:
            privilege = (
                Privilege.ROOT
                if shell.run(native.USER_ID).stdout.strip() == "0"
                else Privilege.SUDO
            )
            stale = php_trust.collect(
                FutureClockShell(shell, future), self.release, self.architecture, privilege
            )
            self.assertFalse(stale.admitted, stale.refusals)
            self.assertTrue(
                any("current approved-primary-key signature" in r for r in stale.refusals),
                stale.refusals,
            )
            self.administer(f"printf '\\nDate: Thu, 01 Oct 2037 12:00:00 UTC\\n' >> {index}")
            verified = shell.run(php_trust.index_authentication(self.release))
            self.assertNotIn("2037", verified.stdout)
            result = php_trust.collect(
                FutureClockShell(shell, future), self.release, self.architecture, privilege
            )
        self.assertFalse(result.admitted, result.refusals)

    def test_compact_source_fence_detects_native_metadata_age_and_resource_drift(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refreshed = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refreshed.verification, Verification.PASSED, refreshed.failure)
        fence = php_trust.conditional_revalidation()
        before = self.administer(fence)
        self.assertEqual(before, self.administer(fence))

        self.administer(f"chmod 666 {php_supply.KEY_FILE}")
        self.assertNotEqual(before, self.administer(fence))
        self.administer(f"chmod 644 {php_supply.KEY_FILE}")
        self.assertEqual(before, self.administer(fence))
        global_key = "/etc/apt/trusted.gpg.d/php-fence-proof.gpg"
        self.administer(f"cp {php_supply.KEY_FILE} {global_key}")
        try:
            self.assertNotEqual(before, self.administer(fence))
        finally:
            self.administer(f"rm {global_key}")
        self.assertEqual(before, self.administer(fence))
        index = php_trust.release_file(self.release)
        date = self.administer(f"grep '^Date: ' {index}").strip().removeprefix("Date: ")
        future = int((parsedate_to_datetime(date) + timedelta(days=7, seconds=1)).timestamp())
        clock = (
            "#!/bin/sh\n"
            'if [ "$*" = "-u +%s" ]; then '
            f"printf '%s\\n' {future}; else exec /usr/bin/date-php-proof \"$@\"; fi\n"
        )
        self.administer(
            "mv /usr/bin/date /usr/bin/date-php-proof; "
            f"printf %s {shlex.quote(clock)} >/usr/bin/date; chmod 755 /usr/bin/date"
        )
        try:
            self.assertNotEqual(before, self.administer(fence))
        finally:
            self.administer("mv /usr/bin/date-php-proof /usr/bin/date")
        self.assertEqual(before, self.administer(fence))

    def test_public_selection_refuses_native_trust_priority_and_index_faults(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refreshed = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refreshed.verification, Verification.PASSED, refreshed.failure)
        before = self.administer("sha256sum /var/lib/dpkg/status")
        directory = "/run/php-source-fault-proof"
        key = php_supply.KEY_FILE
        index = php_trust.release_file(self.release)
        packages = self.administer(
            "find /var/lib/apt/lists -maxdepth 1 -type f -name "
            f"'packages.sury.org_php_dists_{self.release.codename}_main_binary-"
            f"{self.architecture}_Packages*' -print"
        ).splitlines()
        self.assertEqual(len(packages), 1, packages)
        package_index = packages[0]
        self.administer(f"mkdir -m 700 {directory}; cp {key} {directory}/key")
        ubuntu_key = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
        global_key = "/etc/apt/trusted.gpg.d/php-source-fault-proof.gpg"
        target = "/etc/apt/apt.conf.d/99php-source-fault-proof"
        faults = (
            ("wrong dedicated key", f"cp {ubuntu_key} {key}", f"cp {directory}/key {key}"),
            (
                "extra dedicated key",
                f"cat {ubuntu_key} >>{key}",
                f"cp {directory}/key {key}",
            ),
            ("global publisher trust", f"cp {key} {global_key}", f"rm {global_key}"),
            (
                "target release interference",
                f"printf '%s\\n' 'APT::Default-Release \"{self.release.codename}\";' >{target}",
                f"rm {target}",
            ),
            ("own suite absent", f"mv {index} {directory}/index", f"mv {directory}/index {index}"),
            (
                "package index absent",
                f"mv {package_index} {directory}/packages",
                f"mv {directory}/packages {package_index}",
            ),
        )
        try:
            with patch("bootstrap.php_supply.qualified", return_value=True):
                for name, introduce, restore in faults:
                    with self.subTest(fault=name):
                        self.administer(introduce)
                        try:
                            self.client.post(
                                f"/servers/{self.server.pk}/plans/prepare/",
                                {"action": Action.PHP, "php_version": "8.4", "php_supply": "sury"},
                            )
                            run_worker()
                            refused = ConfigurationPlan.objects.latest("pk")
                            self.assertFalse(refused.eligible)
                            self.assertTrue(refused.refusals.exists())
                            self.assertEqual(
                                before, self.administer("sha256sum /var/lib/dpkg/status")
                            )
                        finally:
                            self.administer(restore)
                self.client.post(
                    f"/servers/{self.server.pk}/plans/prepare/",
                    {"action": Action.PHP, "php_version": "8.4", "php_supply": "sury"},
                )
                run_worker()
            accepted = ConfigurationPlan.objects.latest("pk")
            self.assertTrue(
                accepted.eligible, list(accepted.refusals.values_list("text", flat=True))
            )
        finally:
            self.administer(f"rm -rf {directory}; rm -f {global_key} {target}")

    def test_accepted_source_install_survives_ssh_loss_and_reconciles_once(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refreshed = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refreshed.verification, Verification.PASSED, refreshed.failure)
        with patch("bootstrap.php_supply.qualified", return_value=True):
            self.client.post(
                f"/servers/{self.server.pk}/plans/prepare/",
                {"action": Action.PHP, "php_version": "8.4", "php_supply": "sury"},
            )
            run_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        real = ssh.connect
        watchers: list[DisconnectedWatcher] = []

        @contextmanager
        def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
            with real(target) as shell:
                watcher = DisconnectedWatcher(shell)
                watchers.append(watcher)
                yield watcher

        with patch.object(ssh, "connect", connect):
            run = self.apply(plan)
        self.assertTrue(any(w.lost for w in watchers))
        self.assertTrue(any(w.inflight for w in watchers))
        self.assertEqual(run.status, RemoteOperation.Status.RECONCILING, run.failure)
        self.assertIsNotNone(run.acknowledged_at)
        self.assertEqual((run.php_version, run.php_supply), ("8.4", "sury"))
        deadline = time.monotonic() + 180
        while self.administer(f"systemctl show -p MainPID --value {run.unit_name}").strip() != "0":
            if time.monotonic() >= deadline:
                self.fail(self.administer(f"journalctl -q --no-pager -u {run.unit_name}"))
            time.sleep(0.2)
        invocation = self.administer(f"systemctl show -p InvocationID --value {run.unit_name}")
        self.client.post(f"/applies/{run.pk}/check/")
        run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, RemoteOperation.Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run_worker()
        self.assertEqual(ApplyRun.objects.filter(plan_number=plan.pk).count(), 1)
        self.assertEqual(
            invocation, self.administer(f"systemctl show -p InvocationID --value {run.unit_name}")
        )
        journal = self.administer(f"journalctl -q --no-pager -o cat -u {run.unit_name}")
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertEqual(
            self.administer("php8.4 -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"), "8.4"
        )
        cache = native.archive_cache(run.unit_name).removesuffix("archives/")
        self.assertEqual(self.administer(f"test ! -e {cache} && echo removed").strip(), "removed")
        self.assertEqual(self.administer("find /run -maxdepth 1 -name 'barectl-apt-*' -print"), "")

    def test_native_fixture_signatures_refuse_expired_and_revoked_primary_keys(self) -> None:
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "--no-install-recommends gpg-agent >/dev/null"
        )
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        refreshed = self.apply(ConfigurationPlan.objects.latest("pk"))
        self.assertEqual(refreshed.verification, Verification.PASSED, refreshed.failure)
        directory = "/run/php-signature-fault-proof"
        key = php_supply.KEY_FILE
        source = php_supply.SOURCE_FILE
        index = php_trust.release_file(self.release)
        self.administer(
            f"set -e; mkdir -m 700 {directory}; cp {key} {directory}/key; "
            f"cp {source} {directory}/source; cp {index} {directory}/index; "
            f"gpgv --output {directory}/Release --keyring {key} {index}"
        )
        now = int(self.administer("date -u +%s").strip())
        homes: list[str] = []
        try:
            for state in ("valid", "expired", "revoked"):
                with self.subTest(key=state):
                    home = f"{directory}/{state}"
                    homes.append(home)
                    clock = now - 172800 if state == "expired" else now
                    expiry = "1d" if state == "expired" else "never"
                    gpg = (
                        f"gpg --homedir {home} --batch --yes --pinentry-mode loopback "
                        f"--passphrase '' --faked-system-time {clock}"
                    )
                    self.administer(
                        f"set -e; mkdir -m 700 {home}; {gpg} --quick-generate-key "
                        f"'Disposable PHP source fixture' ed25519 sign {expiry}; "
                        f"{gpg} --clearsign --output {index} {directory}/Release"
                    )
                    fingerprint = self.administer(
                        f"{gpg} --with-colons --list-keys | "
                        "awk -F: '$1 == \"fpr\" {print $10; exit}'"
                    ).strip()
                    if state == "revoked":
                        self.administer(
                            f"set -e; sed 's/^://' {home}/openpgp-revocs.d/{fingerprint}.rev "
                            f"| {gpg} --import"
                        )
                    self.administer(f"{gpg} --export >{key}; chmod 644 {key}")
                    digest = self.administer(f"sha256sum {key}").split()[0]
                    with (
                        patch.object(php_supply, "PRIMARY_FINGERPRINT", fingerprint),
                        patch.object(php_supply, "KEY_SHA256", digest),
                    ):
                        content = php_supply.source_content(self.release, self.architecture)
                        self.administer(f"printf %s {shlex.quote(content)} >{source}")
                        with ssh.connect_alias(self.server.ssh_alias) as shell:
                            privilege = (
                                Privilege.ROOT
                                if shell.run(native.USER_ID).stdout.strip() == "0"
                                else Privilege.SUDO
                            )
                            status = shell.run(php_trust.index_authentication(self.release))
                            evidence = php_trust.collect(
                                shell, self.release, self.architecture, privilege
                            )
                        if state == "valid":
                            self.assertIn("[GNUPG:] VALIDSIG " + fingerprint, status.stdout)
                            self.assertTrue(evidence.admitted, evidence.refusals)
                        else:
                            self.assertIn(
                                "[GNUPG:] " + ("EXPKEYSIG" if state == "expired" else "REVKEYSIG"),
                                status.stdout,
                            )
                            self.assertFalse(evidence.admitted)
                            self.assertTrue(evidence.refusals)
        finally:
            self.administer(
                f"cp {directory}/key {key}; cp {directory}/source {source}; "
                f"cp {directory}/index {index}"
            )
            for home in homes:
                self.administer(f"gpgconf --homedir {home} --kill gpg-agent")
            self.administer(f"rm -rf {directory}")

    def test_failed_fresh_source_update_refuses_subsequent_installation(self) -> None:
        setup = self.apply(self.plan())
        self.assertEqual(setup.execution, Execution.SUCCEEDED, setup.failure)
        self.administer(
            "find /var/lib/apt/lists -maxdepth 1 -type f -name 'packages.sury.org_php_*' -delete"
        )
        self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": Action.METADATA_REFRESH}
        )
        run_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        before = self.administer("sha256sum /var/lib/dpkg/status")
        backup = "/run/php-source-update-hosts-proof"
        self.administer(
            f"cp /etc/hosts {backup}; printf '\n127.0.0.1 packages.sury.org\n' >>/etc/hosts"
        )
        try:
            failed = self.apply(plan)
            self.assertEqual(failed.execution, Execution.FAILED, failed.failure)
            journal = self.administer(f"journalctl -q --no-pager -o cat -u {failed.unit_name}")
            self.assertIn("packages.sury.org", journal)
            self.assertIn("Failed to fetch", journal)
            self.assertEqual(before, self.administer("sha256sum /var/lib/dpkg/status"))
        finally:
            self.administer(f"cat {backup} >/etc/hosts; rm {backup}")
        with patch("bootstrap.php_supply.qualified", return_value=True):
            self.client.post(
                f"/servers/{self.server.pk}/plans/prepare/",
                {"action": Action.PHP, "php_version": "8.4", "php_supply": "sury"},
            )
            run_worker()
        refused = ConfigurationPlan.objects.latest("pk")
        self.assertFalse(refused.eligible)
        self.assertTrue(refused.refusals.filter(reason=PlanRefusal.Reason.PACKAGE_SOURCE).exists())
        self.assertEqual(before, self.administer("sha256sum /var/lib/dpkg/status"))
        self.assertEqual(self.administer("find /run -maxdepth 1 -name 'barectl-apt-*' -print"), "")
