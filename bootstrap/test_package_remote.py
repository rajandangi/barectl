"""Exact reviewed Nginx installation on a real, disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Each test starts from the server without
Nginx, as ``bootstrap/test_remote.py`` removes it, and restores the provisioned Nginx
afterwards. Every run goes through actual APT, dpkg, debconf and systemd; ground truth is
read through ``docker exec``, independently of Barectl's connection.

Faults are injected natively: by changing packages, marks, holds and locks as the
server's administrator between review and apply, by inserting such a change into a
submitted payload between its revalidation and APT's resolution, or between APT's
resolution and the guard as an earlier pre-install command, by submitting a payload whose
approved transaction differs from APT's, and by feeding the guard malformed protocol
input. Only those test payloads differ from what the worker submits.
"""

import json
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import override
from unittest import skipUnless

from django.contrib.auth.models import Permission

from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation

from . import native
from .models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Verification,
)
from .test_apply_remote import ApplyAcceptanceTestCase, _is_inspection
from .test_remote import NGINX, PROVIDER, REMOVE_NGINX

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
# Put the provisioned Nginx back, whatever a test left: holds, masks, injected packages.
RESTORE = (
    "apt-mark unhold nginx nginx-common >/dev/null 2>&1; "
    "echo 'iproute2 install' | dpkg --set-selections; apt-mark manual iproute2 >/dev/null; "
    "systemctl unmask nginx >/dev/null 2>&1; "
    "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download nginx "
    ">/dev/null; rm -rf /etc/nginx; mv /root/etc-nginx /etc/nginx; "
    "systemctl enable -q nginx; systemctl restart nginx"
)
# What must not change when a run stops before dpkg: dpkg's status and log, the marks,
# and whether Nginx is installed.
PACKAGE_STATE = (
    "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states | cut -d' ' -f1; "
    "wc -l </var/log/dpkg.log; "
    "dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' nginx nginx-common 2>/dev/null; true"
)
# Lines dpkg logs while it unpacks or configures the nginx package itself.
NGINX_DPKG = re.compile(r" (install|configure|status \S+) nginx:[a-z0-9]+ ")
# A new, independent controller in its own process and database: it registers the server
# through the second alias and key, discovers it, and reviews the Nginx profile.
RECONSTRUCTION = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ConfigurationPlan
from discovery.fakes import run_worker
from discovery.models import ComponentObservation
from discovery.services import request_discovery
from servers.models import Server

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("fresh-operator")
for codename in ("view_server", "view_configurationplan", "prepare_configurationplan"):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable-second")
request_discovery(server)
run_worker()
nginx = ComponentObservation.objects.get(component="nginx")
client = Client()
client.force_login(user)
client.post(f"/servers/{server.pk}/plans/prepare/", {"action": "nginx"}, secure=True)
run_worker()
plan = ConfigurationPlan.objects.get()
print(json.dumps({
    "packages": nginx.packages.splitlines(),
    "units": [
        f"{u.name} {u.active_state} {u.unit_file_state}" for u in nginx.service_units.all()
    ],
    "sites": list(
        nginx.snapshot.nginx_site_files.values_list("name", flat=True)
    ),
    "no_changes": plan.no_changes,
    "eligible": plan.eligible,
}))
"""


@dataclass(frozen=True)
class Reconstructed:
    """What the independent controller observed and reviewed."""

    packages: list[str]
    units: list[str]
    sites: list[str]
    no_changes: bool
    eligible: bool


class PackageAcceptanceTestCase(ApplyAcceptanceTestCase):
    """The disposable server without Nginx, restored to its provisioned Nginx afterwards."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        self.administer(REMOVE_NGINX)
        self.addCleanup(self.administer, RESTORE)
        # dpkg's log so far, which includes the provisioned installation.
        self.logged = int(self.administer("wc -l </var/log/dpkg.log"))

    def package_state(self) -> str:
        return self.administer(PACKAGE_STATE)

    def nginx_plan(self) -> ConfigurationPlan:
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def actions(self, plan: ConfigurationPlan) -> list[native.PackageAction]:
        return [
            native.PackageAction(
                transition.step == PackageTransition.Step.INSTALL,
                transition.package,
                transition.version,
                transition.architecture,
            )
            for transition in plan.transitions.all()
        ]

    def payload(
        self,
        plan: ConfigurationPlan,
        unit: str,
        boot: str,
        deadline: int,
        actions: list[native.PackageAction] | None = None,
    ) -> str:
        """The payload Barectl's worker would submit for ``plan``, or with ``actions``."""
        evidence = dict(plan.evidence.values_list("kind", "fingerprint"))
        return native.package_change(
            unit,
            boot,
            deadline,
            apt=evidence[PlanEvidence.Kind.APT_REVALIDATION],
            packages=evidence[PlanEvidence.Kind.PACKAGE_REVALIDATION],
            scope=NGINX.revalidation,
            roots=[(root.name, root.version) for root in plan.roots.all()],
            actions=self.actions(plan) if actions is None else actions,
            services=NGINX.units,
            enable=False,
            start=False,
            check=NGINX.check,
        )

    def submit_with(
        self, plan: ConfigurationPlan, approved: list[native.PackageAction] | None = None
    ) -> str:
        def script(unit: str, boot: str, deadline: int) -> str:
            return self.payload(plan, unit, boot, deadline, approved)

        return self.submit(script)

    def assert_not_installed(self) -> None:
        state = self.administer("dpkg-query -W -f='${db:Status-Abbrev}' nginx 2>/dev/null; true")
        self.assertNotEqual(state.strip(), "ii")
        since = self.administer(f"tail -n +{self.logged + 1} /var/log/dpkg.log")
        self.assertNotRegex(since, NGINX_DPKG)


class PackageInstallationTests(PackageAcceptanceTestCase):
    def test_a_reviewed_installation_is_exact_verified_and_reconstructed(self) -> None:
        automatic_before = set(self.administer("apt-mark showauto").split())
        plan = self.nginx_plan()
        installs = dict(
            plan.transitions.filter(step=PackageTransition.Step.INSTALL).values_list(
                "package", "version"
            )
        )
        self.assertIn("nginx", installs)
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", installs["nginx"], False)],
        )
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        # Order on the server: debconf's hook, then the guard, then dpkg.
        journal = self.journal(run.unit_name)
        preconfigure = journal.index("Preconfiguring packages")
        admitted = journal.index(native.GUARD_ADMITTED)
        unpacking = journal.index("Unpacking ")
        self.assertLess(preconfigure, admitted)
        self.assertLess(admitted, unpacking)
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertNotIn(native.GUARD_REFUSED, journal)
        # Exactly the reviewed versions, the root manual, the new dependencies automatic,
        # and every other package's mark kept.
        for name, version in installs.items():
            shown = self.administer(f"dpkg-query -W -f='${{Version}} ${{db:Status-Abbrev}}' {name}")
            self.assertEqual(shown.strip(), f"{version} ii")
        self.assertEqual(self.administer("apt-mark showmanual nginx").split(), ["nginx"])
        dependencies = set(installs) - {"nginx"}
        automatic_after = set(self.administer("apt-mark showauto").split())
        self.assertEqual(automatic_after - dependencies, automatic_before)
        self.assertLessEqual(dependencies, automatic_after)
        # The package's maintainer scripts enabled and started the service; the default
        # site listens on every IPv4 and IPv6 address.
        self.assertEqual(
            self.administer("systemctl is-enabled nginx; systemctl is-active nginx").split(),
            ["enabled", "active"],
        )
        listening = self.administer("ss -Hltn sport = :80")
        self.assertIn("0.0.0.0:80", listening)
        self.assertIn("[::]:80", listening)
        # Discovery was refreshed after the run and observes the installation.
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        self.assertEqual(attempt.status, Status.SUCCEEDED, attempt.failure)
        nginx = ComponentObservation.objects.get(snapshot__attempt=attempt, component="nginx")
        self.assertIn(f"nginx {installs['nginx']}", nginx.packages.splitlines())
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")
        self.assertContains(page, "collected after this run finished")

        # Repeating the profile reviews no changes and never runs APT.
        again = self.plan("nginx")
        self.assertTrue(again.no_changes)
        self.client.post(f"/plans/{again.pk}/apply/")
        self.assertFalse(ApplyRun.objects.filter(plan_number=again.pk).exists())
        self.assertEqual(self.units(), [run.unit_name])

        # An independent controller, database and alias reconstructs the same state.
        result = self.reconstruct()
        self.assertIn(f"nginx {installs['nginx']}", result.packages)
        self.assertIn("nginx.service active enabled", result.units)
        self.assertEqual(result.sites, ["default"])
        self.assertTrue(result.eligible and result.no_changes, result)

    def reconstruct(self) -> Reconstructed:
        directory = self.directory / "fresh"
        directory.mkdir()
        config = directory / "config"
        self.write_config(setting("USER"), config)
        completed = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                RECONSTRUCTION,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        return Reconstructed(**json.loads(completed.stdout.strip().splitlines()[-1]))

    def test_service_effects_external_changes_and_refusals(self) -> None:
        self.assertEqual(self.apply(self.nginx_plan()).status, Status.SUCCEEDED)
        # An administrator stops and disables Nginx outside Barectl; discovery sees it.
        self.administer("systemctl disable --now -q nginx")
        request_discovery(self.server)
        run_worker()
        nginx = ComponentObservation.objects.filter(
            snapshot__server=self.server, component="nginx"
        ).latest("pk")
        units = {unit.name: unit for unit in nginx.service_units.all()}
        self.assertEqual(
            (units["nginx.service"].active_state, units["nginx.service"].unit_file_state),
            ("inactive", "disabled"),
        )
        # The review proposes only enabling and starting, applied without APT.
        plan = self.nginx_plan()
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.HTTP_LISTENER],
        )
        before = self.package_state()
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.assertEqual(self.package_state(), before)
        self.assertEqual(
            self.administer("systemctl is-enabled nginx; systemctl is-active nginx").split(),
            ["enabled", "active"],
        )
        # Masked or customized states are refused without changes.
        self.administer("systemctl mask -q nginx")
        refused = self.plan("nginx")
        self.assertEqual(
            set(refused.refusals.values_list("reason", flat=True)),
            {PlanRefusal.Reason.SERVICE_UNIT},
        )
        self.administer("systemctl unmask -q nginx")
        self.administer("echo '# local' >>/etc/nginx/nginx.conf")
        refused = self.plan("nginx")
        self.assertIn(
            PlanRefusal.Reason.CUSTOMIZED, refused.refusals.values_list("reason", flat=True)
        )

    def test_losing_the_connection_mid_installation_reconciles_the_same_unit(self) -> None:
        plan = self.nginx_plan()
        with self.losing(_is_inspection, after=False):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIsNotNone(run.acknowledged_at)
        # The installation continues on the server, owned by systemd.
        self.wait_terminal(run.unit_name, timeout=300)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(self.units(), [run.unit_name])
        self.assertTrue(DiscoveryAttempt.objects.filter(server=self.server).exists())


class PackageAdmissionTests(PackageAcceptanceTestCase):
    def test_changes_between_review_and_the_lock_refuse_before_apt(self) -> None:
        for change, undo in (
            # A dependency installed outside Barectl.
            (
                (
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download "
                    "nginx-common >/dev/null"
                ),
                "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx-common >/dev/null",
            ),
            # A hold on the root package.
            ("apt-mark hold nginx >/dev/null", "apt-mark unhold nginx >/dev/null"),
            # An earlier package's automatic mark.
            ("apt-mark auto iproute2 >/dev/null", "apt-mark manual iproute2 >/dev/null"),
        ):
            with self.subTest(change=change):
                plan = self.nginx_plan()
                self.administer(change)
                self.addCleanup(self.administer, undo)
                before = self.package_state()
                run = self.apply(plan)
                self.assertEqual(run.execution, Execution.DRIFT, run.failure)
                self.assertEqual(run.status, Status.FAILED)
                journal = self.journal(run.unit_name)
                self.assertNotIn("Reading package lists", journal)
                self.assertEqual(self.package_state(), before)
                self.assert_not_installed()
                self.assertFalse(DiscoveryAttempt.objects.filter(server=self.server).exists())
                self.administer(undo)

    def test_package_lock_contention_refuses_at_once(self) -> None:
        plan = self.nginx_plan()
        holder = (
            "import fcntl, os, time; "
            "f = os.open('/var/lib/dpkg/lock-frontend', os.O_RDWR | os.O_CREAT, 0o640); "
            "fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(120)"
        )
        self.addCleanup(self.administer, "pkill -f '[l]ock-frontend'; true")
        self.administer(f'python3 -c "{holder}"', detach=True)
        time.sleep(1)
        before = self.package_state()
        started = time.monotonic()
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.PACKAGE_MANAGER_BUSY, run.failure)
        self.assertLess(time.monotonic() - started, 60)
        journal = self.journal(run.unit_name)
        self.assertIn("Could not get lock /var/lib/dpkg/lock-frontend", journal)
        # A server configuration that makes APT wait, such as a provider's 99lock-timeout,
        # does not apply to Barectl's invocation.
        self.assertNotIn("Waiting for cache lock", journal)
        if PROVIDER:
            timeout = self.administer("apt-config shell T DPkg::Lock::Timeout").strip()
            self.assertEqual(timeout, "T='60'")
        self.assertEqual(self.package_state(), before)
        self.assert_not_installed()

    @skipUnless(PROVIDER, "The disposable server has no provider customizations")
    def test_a_provider_pre_install_hook_runs_before_the_guard_and_changes_nothing(self) -> None:
        plan = self.nginx_plan()
        # docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#consequences
        unset = self.administer("apt-config shell V DPkg::Tools::Options::test::Version")
        self.assertEqual(unset.strip(), "")
        apt = "DEBIAN_FRONTEND=noninteractive apt-get"
        name = self.submit(
            lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                apt, f"{apt} -o Debug::RunScripts=1", 1
            )
        )
        self.wait_terminal(name)
        self.assertEqual(self.inspect(name).execution, Execution.SUCCEEDED)
        journal = self.journal(name)
        running = "Running external script with list of all .deb file: '"
        debconf = journal.index(f"{running}/usr/sbin/dpkg-preconfigure --apt")
        virt = journal.index(f"{running}test -x /usr/bin/apt_hook_ubuntu_virt")
        guard = journal.index(f"{running}{native.GUARD_NAME}()")
        # The guard's admission proves dpkg's status was unchanged when it ran.
        admitted = journal.index(native.GUARD_ADMITTED)
        self.assertLess(debconf, virt)
        self.assertLess(virt, guard)
        self.assertLess(guard, admitted)
        self.assertLess(admitted, journal.index("Unpacking "))
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)

    def test_the_guard_refuses_any_transaction_but_the_reviewed_one(self) -> None:
        plan = self.nginx_plan()
        actions = self.actions(plan)
        root = next(a for a in actions if a.package == "nginx")
        cases = {
            "a missing dependency": [a for a in actions if a.package == "nginx"],
            "an extra package": [
                *actions,
                native.PackageAction(True, "hello", "2.10-3build2", root.architecture),
                native.PackageAction(False, "hello", "2.10-3build2", root.architecture),
            ],
            "another version": [
                native.PackageAction(a.unpack, a.package, f"{a.version}.1", a.architecture)
                for a in actions
            ],
            "another architecture": [
                native.PackageAction(
                    a.unpack,
                    a.package,
                    a.version,
                    "s390x" if a.package == "nginx" else a.architecture,
                )
                for a in actions
            ],
            "unpacks without configuration": [a for a in actions if a.unpack],
            "configuration without unpacks": [a for a in actions if not a.unpack],
        }
        for case, approved in cases.items():
            with self.subTest(case=case):
                before = self.package_state()
                name = self.submit_with(plan, approved)
                self.wait_terminal(name)
                self.assertEqual(self.inspect(name).execution, Execution.TRANSACTION_REFUSED)
                journal = self.journal(name)
                self.assertIn(f"{native.GUARD_REFUSED} transaction", journal)
                self.assertIn("Preconfiguring packages", journal)
                self.assertEqual(self.package_state(), before)
                self.assert_not_installed()

    def test_races_after_revalidation_are_refused_by_apt_or_the_guard(self) -> None:
        plan = self.nginx_plan()

        def injected(step: str) -> str:
            """The worker's payload with ``step`` run after the lock and revalidation."""
            return self.submit(
                lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                    "b=$(sha256sum", f"{step}; b=$(sha256sum", 1
                )
            )

        # A dependency installed between revalidation and APT's resolution: APT's
        # transaction lacks it, so the guard refuses the rest.
        name = injected(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download nginx-common"
        )
        self.addCleanup(
            self.administer,
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx-common >/dev/null",
        )
        self.wait_terminal(name)
        self.assertEqual(self.inspect(name).execution, Execution.TRANSACTION_REFUSED)
        self.assertIn(f"{native.GUARD_REFUSED} transaction", self.journal(name))
        self.assert_not_installed()
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx-common >/dev/null"
        )

        # A hold placed after revalidation: APT itself refuses before dpkg.
        self.addCleanup(self.administer, "apt-mark unhold nginx >/dev/null")
        name = injected("apt-mark hold nginx >/dev/null")
        self.wait_terminal(name)
        self.assertEqual(self.inspect(name).execution, Execution.INSTALL_NOT_STARTED)
        self.assertIn("Held packages were changed", self.journal(name))
        self.assertNotIn(native.GUARD_ADMITTED + "\n", self.journal(name))
        self.assert_not_installed()
        self.administer("apt-mark unhold nginx >/dev/null")

        # dpkg's state changed after APT resolved its transaction, here by an earlier
        # pre-install command: the guard refuses before dpkg unpacks anything. The hold
        # left a selection in dpkg's status, so the earlier plan would be drift now.
        plan = self.nginx_plan()
        change = "echo 'iproute2 hold' | dpkg --set-selections"
        predecessor = shlex.quote(f"DPkg::Pre-Install-Pkgs::={change}")
        name = self.submit(
            lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                "-o 'DPkg::Pre-Install-Pkgs::=",
                f"-o {predecessor} -o 'DPkg::Pre-Install-Pkgs::=",
                1,
            )
        )
        self.wait_terminal(name)
        # dpkg's status did change, by the earlier command, so the payload never reports
        # that nothing changed; dpkg itself unpacked nothing.
        self.assertEqual(self.inspect(name).execution, Execution.INSTALL_FAILED)
        self.assertIn(f"{native.GUARD_REFUSED} dpkg-status", self.journal(name))
        self.assertNotIn("Unpacking ", self.journal(name))
        self.assert_not_installed()

    def test_a_partial_download_stops_apt_before_dpkg(self) -> None:
        plan = self.nginx_plan()
        # APT's cache keeps every reviewed archive but nginx's own, and the archive is
        # unreachable, so APT downloads part of the transaction and fails on the rest.
        held = "/root/held-archives"
        self.administer(f"mkdir -p {held}; mv /var/cache/apt/archives/nginx_*.deb {held}/")
        self.addCleanup(self.administer, f"mv {held}/*.deb /var/cache/apt/archives/; rmdir {held}")
        before = self.package_state()
        apt = "DEBIAN_FRONTEND=noninteractive apt-get"
        unreachable = f"http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 {apt}"
        name = self.submit(
            lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                apt, unreachable, 1
            )
        )
        self.wait_terminal(name)
        self.assertEqual(self.inspect(name).execution, Execution.INSTALL_NOT_STARTED)
        journal = self.journal(name)
        self.assertIn("Failed to fetch", journal)
        self.assertNotIn(native.GUARD_ADMITTED, journal)
        self.assertEqual(self.package_state(), before)
        self.assert_not_installed()
        # The archives APT already had stay in its cache; no package changed.
        self.assertIn("nginx-common_", self.administer("ls /var/cache/apt/archives"))

    def test_the_guard_reads_the_protocol_strictly(self) -> None:
        plan = self.nginx_plan()
        actions = self.actions(plan)
        guard = native.guard(actions)
        lines = []
        for action in sorted(actions, key=lambda a: not a.unpack):
            multiarch = "foreign" if action.architecture == "all" else "none"
            target = (
                f"{native.ARCHIVES}{action.normalized().split()[-1]}"
                if action.unpack
                else "**CONFIGURE**"
            )
            lines.append(
                f"{action.package} - - none < {action.version} {action.architecture} "
                f"{multiarch} {target}"
            )
        body = "\n".join(lines) + "\n"
        header = "VERSION 3\nAPT::Architecture=arm64\n\n"
        upgrade = lines[0].replace("- - none <", "1.0 all none <", 1)
        removal = lines[-1].rsplit(" ", 1)[0] + " **REMOVE**"
        arch = next(a.architecture for a in actions if a.package == "nginx")
        extra = f"hello - - none < 2.10-3build2 {arch} none"
        configure_only = f"{extra} **CONFIGURE**\n"
        unpack_only = f"{extra} {native.ARCHIVES}hello_2.10-3build2_{arch}.deb\n"
        cases = {
            "the complete transaction": (header + body, 0, native.GUARD_ADMITTED),
            "no configuration section end": (
                "VERSION 3\nAPT::Architecture=arm64\n",
                1,
                "truncated",
            ),
            "a truncated last line": (header + body[:-12], 1, "truncated"),
            "another protocol version": (header.replace("3", "2", 1) + body, 1, "version"),
            "an upgrade": (header + body.replace(lines[0], upgrade), 1, "transition"),
            "a removal": (header + body.replace(lines[-1], removal), 1, "action"),
            "an unknown multi-arch form": (
                header + body.replace(" none /", " weird /", 1),
                1,
                "form",
            ),
            "doubled spaces": (header + body.replace(" < ", "  < ", 1), 1, "form"),
            "a repeated action": (header + body + lines[-1] + "\n", 1, "transaction"),
            "an extra configure-only action": (header + body + configure_only, 1, "transaction"),
            "an extra unpack": (header + body + unpack_only, 1, "transaction"),
            "a partial round": (header + "\n".join(lines[:1]) + "\n", 1, "transaction"),
            "an archive outside APT's cache": (
                header + body.replace(native.ARCHIVES, "/media/cdrom/pool/", 1),
                1,
                "action",
            ),
        }
        status = "$(sha256sum /var/lib/dpkg/status | cut -d' ' -f1)"
        for case, (text, exit_status, output) in cases.items():
            with self.subTest(case=case):
                script = (
                    f"printf '%s' {shlex.quote(text)} | DPKG_FRONTEND_LOCKED=true "
                    f"APT_HOOK_INFO_FD=0 {native.STATUS_VARIABLE}={status} "
                    f'sh -c {shlex.quote(guard)}; echo "exit $?"'
                )
                result = self.administer(script)
                self.assertIn(output, result)
                self.assertTrue(result.endswith(f"exit {exit_status}\n"), result)
        # Outside APT's frontend lock, or after dpkg's state changed, nothing is admitted.
        for environment, reason in (
            (f"APT_HOOK_INFO_FD=0 {native.STATUS_VARIABLE}={status}", "frontend-lock"),
            (
                f"DPKG_FRONTEND_LOCKED=true APT_HOOK_INFO_FD=0 {native.STATUS_VARIABLE}=0",
                "dpkg-status",
            ),
        ):
            with self.subTest(reason=reason):
                result = self.administer(
                    f"printf '%s' {shlex.quote(header + body)} | {environment} "
                    f'sh -c {shlex.quote(guard)}; echo "exit $?"'
                )
                self.assertIn(f"{native.GUARD_REFUSED} {reason}", result)
                self.assertTrue(result.endswith("exit 1\n"))
