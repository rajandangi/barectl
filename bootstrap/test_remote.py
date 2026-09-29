"""Plan preparation against a real, disposable Ubuntu server with systemd.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``discovery/test_remote.py`` describes; these tests also need ``BARECTL_SSH_TEST_CONTAINER``
to change fixtures as the server's administrator, and ``BARECTL_SSH_TEST_UNPRIVILEGED_USER``,
an account without sudo that accepts the same key. The SSH user must have noninteractive
sudo. Ground truth is read through the controller's OpenSSH client or ``docker exec``,
independently of Barectl's connection, and after every test the server's configuration,
package database and running services must be as the fixtures left them.

``BARECTL_SSH_TEST_RELEASE`` names the disposable server's Ubuntu release, 24.04 unless
set; the tests expect that release's profiles and archives.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag

from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.test_remote import CONFIGURED, STATE_COMMAND, NativeShell, setting
from operations.models import RemoteOperation
from servers.models import Server

from . import profiles, releases
from .models import (
    ADMISSION_CENTISECONDS,
    Action,
    ConfigurationPlan,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Privilege,
)

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
FIXTURES = CONFIGURED and all(
    os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in ("CONTAINER", "UNPRIVILEGED_USER")
)
RELEASE = releases.RELEASES[os.environ.get("BARECTL_SSH_TEST_RELEASE", "24.04")]
# The directory serving the server's signed third-party repository, when it has one as a
# hosting provider's image does: its current link names the clean or the offering tree.
PROVIDER = os.environ.get("BARECTL_SSH_TEST_PROVIDER_REPOSITORY", "")
PROVIDER_SITE = "http://127.0.0.1:8750"
NGINX = profiles.profile(RELEASE, Action.NGINX)
PHP = profiles.profile(RELEASE, Action.PHP)
PHP_FPM, PHP_CLI = PHP.roots
# Take Nginx away as a server without it would be: its configuration moved aside, its
# packages purged and its listener stopped. RESTORE_NGINX puts the provisioned state back
# from APT's package cache, without downloading.
REMOVE_NGINX = (
    "set -e; systemctl stop nginx; mv /etc/nginx /root/etc-nginx; "
    "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx nginx-common >/dev/null"
)
RESTORE_NGINX = (
    "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download nginx "
    ">/dev/null; rm -rf /etc/nginx; mv /root/etc-nginx /etc/nginx; systemctl restart nginx"
)


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class PreparationAcceptanceTests(TestCase):
    user: ClassVar[User]
    baseline: str
    config: Path

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in (
            "view_server",
            "view_configurationplan",
            "prepare_configurationplan",
        ):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.config = directory / "config"
        self.write_config(setting("USER"))
        self.native = NativeShell(directory)
        self.addCleanup(self.native.close)
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Disposable", ssh_alias="disposable")
        # Preparation only reads: each one leaves the server as the fixtures left it.
        self.baseline = self.remote_state()

    def write_config(self, user: str) -> None:
        self.config.write_text(
            "Host disposable\n"
            f"  HostName {setting('HOST')}\n  Port {setting('PORT')}\n  User {user}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n  IdentityFile {setting('KEY')}\n",
            encoding="utf-8",
        )

    def remote_state(self) -> str:
        result = self.native.run(STATE_COMMAND)
        self.assertEqual(result.exit_status, 0)
        return result.stdout

    def assert_remote_unchanged(self) -> None:
        self.assertEqual(self.remote_state(), self.baseline, "Preparation changed the server")

    def administer(self, script: str) -> str:
        """Run ``script`` as the server's administrator, outside Barectl; return its output."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout

    def change_fixture(self, script: str, restore: str) -> None:
        """Change the server, restoring it after the test; the read-only check restarts."""
        self.addCleanup(self.administer, restore)
        self.administer(script)
        self.baseline = self.remote_state()

    def plan(self, action: str) -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": action})
        run_worker()
        self.assert_remote_unchanged()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, RemoteOperation.Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def reasons(self, plan: ConfigurationPlan) -> set[str]:
        return set(plan.refusals.values_list("reason", flat=True))

    def assert_bound_to_this_boot(self, plan: ConfigurationPlan) -> None:
        boot_id = self.administer("cat /proc/sys/kernel/random/boot_id").strip()
        uptime = float(self.administer("cut -d' ' -f1 /proc/uptime"))
        self.assertEqual(plan.boot_id, boot_id)
        self.assertIsNotNone(plan.uptime_centiseconds)
        self.assertLessEqual(plan.uptime_centiseconds or 0, uptime * 100)
        self.assertEqual(
            plan.admission_deadline_centiseconds,
            (plan.uptime_centiseconds or 0) + ADMISSION_CENTISECONDS,
        )
        host_key = self.administer("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").split()
        self.assertEqual(plan.host_key, f"ssh-ed25519 {host_key[1]}")

    def test_the_provisioned_nginx_is_refused_as_customized_without_changes(self) -> None:
        plan = self.plan("nginx")
        self.assertFalse(plan.eligible)
        self.assertEqual(self.reasons(plan), {Reason.CUSTOMIZED})
        text = plan.refusals.get().text
        self.assertIn("/etc/nginx/sites-available/private", text)
        self.assertIn("/etc/nginx/sites-enabled/private (a link", text)
        self.assert_bound_to_this_boot(plan)
        self.assertEqual(plan.privilege, Privilege.SUDO)
        self.assertEqual(plan.os_name.split(" LTS")[0][:12], RELEASE.name)
        self.assertEqual(plan.release, RELEASE.version)
        self.assertEqual(plan.architecture, self.administer("dpkg --print-architecture").strip())
        self.assertEqual(
            plan.apt_version, self.administer("dpkg-query -W -f='${Version}' apt").strip()
        )
        hooks = plan.evidence.get(kind=PlanEvidence.Kind.APT_HOOKS).summary
        virt = " ubuntu-helper-virt-hwe," if PROVIDER else ""
        self.assertEqual(
            hooks,
            f"{14 if PROVIDER else 12} hooks from appstream, apt, command-not-found, debconf, "
            f"needrestart, packagekit, snapd,{virt} ubuntu-pro-client, update-notifier-common.",
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Customized configuration")

    def test_the_installed_php_profile_is_satisfied_without_changes(self) -> None:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertTrue(plan.no_changes)
        installed = self.administer(f"dpkg-query -W -f='${{Version}}' {PHP_FPM}").strip()
        self.assertEqual(
            set(plan.roots.values_list("name", "version", "installed")),
            {(PHP_FPM, installed, True), (PHP_CLI, installed, True)},
        )
        self.assertFalse(plan.transitions.exists())

    def test_a_stopped_disabled_php_proposes_enable_and_start(self) -> None:
        self.change_fixture(
            f"systemctl disable --now {PHP_FPM} 2>/dev/null",
            f"systemctl enable --now {PHP_FPM} 2>/dev/null",
        )
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.LOCAL_SOCKET],
        )

    def test_a_server_without_nginx_gets_exact_transitions_then_a_fresh_review(self) -> None:
        self.change_fixture(REMOVE_NGINX, RESTORE_NGINX)
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assert_bound_to_this_boot(plan)
        # The same simulation, read natively, proposes exactly the recorded transitions.
        native = self.native.run(
            "LC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
            "install nginx"
        ).stdout
        unpacked = re.findall(r"^Inst (\S+) \((\S+) ", native, re.MULTILINE)
        installs = plan.transitions.filter(step=PackageTransition.Step.INSTALL)
        self.assertEqual(list(installs.values_list("package", "version")), unpacked)
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", dict(unpacked)["nginx"], False)],
        )
        for transition in plan.transitions.all():
            self.assertLessEqual(set(transition.origins.splitlines()), RELEASE.origins)
        self.assertIn(Effect.HTTP_LISTENER, plan.effects.values_list("kind", flat=True))
        self.assertIn(Effect.NEEDRESTART, plan.effects.values_list("kind", flat=True))
        # An administrator leaves configuration behind; the next preparation sees it.
        self.change_fixture(
            "mkdir -p /etc/nginx/conf.d && echo '# custom' >/etc/nginx/conf.d/custom.conf",
            "rm -rf /etc/nginx",
        )
        refused = self.plan("nginx")
        self.assertEqual(self.reasons(refused), {Reason.LEFTOVER})
        self.assertNotEqual(refused.pk, plan.pk)
        self.assertTrue(ConfigurationPlan.objects.get(pk=plan.pk).eligible)

    def test_missing_package_indexes_block_installation_not_a_refresh_review(self) -> None:
        self.change_fixture(REMOVE_NGINX, RESTORE_NGINX)
        self.change_fixture(
            "mv /var/lib/apt/lists /root/apt-lists && install -d -m 755 /var/lib/apt/lists "
            "&& install -d -m 700 -o _apt /var/lib/apt/lists/partial",
            "rm -rf /var/lib/apt/lists && mv /root/apt-lists /var/lib/apt/lists",
        )
        plan = self.plan("nginx")
        self.assertIn(Reason.PACKAGE_METADATA, self.reasons(plan))
        self.assertTrue(
            plan.refusals.filter(text__contains=f"{RELEASE.codename}-security main").exists()
        )
        # A satisfied profile needs no indexes, and the refresh itself can be reviewed.
        self.assertTrue(self.plan("php").no_changes)
        refresh = self.plan("metadata_refresh")
        self.assertTrue(refresh.eligible, list(refresh.refusals.values_list("text", flat=True)))
        self.assertFalse(refresh.transitions.exists())
        self.assertEqual(
            list(refresh.effects.values_list("kind", flat=True)),
            [
                Effect.INDEX_UPDATE,
                Effect.UPDATE_HOOKS,
                Effect.INVALIDATES_PLANS,
                Effect.NO_ROLLBACK,
            ],
        )
        # Without downloaded indexes, no source is identified yet.
        update = refresh.effects.get(kind=Effect.INDEX_UPDATE).text
        self.assertIn("APT has no indexes of ", update)
        if PROVIDER:
            self.assertIn(f"{PROVIDER_SITE} {RELEASE.codename} (main)", update)

    @skipUnless(PROVIDER, "The disposable server has no third-party repository")
    def test_a_third_party_source_is_listed_and_refuses_plans_whose_packages_it_offers(
        self,
    ) -> None:
        self.change_fixture(REMOVE_NGINX, RESTORE_NGINX)
        # Its Release file has no Origin, which APT prints as the placeholder itself.
        targets = self.administer(
            "apt-get indextargets --format '$(ORIGIN)|$(SITE)' 'Created-By: Packages'"
        )
        self.assertIn(f"$(ORIGIN)|{PROVIDER_SITE}", targets.splitlines())
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        disclosed = plan.effects.get(kind=Effect.THIRD_PARTY_SOURCES).text
        self.assertIn(f"{PROVIDER_SITE} {RELEASE.codename} (main)", disclosed)
        hooks = plan.evidence.get(kind=PlanEvidence.Kind.APT_HOOKS).summary
        self.assertIn("packagekit", hooks)
        self.assertIn("ubuntu-helper-virt-hwe", hooks)
        # The source publishes an nginx-common older than Ubuntu's, which APT would not
        # choose; offering it at all refuses the plan.
        self.change_fixture(
            f"cp -a /var/lib/apt/lists /root/apt-lists; ln -sfn offering {PROVIDER}/current; "
            f"find {PROVIDER}/offering -exec touch {{}} +; apt-get -qq update",
            f"ln -sfn clean {PROVIDER}/current; rm -rf /var/lib/apt/lists; "
            "mv /root/apt-lists /var/lib/apt/lists",
        )
        refused = self.plan("nginx")
        self.assertEqual(self.reasons(refused), {Reason.PACKAGE_SOURCE})
        self.assertIn(
            f"{PROVIDER_SITE} {RELEASE.codename}/main, which Barectl does not identify as "
            f"{RELEASE.name}'s own archive, offers nginx-common 0.1-provider",
            refused.refusals.get().text,
        )
        simulated = self.administer("LC_ALL=C apt-get -s install nginx | grep '^Inst '")
        self.assertNotIn("0.1-provider", simulated)

    def test_an_account_without_sudo_is_refused_for_privilege(self) -> None:
        self.write_config(setting("UNPRIVILEGED_USER"))
        plan = self.plan("php")
        self.assertEqual(self.reasons(plan), {Reason.PRIVILEGE})
        self.assertEqual(plan.privilege, Privilege.UNAVAILABLE)
        self.assertTrue(plan.evidence.filter(kind=PlanEvidence.Kind.SERVICE_UNITS).exists())

    def test_sudo_authorizes_the_exact_commands_it_lists(self) -> None:
        """Each sudo provider the release installs lists the exact commands it authorizes,
        without prompting: sudo on Ubuntu 24.04, and on 26.04 its default sudo-rs and the
        original sudo, sudo.ws, when an administrator selects it."""
        providers = [""]
        if RELEASE is releases.RESOLUTE:
            self.assertEqual(
                self.administer("readlink -f /usr/bin/sudo").strip(), "/usr/lib/cargo/bin/sudo"
            )
            providers.append("update-alternatives --quiet --set sudo /usr/bin/sudo.ws")
        restore = (
            "cp /root/sudoers-deploy /etc/sudoers.d/deploy; "
            "update-alternatives --quiet --auto sudo 2>/dev/null; true"
        )
        for provider in providers:
            with self.subTest(provider=provider or "default"):
                # Only the submission is authorized: applying is possible, the listener
                # query is not, so listeners are read without process names.
                self.change_fixture(
                    "cp /etc/sudoers.d/deploy /root/sudoers-deploy; "
                    f"{provider + '; ' if provider else ''}"
                    "printf 'deploy ALL=(root) NOPASSWD: /usr/bin/systemd-run\\n' "
                    ">/etc/sudoers.d/deploy",
                    restore,
                )
                plan = self.plan("php")
                self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
                self.assertEqual(plan.privilege, Privilege.SUDO)
                self.assertEqual(
                    plan.evidence.get(kind=PlanEvidence.Kind.PRIVILEGE).summary,
                    "Noninteractive sudo is authorized for /usr/bin/systemd-run.",
                )
                # A password requirement is never answered: nothing is authorized.
                self.administer("printf 'deploy ALL=(root) ALL\\n' >/etc/sudoers.d/deploy")
                self.baseline = self.remote_state()
                refused = self.plan("php")
                self.assertEqual(self.reasons(refused), {Reason.PRIVILEGE})
                self.administer(restore)
                self.baseline = self.remote_state()

    def test_an_unknown_apt_hook_is_refused(self) -> None:
        self.change_fixture(
            "printf 'DPkg::Post-Invoke {\"true\";};\\n' >/etc/apt/apt.conf.d/99local",
            "rm -f /etc/apt/apt.conf.d/99local",
        )
        for action in ("php", "metadata_refresh"):
            with self.subTest(action=action):
                plan = self.plan(action)
                self.assertEqual(self.reasons(plan), {Reason.APT_HOOK})
