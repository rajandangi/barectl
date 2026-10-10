"""The release-aware platform policy: Ubuntu 26.04 reviewed by its own rules.

Real views, services, the worker, persistence and rendering run against a simulated
Ubuntu 26.04 server. These tests establish that a server is reviewed and applied only
against its release's archives, tool series, hook baseline and profiles, that another
release's packages, indexes or tools are refused, and that any other release, Ubuntu 24.04
included, is unsupported. Real APT 3.2, systemd 259 and sudo-rs behaviour is established by
the disposable-server suites.
"""

import re
import shlex
from typing import override

from django.test import SimpleTestCase

from discovery.ssh import CommandResult

from . import inspection, profiles, releases
from .evidence import OsRelease, Unreadable, parse_apt_config, parse_index_targets
from .fakes import PACKAGING, PreparationTestCase, baseline_hooks
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Verification,
)
from .plan_testing import kept_text
from .test_apply import ApplyTestCase
from .test_workflow import names_release

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
_PHP_VERSION = PACKAGING.php_version
# Ubuntu 24.04's suites, which an Ubuntu 26.04 server never uses.
_NOBLE_SUITES = ("noble", "noble-updates", "noble-security")


class ReleasePolicyTests(SimpleTestCase):
    def test_the_release_names_its_own_archives_tools_and_php(self) -> None:
        resolute = releases.RESOLUTE
        self.assertEqual(resolute.suites, ("resolute", "resolute-updates", "resolute-security"))
        self.assertEqual(
            resolute.origins,
            {
                "Ubuntu:26.04/resolute",
                "Ubuntu:26.04/resolute-updates",
                "Ubuntu:26.04/resolute-security",
            },
        )
        self.assertEqual(resolute.php, "8.5")
        self.assertTrue(resolute.qualifies("apt", "3.2.0"))
        self.assertTrue(resolute.qualifies("systemd", "259.5-0ubuntu3.4"))
        for package, version in (("apt", "3.1.12"), ("apt", "2.8.3"), ("systemd", "2590")):
            with self.subTest(package=package, version=version):
                self.assertFalse(resolute.qualifies(package, version))
        self.assertFalse(resolute.qualifies("systemd", "255.4-1ubuntu8.17"))
        self.assertEqual(releases.named(), "Ubuntu 26.04")

    def test_only_ubuntu_releases_it_names_are_supported(self) -> None:
        self.assertIs(releases.of(OsRelease("ubuntu", "26.04", "")), releases.RESOLUTE)
        for os in (
            OsRelease("ubuntu", "22.04", ""),
            OsRelease("ubuntu", "24.04", ""),
            OsRelease("ubuntu", "25.10", ""),
            OsRelease("debian", "26.04", ""),
            OsRelease("", "", ""),
        ):
            with self.subTest(os=os):
                self.assertIsNone(releases.of(os))

    def test_the_php_profile_installs_the_release_default_version(self) -> None:
        php = profiles.profile(releases.RESOLUTE, Action.PHP)
        self.assertEqual(php.roots, ("php8.5-fpm", "php8.5-cli"))
        # PHP 8.5 builds OPcache in, so there is no php8.5-opcache package.
        self.assertEqual(
            php.packages,
            (
                "php8.5-fpm",
                "php8.5-cli",
                "php8.5-common",
                "php8.5-readline",
                "php-common",
                "needrestart",
            ),
        )
        self.assertEqual(php.units, ("php8.5-fpm.service",))
        self.assertEqual(php.socket, "/run/php/php8.5-fpm.sock")
        self.assertEqual(php.check.command, "/usr/sbin/php-fpm8.5 -t")
        self.assertEqual(
            php.intent,
            "Install the distribution-default PHP 8.5 FPM and CLI from Ubuntu 26.04 packages.",
        )
        (fpm, _, _) = php.trees
        self.assertTrue(
            fpm.links("/etc/php/8.5/fpm/conf.d/10-pdo.ini", "/etc/php/8.5/mods-available/pdo.ini")
        )
        # Another version's module is not a default link of this release's tree.
        self.assertFalse(
            fpm.links("/etc/php/8.5/fpm/conf.d/10-pdo.ini", "/etc/php/8.3/mods-available/pdo.ini")
        )

    def test_the_hook_baseline_has_packagekit_and_the_virtualization_helper(self) -> None:
        hooks = dict(releases.RESOLUTE.hooks)
        self.assertEqual(len(hooks), 14)
        packagekit = [value for (_, value), owner in hooks.items() if owner == "packagekit"]
        self.assertEqual(len(packagekit), 2)
        for value in packagekit:
            self.assertIn("/usr/bin/test ! -e /run/ostree-booted", value)
        # docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#consequences
        virt = {
            name: value
            for (name, value), owner in hooks.items()
            if owner == "ubuntu-helper-virt-hwe"
        }
        self.assertEqual(
            virt["dpkg::pre-install-pkgs"],
            "test -x /usr/bin/apt_hook_ubuntu_virt && /usr/bin/apt_hook_ubuntu_virt || true",
        )
        self.assertNotIn("dpkg::tools::options::test::version", virt)


class AptOutputTests(SimpleTestCase):
    """APT 3.2's outputs, as recorded on Ubuntu 26.04, parse in the same strict forms."""

    def test_apt_32_index_targets_and_configuration_are_read(self) -> None:
        (target,) = parse_index_targets(
            "Ubuntu\tresolute-security\tresolute\tresolute-security\tyes\tmain\tamd64\t"
            "http://security.ubuntu.com/ubuntu\n"
        )
        self.assertEqual(
            (target.suite, target.codename, target.trusted), ("resolute-security", "resolute", True)
        )
        entries = parse_apt_config(
            'Acquire::AllowWeakRepositories "0";\n'
            'DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";\n'
        )
        self.assertEqual(entries[1].name, "dpkg::pre-install-pkgs")

    def test_an_unreadable_index_target_names_its_field_and_repository(self) -> None:
        with self.assertRaises(Unreadable) as raised:
            parse_index_targets(
                "Example, Inc.\tstable\tstable\tstable\tyes\tmain\tamd64\t"
                "https://user:secret@repo.example/apt\n"
            )
        message = str(raised.exception)
        self.assertIn("the origin of an index from https://repo.example/apt", message)
        self.assertNotIn("secret", message)
        with self.assertRaises(Unreadable) as raised:
            parse_index_targets("Ubuntu\tresolute\tresolute\n")
        self.assertIn("3 fields instead of 8", str(raised.exception))

    def test_an_unreadable_configuration_line_is_named_without_its_value(self) -> None:
        with self.assertRaises(Unreadable) as raised:
            parse_apt_config('APT "";\nAcquire::http::Proxy "http://u:hunter2@proxy:3128\n')
        self.assertIn("at line 2", str(raised.exception))
        self.assertNotIn("hunter2", str(raised.exception))


class ReleaseNameTests(SimpleTestCase):
    def test_a_release_is_named_by_packages_paths_and_origins(self) -> None:
        for text, release in (
            ("php8.5-fpm", "8.5"),
            ("/run/php/php8.5-fpm.sock", "8.5"),
            ("PHP 8.5.4", "8.5"),
            ("Ubuntu:26.04/resolute", "26.04"),
        ):
            with self.subTest(text=text):
                self.assertTrue(names_release(text, release))

    def test_digits_of_a_timestamp_or_longer_version_name_no_release(self) -> None:
        for text, release in (
            ("2026-09-29 12:37:58.512744+00:00", "8.5"),
            ("2026-09-29 12:37:26.041234+00:00", "26.04"),
            ("nginx 1.28.5-2ubuntu1.11", "8.5"),
            ("PHP 18.5", "8.5"),
        ):
            with self.subTest(text=text):
                self.assertFalse(names_release(text, release))


class ReleasePreparationTests(PreparationTestCase):
    def test_an_ubuntu_2604_server_gets_its_own_nginx_plan(self) -> None:
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(plan.release, "26.04")
        self.assertEqual(
            (plan.os_name, plan.apt_version, plan.systemd_version),
            ("Ubuntu 26.04.1 LTS", "3.2.0", "259.5-0ubuntu3.4"),
        )
        self.assertEqual(
            plan.intent,
            "Install the distribution-default Nginx web server from Ubuntu 26.04 packages.",
        )
        version = PACKAGING.nginx_version
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", version, False)],
        )
        self.assertEqual(
            list(plan.transitions.filter(step="install").values_list("package", flat=True)),
            ["nginx-common", "nginx"],
        )
        for origins in plan.transitions.values_list("origins", flat=True):
            self.assertLessEqual(set(origins.splitlines()), releases.RESOLUTE.origins)
        text = kept_text(plan)
        self.assertIn("from the Ubuntu 26.04 archives", text)
        self.assertIn("With Ubuntu 26.04's default configuration", text)
        self.assertFalse(names_release(text, "24.04"))
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "Ubuntu 26.04.1 LTS")

    def test_the_php_profile_is_php_85_on_ubuntu_2604(self) -> None:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("php8.5-fpm", _PHP_VERSION, False), ("php8.5-cli", _PHP_VERSION, False)],
        )
        self.assertIn("PHP 8.5 FPM and CLI from Ubuntu 26.04", plan.intent)
        # A collection time whose seconds read 58.312744 names no PHP release.
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            collected_at=plan.collected_at.replace(second=58, microsecond=312744)
        )
        text = kept_text(ConfigurationPlan.objects.get(pk=plan.pk))
        self.assertIn("58.312744", text)
        self.assertIn("php-fpm8.5 -t accepts the configuration.", text)
        self.assertIn("The default www pool listens on /run/php/php8.5-fpm.sock.", text)
        self.assertFalse(names_release(text, "8.3"))
        # A PHP 8.3 effect in the same plan is still found.
        plan.effects.filter(pk=plan.effects.all()[0].pk).update(
            text="The default www pool listens on /run/php/php8.3-fpm.sock."
        )
        self.assertTrue(names_release(kept_text(plan), "8.3"))
        self.assertIn(inspection.simulate(["php8.5-fpm", "php8.5-cli"]), self.remote.commands)
        self.assert_read_only()

    def test_an_installed_php_85_is_satisfied_and_another_release_refused(self) -> None:
        self.ubuntu.php = "installed"
        self.assertTrue(self.plan("php").no_changes)
        self.fresh_server()
        self.ubuntu.php = "installed"
        self.ubuntu.php_releases = (("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11", "ii"),)
        plan = self.plan("php")
        self.assertIn(Reason.UNSUPPORTED_VERSION, self.reasons(plan))
        self.assertIn("supports only PHP 8.5", plan.refusals.get().text)

    def test_another_release_archive_is_refused(self) -> None:
        # A source offering Ubuntu 24.04's packages on a 26.04 server.
        self.ubuntu.nginx_origins = "Ubuntu:24.04/noble-updates"
        plan = self.plan("nginx")
        refusals = plan.refusals.filter(reason=Reason.PACKAGE_SOURCE)
        origins = refusals.filter(text__contains="would come from")
        self.assertEqual(origins.count(), 2)
        self.assertIn(
            "would come from Ubuntu:24.04/noble-updates. Bootstrap installs only from the "
            "Ubuntu 26.04 resolute, resolute-updates and resolute-security archives.",
            "".join(origins.values_list("text", flat=True)),
        )
        # Its index is not the release's own archive, which offering the packages refuses too.
        self.assertTrue(
            refusals.filter(
                text__startswith="http://archive.ubuntu.com/ubuntu noble-updates/main, which "
            ).exists()
        )

    def test_another_release_indexes_do_not_count(self) -> None:
        self.ubuntu.suites = _NOBLE_SUITES
        plan = self.plan("nginx")
        self.assertIn(Reason.PACKAGE_METADATA, self.reasons(plan))
        self.assertTrue(plan.refusals.filter(text__contains="resolute-security main").exists())

    def test_an_unqualified_apt_or_systemd_series_refuses_every_plan(self) -> None:
        for tools in (
            "apt\t3.1.12\ndpkg\t1.23.7ubuntu1\nsystemd\t259.5-0ubuntu3.4\n",
            "apt\t3.2.0\ndpkg\t1.23.7ubuntu1\nsystemd\t260.1-0ubuntu1\n",
        ):
            with self.subTest(tools=tools):
                self.fresh_server()
                self.ubuntu.extra = {inspection.TOOL_VERSIONS: CommandResult(0, tools)}
                plan = self.plan("metadata_refresh")
                self.assertEqual(self.reasons(plan), [Reason.UNSUPPORTED_PLATFORM])
                self.assertIn("On Ubuntu 26.04, bootstrap is qualified with", kept_text(plan))

    def test_a_refresh_plan_names_the_release_suites(self) -> None:
        plan = self.plan("metadata_refresh")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertIn(
            "The resolute, resolute-updates and resolute-security indexes are authenticated "
            "Ubuntu indexes.",
            plan.postconditions.values_list("text", flat=True),
        )


class ProviderCustomizationTests(PreparationTestCase):
    """A hosting provider's 26.04 server: a signed third-party source whose Release file has
    no Origin, and ubuntu-helper-virt-hwe's hook (part of every fake 26.04 server)."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.ubuntu.third_party = True

    def test_a_third_party_source_without_an_origin_is_listed_not_refused(self) -> None:
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        disclosed = plan.effects.get(kind=Effect.THIRD_PARTY_SOURCES).text
        self.assertIn("https://repository.example/ubuntu resolute (main)", disclosed)
        self.assertIn("None of them offers any package of this plan", disclosed)
        hooks = plan.evidence.get(kind=PlanEvidence.Kind.APT_HOOKS).summary
        self.assertIn("ubuntu-helper-virt-hwe", hooks)

    def test_a_refresh_discloses_every_source_it_updates(self) -> None:
        plan = self.plan("metadata_refresh")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        disclosed = plan.effects.get(kind=Effect.THIRD_PARTY_SOURCES).text
        self.assertIn("https://repository.example/ubuntu resolute (main)", disclosed)
        self.assertIn("or the refresh fails", disclosed)
        self.assertNotIn("archive.ubuntu.com", disclosed)

    def test_a_third_party_source_offering_a_closure_package_refuses_the_plan(self) -> None:
        # A lower version than Ubuntu's, which APT would not choose, still refuses.
        self.ubuntu.third_party_offers = (("nginx-common", "0.1-provider"),)
        plan = self.plan("nginx")
        self.assertEqual(self.reasons(plan), [Reason.PACKAGE_SOURCE])
        self.assertIn(
            "https://repository.example/ubuntu resolute/main, which Barectl does not identify "
            "as Ubuntu 26.04's own archive, offers nginx-common 0.1-provider",
            plan.refusals.get().text,
        )
        # A package outside the plan's closure does not count.
        self.fresh_server()
        self.ubuntu.third_party = True
        self.ubuntu.third_party_offers = (("provider-agent", "1.0"),)
        self.assertTrue(self.plan("nginx").eligible)

    def test_backports_may_offer_packages_but_never_supplies_them(self) -> None:
        self.ubuntu.backports_offers = (("nginx", "1.30.0-1~bpo26.04.1"),)
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertNotIn("backports", plan.effects.get(kind=Effect.THIRD_PARTY_SOURCES).text)
        self.fresh_server()
        self.ubuntu.nginx_origins = "Ubuntu:26.04/resolute-backports"
        plan = self.plan("nginx")
        self.assertIn(Reason.PACKAGE_SOURCE, self.reasons(plan))
        self.assertTrue(
            plan.refusals.filter(text__contains="from Ubuntu:26.04/resolute-backports").exists()
        )

    def test_an_unauthenticated_third_party_index_refuses_package_plans(self) -> None:
        self.ubuntu.third_party_trusted = False
        plan = self.plan("php")
        self.assertEqual(self.reasons(plan), [Reason.PACKAGE_SOURCE])
        self.assertIn(
            "unauthenticated package indexes from https://repository.example/ubuntu resolute",
            plan.refusals.get().text,
        )

    def test_the_reviewed_versions_must_be_offered_by_the_release_archive(self) -> None:
        prefix = inspection.offers([])
        self.remote.answers.insert(
            0, lambda command: CommandResult(0, "") if command.startswith(prefix) else None
        )
        plan = self.plan("nginx")
        self.assertIn(Reason.SIMULATION, self.reasons(plan))
        self.assertTrue(plan.refusals.filter(text__startswith="APT does not list nginx ").exists())

    def test_absent_release_fields_are_read_as_empty_and_nothing_else(self) -> None:
        (target,) = parse_index_targets(
            "$(ORIGIN)\tresolute\tresolute\tresolute\tyes\tmain\tamd64\t"
            "https://repository.monarx.com/repository/ubuntu-resolute\n"
        )
        self.assertEqual(
            (target.origin, target.suite, target.codename), ("", "resolute", "resolute")
        )
        self.assertFalse(releases.RESOLUTE.owns(target))
        for line in (
            # Another field's placeholder, or a placeholder APT never leaves in a field.
            "$(SUITE)\tresolute\tresolute\tresolute\tyes\tmain\tamd64\thttps://r.example\n",
            "Ubuntu\tresolute\tresolute\tresolute\tyes\t$(COMPONENT)\tamd64\thttps://r.example\n",
            "Ubuntu\tresolute\tresolute\t$(RELEASE)\tyes\tmain\tamd64\thttps://r.example\n",
        ):
            with self.subTest(line=line), self.assertRaises(Unreadable):
                parse_index_targets(line)

    def test_a_changed_virtualization_hook_is_refused(self) -> None:
        self.ubuntu.hooks = [
            (key, value.replace("|| true", "") if "apt_hook_ubuntu_virt &&" in value else value)
            for key, value in baseline_hooks(releases.RESOLUTE)
        ]
        plan = self.plan("nginx")
        self.assertEqual(self.reasons(plan), [Reason.APT_HOOK])
        self.assertIn(
            "to a command Barectl has not qualified on Ubuntu 26.04.", plan.refusals.get().text
        )


class UnsupportedReleaseTests(PreparationTestCase):
    def test_an_unsupported_release_is_refused_after_reading_only_the_platform(self) -> None:
        for version, name in (("22.04", "22.04.5 LTS"), ("24.04", "24.04.3 LTS")):
            self.ubuntu.extra = {
                inspection.OS_RELEASE: CommandResult(
                    0, f'PRETTY_NAME="Ubuntu {name}"\nVERSION_ID="{version}"\nID=ubuntu\n'
                )
            }
            for action in ("nginx", "php", "metadata_refresh", "clear_results"):
                with self.subTest(version=version, action=action):
                    self.remote.commands.clear()
                    plan = self.plan(action)
                    self.assertEqual(self.reasons(plan), [Reason.UNSUPPORTED_PLATFORM])
                    self.assertEqual(plan.release, "")
                    self.assertIn(
                        f"The server runs Ubuntu {name}. Bootstrap supports Ubuntu 26.04 only.",
                        plan.refusals.get().text,
                    )
                    self.assertNotIn(inspection.APT_CONFIG, self.remote.commands)
                    self.assertFalse([c for c in self.remote.commands if "apt-get" in c])


class ReleaseApplyTests(ApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd.on_submit = self.php_installed

    def php_installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.ubuntu.php = "installed"
            self.ubuntu.php_active = "active"
            self.ubuntu.php_enabled = "enabled"
            self.ubuntu.answer(self.remote)

    def test_a_php_85_run_installs_and_verifies_the_release_profile(self) -> None:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        run = self.apply(plan)
        self.assertEqual(run.status, ApplyRun.Status.SUCCEEDED, run.failure)
        self.assertEqual((run.release, run.verification), ("26.04", Verification.PASSED))
        (submission,) = self.systemd.submissions
        payload = shlex.split(submission)[-1]
        install = re.search(r" install (\S+ \S+) 2>&1", payload)
        if install is None:
            self.fail("The payload runs no installation.")
        self.assertEqual(install[1], f"php8.5-fpm={_PHP_VERSION} php8.5-cli={_PHP_VERSION}")
        self.assertIn("'U php-common 2:99ubuntu1 all php-common_2%3a99ubuntu1_all.deb'", payload)
        self.assertIn(PACKAGING.php.revalidation, payload)
        self.assertTrue(payload.endswith("/usr/sbin/php-fpm8.5 -t || exit 24; exit 0"))
        self.assertIn("php8.5 -v", self.remote.commands)
        self.assertIn(inspection.socket_listeners("/run/php/php8.5-fpm.sock"), self.remote.commands)

    def test_a_refresh_is_verified_against_the_release_suites(self) -> None:
        run = self.apply()
        self.assertEqual(run.status, ApplyRun.Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        # After the refresh, the server has only another release's indexes.
        self.fresh_server()
        self.systemd.submissions.clear()
        self.systemd.answer(self.remote)
        plan = self.refresh_plan()

        def indexes_of_another_release() -> None:
            self.ubuntu.suites = _NOBLE_SUITES
            self.ubuntu.answer(self.remote)

        self.systemd.on_submit = indexes_of_another_release
        run = self.apply(plan)
        self.assertEqual(run.verification, Verification.FAILED)
