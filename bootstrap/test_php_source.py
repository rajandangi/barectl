from typing import override

from django.test import SimpleTestCase

from discovery.ssh import CommandResult

from . import inspection, php_source, php_supply, php_trust, releases
from .fakes import PreparationTestCase
from .models import Action, PlanRefusal


class PhpSourceConventionTests(SimpleTestCase):
    def test_source_is_own_suite_architecture_and_dedicated_bounded_trust(self) -> None:
        for release in releases.RELEASES.values():
            for architecture in ("amd64", "arm64"):
                content = php_supply.source_content(release, architecture)
                self.assertIn(f"Suites: {release.codename}\n", content)
                self.assertIn(f"Architectures: {architecture}\n", content)
                self.assertIn(
                    f"Signed-By: /etc/apt/keyrings/sury-php.gpg {php_supply.PRIMARY_FINGERPRINT}\n",
                    content,
                )
                self.assertIn("Check-Valid-Until: yes\nValid-Until-Max: 604800\n", content)
        with self.assertRaises(ValueError):
            php_supply.source_content(releases.NOBLE, "armhf")

    def test_pins_allow_exact_php_names_and_block_every_other_source_package(self) -> None:
        preferences = php_supply.preference_content(releases.NOBLE)
        self.assertTrue(
            preferences.startswith(
                "Package: *\nPin: release o=deb.sury.org,n=noble\nPin-Priority: -1\n"
            )
        )
        allow = preferences.split("\n\n")[1].splitlines()[0]
        self.assertNotIn("*", allow)
        self.assertIn("php8.4-mysql", allow)
        self.assertNotIn("php8.2", allow)
        self.assertNotIn("php8.5-opcache", allow)
        self.assertIn("Pin-Priority: 700", preferences)


class SourcePreparationTests(PreparationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.ubuntu.privilege = "root"
        self.state = "\n".join(
            [f"{path}|directory|0|0|755|2" for path in php_source.DIRECTORIES]
            + [f"{path}|absent" for path in php_source.FILES]
        )
        self.remote.answers.insert(0, self.ubuntu.extra.get)
        self.ubuntu.extra.update(
            {
                php_source.STATE: CommandResult(0, self.state),
                php_source.REVALIDATION: CommandResult(0, "a" * 64 + "  -\n"),
                php_source.PHP_STATES: CommandResult(1, ""),
                php_source.TOOLS: CommandResult(0, ""),
                php_source.ENVIRONMENT: CommandResult(0, ""),
                php_source.KEY_STATE: CommandResult(0, "CLOCK|1791340000\n"),
            }
        )

    @override
    def assert_read_only(self) -> None:
        source_reads = {
            php_source.STATE,
            php_source.REVALIDATION,
            php_source.TOOLS,
            php_source.ENVIRONMENT,
            php_source.KEY_STATE,
            php_trust.index_authentication(self.packaging.release),
            php_trust.policies(),
        }
        commands = self.remote.commands
        self.remote.commands = [command for command in commands if command not in source_reads]
        try:
            super().assert_read_only()
        finally:
            self.remote.commands = commands

    def test_source_setup_reviews_exact_missing_resources_without_package_changes(self) -> None:
        plan = self.plan(Action.PHP_SOURCE)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertFalse(plan.no_changes)
        self.assertFalse(plan.transitions.exists())
        self.assertFalse(plan.roots.exists())
        response = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(response, "Publisher package code can run as root")
        self.assertContains(response, "metadata refresh")
        for command in self.remote.commands:
            self.assertNotIn("download-file", command)
            self.assertNotIn(" install ", command)
            self.assertNotIn(" update", command)

    def test_differing_source_is_refused_without_overwrite(self) -> None:
        state = self.state.replace(
            php_supply.SOURCE_FILE + "|absent",
            php_supply.SOURCE_FILE
            + "|regular file|0|0|644|1\n"
            + "b" * 64
            + "  "
            + php_supply.SOURCE_FILE,
        )
        self.ubuntu.extra[php_source.STATE] = CommandResult(0, state)
        plan = self.plan(Action.PHP_SOURCE)
        self.assertFalse(plan.eligible)
        self.assertTrue(plan.refusals.filter(reason=PlanRefusal.Reason.NOT_FOLLOWING).exists())

    def test_existing_php_is_refused_before_supplier_conversion(self) -> None:
        self.ubuntu.extra[php_source.PHP_STATES] = CommandResult(
            0, "php8.3-cli\tamd64\t8.3.6\tii \n"
        )
        plan = self.plan(Action.PHP_SOURCE)
        self.assertFalse(plan.eligible)
        self.assertTrue(
            plan.refusals.filter(reason=PlanRefusal.Reason.INSTALLED_PACKAGE_CHANGE).exists()
        )

    def test_matching_administrator_resources_need_no_apply(self) -> None:
        state = "\n".join([f"{path}|directory|0|0|755|2" for path in php_source.DIRECTORIES])
        for path, digest in php_source.expected(self.packaging.release, "amd64").items():
            state += f"\n{path}|regular file|0|0|644|1\n{digest}  {path}"
        self.ubuntu.extra[php_source.STATE] = CommandResult(0, state)
        plan = self.plan(Action.PHP_SOURCE)
        self.assertTrue(plan.eligible)
        self.assertTrue(plan.no_changes)

    def test_missing_native_key_tools_refuses_instead_of_installing_them(self) -> None:
        self.ubuntu.extra[php_source.TOOLS] = CommandResult(1, "")
        plan = self.plan(Action.PHP_SOURCE)
        self.assertFalse(plan.eligible)
        self.assertTrue(plan.refusals.filter(reason=PlanRefusal.Reason.PREREQUISITE).exists())

    def test_priority_interference_is_refused_before_source_publication(self) -> None:
        self.ubuntu.extra[php_source.ENVIRONMENT] = CommandResult(
            0, "/etc/apt/preferences.d/custom\n"
        )
        plan = self.plan(Action.PHP_SOURCE)
        self.assertFalse(plan.eligible)
        self.assertTrue(plan.refusals.filter(reason=PlanRefusal.Reason.APT_CONFIGURATION).exists())

    def test_ubuntu_non_php_plan_admits_only_the_exact_authenticated_source_options(self) -> None:
        release = self.packaging.release
        self.ubuntu.answer(self.remote)
        state = "".join(f"{p}|directory|0|0|755|2\n" for p in php_source.DIRECTORIES)
        state += "".join(
            f"{p}|regular file|0|0|644|1\n{digest}  {p}\n"
            for p, digest in php_source.expected(release, "amd64").items()
        )
        fingerprint = php_supply.PRIMARY_FINGERPRINT
        self.ubuntu.extra.update(
            {
                php_source.STATE: CommandResult(0, state),
                php_source.KEY_STATE: CommandResult(
                    0,
                    f"CLOCK|1791331200\nKEY|{php_supply.KEY_FILE}\n"
                    f"pub:-:4096:1:4743:1738666803:1833274803:\nfpr:::::::::{fingerprint}:\n",
                ),
                php_trust.index_authentication(release): CommandResult(
                    0,
                    f"CLOCK|1791331200\n[GNUPG:] VALIDSIG {fingerprint} 1 1 0 4 0 1 10 01 "
                    f"{fingerprint}\nOrigin: deb.sury.org\nSuite: {release.codename}\n"
                    f"Codename: {release.codename}\nDate: Thu, 01 Oct 2026 12:01:15 UTC\n"
                    "Architectures: amd64 arm64\nComponents: main\n",
                ),
                php_trust.policies(): CommandResult(
                    0,
                    "php-common:\n  Version table:\n     1.2 700\n"
                    "        -1 https://packages.sury.org/php "
                    f"{release.codename}/main amd64 Packages\n",
                ),
                inspection.APT_FILES: CommandResult(
                    0,
                    self.remote.results[inspection.APT_FILES].stdout
                    + f"{php_source.expected(release, 'amd64')[php_supply.SOURCE_FILE]}  "
                    + php_supply.SOURCE_FILE
                    + "\n",
                ),
                inspection.SOURCE_OVERRIDES: CommandResult(0, php_supply.SOURCE_FILE + "\n"),
            }
        )
        plan = self.plan(Action.NGINX)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(plan.php_supply, "ubuntu")
        self.ubuntu.extra[php_source.KEY_STATE] = CommandResult(1, "")
        refused = self.plan(Action.NGINX)
        self.assertFalse(refused.eligible)
        self.assertTrue(refused.refusals.filter(reason=PlanRefusal.Reason.PACKAGE_SOURCE).exists())
