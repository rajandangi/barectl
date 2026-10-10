from datetime import date
from unittest.mock import patch

from django.test import SimpleTestCase

from . import php_supply, profiles, releases
from .fakes import PreparationTestCase
from .models import Action


class ExplicitPhpProfileTests(SimpleTestCase):
    def test_branch_profile_and_driver_use_selected_runtime(self) -> None:
        release = releases.RESOLUTE
        for version in php_supply.ELIGIBLE_BRANCHES:
            with self.subTest(version=version):
                profile = profiles.php(release, version=version, supply="sury")
                self.assertEqual(profile.roots, (f"php{version}-fpm", f"php{version}-cli"))
                self.assertEqual(profile.check.command, f"/usr/sbin/php-fpm{version} -t")
                self.assertEqual(profile.php_version, version)
                self.assertEqual(profile.php_supply, "sury")
                self.assertEqual(f"php{version}-opcache" in profile.packages, version != "8.5")
                driver = profiles.php_driver(
                    release, Action.PHP_MYSQL, version=version, supply="sury"
                )
                self.assertEqual(driver.pinned, ((f"php{version}-mysql",), f"php{version}-common"))
                self.assertEqual(driver.reload, f"php{version}-fpm.service")
                self.assertEqual(driver.php_version, version)
                self.assertEqual(driver.php_supply, "sury")

    def test_ubuntu_selection_and_missing_historical_selection_keep_release_default(self) -> None:
        release = releases.RESOLUTE
        self.assertEqual(profiles.php(release).php_version, "8.5")
        for other in ("8.3", "8.4"):
            with self.assertRaises(ValueError):
                profiles.php(release, version=other)
        for version in ("8.2", "8.6", "8.4; id"):
            with self.assertRaises(ValueError):
                profiles.php(release, version=version, supply="sury")

    def test_support_cutoff_refuses_new_selection_but_does_not_alter_reporting(self) -> None:
        self.assertTrue(php_supply.supported("8.3", date(2027, 12, 31)))
        self.assertFalse(php_supply.supported("8.3", date(2028, 1, 1)))
        self.assertFalse(php_supply.supported("8.2", date(2026, 10, 7)))

    def test_qualified_combinations_follow_the_recorded_native_evidence(self) -> None:
        release = releases.RESOLUTE
        for architecture in ("amd64", "arm64"):
            for version in php_supply.ELIGIBLE_BRANCHES:
                self.assertTrue(
                    php_supply.qualified(release, architecture, version, "sury"),
                    f"{architecture} {version}",
                )
            self.assertTrue(php_supply.qualified(release, architecture, "8.5", "ubuntu"))
            for other in ("8.3", "8.4"):
                self.assertFalse(php_supply.qualified(release, architecture, other, "ubuntu"))
        self.assertFalse(php_supply.qualified(release, "riscv64", "8.4", "sury"))
        self.assertFalse(php_supply.qualified(release, "amd64", "8.6", "sury"))


class IsolatedArchivePayloadTests(SimpleTestCase):
    def test_source_transaction_acquires_in_fresh_native_cache_before_package_hooks(self) -> None:
        from . import native

        unit = "barectl-apply-" + "1" * 32 + ".service"
        profile = profiles.php(releases.RESOLUTE, version="8.4", supply="sury")
        script = native.package_change(
            unit,
            "e73ef95b-4bb2-4d0f-a169-012baaa365cb",
            1000000,
            apt="a" * 64,
            packages="b" * 64,
            scope=profile.revalidation,
            roots=[("php8.4-fpm", "8.4.26-1")],
            actions=[native.PackageAction(True, "php8.4-fpm", "8.4.26-1", "amd64")],
            services=profile.units,
            enable=False,
            start=False,
            check=profile.check,
            isolated_archives=True,
        )
        argv = native.submission(unit, script, isolated_archives=True)
        self.assertIn("--property=RuntimeDirectory=barectl-apt-" + "1" * 32, argv)
        self.assertIn("Dir::Cache::Archives=/run/barectl-apt-" + "1" * 32 + "/archives/", script)
        self.assertIn("Acquire::ForceHash=SHA256", script)
        self.assertIn("regular empty file", script)
        self.assertLess(
            script.index("mkdir -m 0755"), script.index("DEBIAN_FRONTEND=noninteractive apt-get")
        )
        self.assertNotIn("/var/cache/apt/archives/", script)
        self.assertLess(len(script.encode()), native.MAX_PAYLOAD)


class ExpiredDefaultPreparationTests(PreparationTestCase):
    def test_blank_php_selection_resolves_default_before_security_cutoff_admission(self) -> None:
        with patch("bootstrap.php_supply.supported", return_value=False) as supported:
            plan = self.plan(Action.PHP)
        self.assertFalse(plan.eligible)
        self.assertEqual(supported.call_args.args[0], self.packaging.release.php)
        self.assertTrue(plan.refusals.filter(text__contains="security cutoff").exists())
