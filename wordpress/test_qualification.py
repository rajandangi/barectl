"""The supported combinations (docs/v0.4-qualification.md#supported-combinations)."""

from unittest import mock

from django.test import SimpleTestCase

from bootstrap import releases
from bootstrap.models import PlanRefusal
from sites.convention import Application, Stage

from . import inspection, qualification
from .presentation import supported_combinations

REAL = qualification.COMBINATIONS
Reason = PlanRefusal.Reason


class GateTests(SimpleTestCase):
    def test_only_the_releases_own_ubuntu_branch_on_a_qualified_architecture_passes(self) -> None:
        for version, php, supply, architecture, expected in (
            ("24.04", "8.3", "ubuntu", "arm64", True),
            ("26.04", "8.5", "ubuntu", "arm64", True),
            ("24.04", "8.3", "ubuntu", "amd64", False),
            ("26.04", "8.5", "ubuntu", "amd64", False),
            ("24.04", "8.4", "ubuntu", "arm64", False),
            ("26.04", "8.3", "ubuntu", "arm64", False),
            ("24.04", "8.3", "sury", "arm64", False),
            ("24.04", "8.3", "ubuntu", "riscv64", False),
            ("22.04", "8.1", "ubuntu", "arm64", False),
        ):
            with self.subTest(version=version, php=php, supply=supply, architecture=architecture):
                self.assertIs(qualification.qualified(version, architecture, php, supply), expected)

    def test_an_architecture_is_enabled_only_by_listing_it_as_qualified(self) -> None:
        with mock.patch.object(
            qualification,
            "COMBINATIONS",
            tuple(
                item.__class__(item.release, item.architecture, True, item.evidence)
                for item in REAL
            ),
        ):
            self.assertTrue(qualification.qualified("24.04", "amd64", "8.3", "ubuntu"))
        self.assertFalse(qualification.qualified("24.04", "amd64", "8.3", "ubuntu"))

    def test_a_refusal_names_why_in_the_operators_words(self) -> None:
        disabled = qualification.reason("24.04", "amd64", "8.3", "ubuntu")
        self.assertIn("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, amd64 is not qualified", disabled)
        self.assertIn("stays disabled", disabled)
        other = qualification.reason("24.04", "arm64", "8.4", "sury")
        self.assertIn("PHP 8.4 from sury packages", other)
        self.assertIn("does not change the site's PHP selection", other)

    def test_the_machine_name_maps_to_the_package_architecture(self) -> None:
        self.assertEqual(qualification.architecture_of("aarch64"), "arm64")
        self.assertEqual(qualification.architecture_of("x86_64"), "amd64")
        self.assertEqual(qualification.architecture_of("riscv64"), "")


class InspectionGateTests(SimpleTestCase):
    def draft(self, version: str, php: str) -> inspection.InspectionDraft:
        result = inspection.InspectionDraft(
            "shop", "0" * 32, "inspect", None, releases.RELEASES[version]
        )
        result.php_version, result.php_supply = php, "ubuntu"
        return result

    def test_inspection_refuses_a_disabled_architecture_before_any_application_runs(self) -> None:
        for version, php in (("24.04", "8.3"), ("26.04", "8.5")):
            with self.subTest(version=version):
                result = self.draft(version, php)
                inspection._site(result, "amd64", Application.WORDPRESS, Stage.REDIRECT)
                self.assertEqual(
                    [reason for reason, _ in result.refusals], [Reason.UNSUPPORTED_VERSION]
                )
                self.assertIn("amd64 is not qualified", result.refusals[0][1])
                clean = self.draft(version, php)
                inspection._site(clean, "arm64", Application.WORDPRESS, Stage.REDIRECT)
                self.assertEqual(clean.refusals, [])


class MatrixTests(SimpleTestCase):
    def test_every_combination_shows_with_its_status_and_the_servers_own_is_marked(self) -> None:
        matrix = supported_combinations("26.04", "aarch64")
        self.assertEqual(
            [(item.label, item.qualified, item.here) for item in matrix.combinations],
            [
                ("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, arm64", True, False),
                ("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, amd64", False, False),
                ("Ubuntu 26.04, PHP 8.5, MariaDB 11.8, arm64", True, True),
                ("Ubuntu 26.04, PHP 8.5, MariaDB 11.8, amd64", False, False),
            ],
        )
        self.assertEqual(
            matrix.verdict, "This server is Ubuntu 26.04, PHP 8.5, MariaDB 11.8, arm64: qualified."
        )

    def test_a_disabled_architecture_and_an_unknown_server_are_stated_not_omitted(self) -> None:
        self.assertIn(
            "not qualified, so installation stays disabled",
            supported_combinations("24.04", "x86_64").verdict,
        )
        self.assertIn("not in the matrix", supported_combinations("22.04", "x86_64").verdict)
        self.assertIn("did not identify", supported_combinations("", "").verdict)
