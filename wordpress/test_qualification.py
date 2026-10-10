"""The supported combinations (docs/v0.4-qualification.md#supported-combinations)."""

from django.test import SimpleTestCase

from bootstrap import releases
from bootstrap.models import PlanRefusal
from sites.convention import Application, Stage

from . import inspection, qualification, qualification_testing
from .presentation import supported_combinations

Reason = PlanRefusal.Reason


class GateTests(SimpleTestCase):
    def test_only_recorded_release_branch_supply_and_architecture_pass(self) -> None:
        for version, php, supply, architecture, expected in (
            ("24.04", "8.3", "ubuntu", "arm64", True),
            ("26.04", "8.5", "ubuntu", "arm64", True),
            ("24.04", "8.3", "ubuntu", "amd64", False),
            ("26.04", "8.5", "ubuntu", "amd64", False),
            ("24.04", "8.4", "ubuntu", "arm64", False),
            ("26.04", "8.3", "ubuntu", "arm64", False),
            ("24.04", "8.3", "sury", "arm64", True),
            ("24.04", "8.4", "sury", "arm64", True),
            ("24.04", "8.5", "sury", "arm64", True),
            ("26.04", "8.3", "sury", "arm64", True),
            ("26.04", "8.4", "sury", "arm64", True),
            ("26.04", "8.5", "sury", "arm64", True),
            ("24.04", "8.3", "sury", "amd64", False),
            ("26.04", "8.5", "sury", "amd64", False),
            ("24.04", "8.2", "sury", "arm64", False),
            ("24.04", "8.3", "other", "arm64", False),
            ("24.04", "8.3", "ubuntu", "riscv64", False),
            ("22.04", "8.1", "ubuntu", "arm64", False),
        ):
            with self.subTest(version=version, php=php, supply=supply, architecture=architecture):
                self.assertIs(qualification.qualified(version, architecture, php, supply), expected)

    def test_native_candidates_can_collect_evidence_without_enabling_production(self) -> None:
        for version, php in (("24.04", "8.3"), ("26.04", "8.5")):
            with self.subTest(version=version):
                self.assertFalse(qualification.qualified(version, "amd64", php, "ubuntu"))
                with qualification_testing.native_candidates_qualified():
                    self.assertTrue(qualification.qualified(version, "amd64", php, "ubuntu"))
                    for architecture, branch, supply in (
                        ("riscv64", php, "ubuntu"),
                        ("amd64", "8.4", "ubuntu"),
                        ("amd64", php, "sury"),
                    ):
                        self.assertFalse(
                            qualification.qualified(version, architecture, branch, supply)
                        )
                    self.assertFalse(qualification.qualified("22.04", "amd64", "8.1", "ubuntu"))
                self.assertFalse(qualification.qualified(version, "amd64", php, "ubuntu"))

    def test_source_candidate_admission_is_exact_and_restores_the_gate(self) -> None:
        recorded = qualification.SOURCE_COMBINATIONS
        with qualification_testing.source_candidate_qualified("24.04", "amd64", "8.4"):
            self.assertTrue(qualification.qualified("24.04", "amd64", "8.4", "sury"))
            for version, architecture, branch, supply in (
                ("26.04", "amd64", "8.4", "sury"),
                ("24.04", "amd64", "8.3", "sury"),
                ("24.04", "riscv64", "8.4", "sury"),
                ("24.04", "amd64", "8.4", "other"),
            ):
                self.assertFalse(qualification.qualified(version, architecture, branch, supply))
        self.assertEqual(qualification.SOURCE_COMBINATIONS, recorded)
        self.assertFalse(qualification.qualified("24.04", "amd64", "8.4", "sury"))
        with qualification_testing.source_candidate_qualified("24.04", "arm64", "8.4"):
            self.assertEqual(qualification.SOURCE_COMBINATIONS, recorded)
        for version, architecture, branch in (
            ("22.04", "arm64", "8.4"),
            ("24.04", "riscv64", "8.4"),
            ("24.04", "arm64", "8.2"),
        ):
            with self.assertRaises(ValueError):
                qualification_testing.source_candidate_qualified(version, architecture, branch)

    def test_a_refusal_names_why_in_the_operators_words(self) -> None:
        disabled = qualification.reason("24.04", "amd64", "8.3", "ubuntu")
        self.assertIn("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, amd64 is not qualified", disabled)
        self.assertIn("stays disabled", disabled)
        other = qualification.reason("24.04", "amd64", "8.4", "sury")
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
    def test_each_admitted_source_selection_is_named_without_claiming_a_server_default(
        self,
    ) -> None:
        with qualification_testing.source_candidate_qualified("24.04", "amd64", "8.4"):
            matrix = supported_combinations("24.04", "x86_64")
        self.assertEqual(
            matrix.combinations[-1].label,
            "Ubuntu 24.04, PHP 8.4 from sury packages, MariaDB 10.11, amd64",
        )
        self.assertTrue(matrix.combinations[-1].qualified)
        self.assertTrue(matrix.combinations[-1].here)
        self.assertIn("each site keeps its own branch and package supply", matrix.verdict)

    def test_every_combination_shows_with_its_status_and_the_servers_own_is_marked(self) -> None:
        matrix = supported_combinations("26.04", "aarch64")
        self.assertEqual(
            [(item.label, item.qualified, item.here) for item in matrix.combinations],
            [
                ("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, arm64", True, False),
                ("Ubuntu 24.04, PHP 8.3, MariaDB 10.11, amd64", False, False),
                ("Ubuntu 26.04, PHP 8.5, MariaDB 11.8, arm64", True, True),
                ("Ubuntu 26.04, PHP 8.5, MariaDB 11.8, amd64", False, False),
                ("Ubuntu 24.04, PHP 8.3 from sury packages, MariaDB 10.11, arm64", True, False),
                ("Ubuntu 24.04, PHP 8.4 from sury packages, MariaDB 10.11, arm64", True, False),
                ("Ubuntu 24.04, PHP 8.5 from sury packages, MariaDB 10.11, arm64", True, False),
                ("Ubuntu 26.04, PHP 8.3 from sury packages, MariaDB 11.8, arm64", True, True),
                ("Ubuntu 26.04, PHP 8.4 from sury packages, MariaDB 11.8, arm64", True, True),
                ("Ubuntu 26.04, PHP 8.5 from sury packages, MariaDB 11.8, arm64", True, True),
            ],
        )
        self.assertEqual(
            matrix.verdict,
            "This server is Ubuntu 26.04, arm64. Its qualified PHP selections "
            "are listed below; each site keeps its own branch and package supply.",
        )

    def test_a_disabled_architecture_and_an_unknown_server_are_stated_not_omitted(self) -> None:
        self.assertIn(
            "not qualified, so installation stays disabled",
            supported_combinations("24.04", "x86_64").verdict,
        )
        self.assertIn("not in the matrix", supported_combinations("22.04", "x86_64").verdict)
        self.assertIn("did not identify", supported_combinations("", "").verdict)
