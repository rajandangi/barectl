"""Public source admission refuses incomplete trust, freshness and selection evidence."""

from dataclasses import replace
from typing import override
from unittest.mock import patch

from django.test import SimpleTestCase

from discovery.fakes import FakeServer
from discovery.ssh import CommandResult

from . import inspection, php_source, php_supply, php_trust, releases, review
from .evidence import Evidence, IndexTarget, Offer, PackageState, PhpSourceEvidence, Transition
from .fakes import UbuntuServer
from .models import Action, Privilege


class PhpTrustTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.shell = FakeServer()
        resources = "".join(f"{p}|directory|0|0|755|2\n" for p in php_source.DIRECTORIES)
        resources += "".join(
            f"{p}|regular file|0|0|644|1\n{digest}  {p}\n"
            for p, digest in php_source.expected(releases.NOBLE, "arm64").items()
        )
        self.keys = (
            "CLOCK|1791331200\n"
            f"KEY|{php_supply.KEY_FILE}\n"
            "pub:-:4096:1:B188E2B695BD4743:1738666803:1833274803:::-:::scSC::::::23::0:\n"
            f"fpr:::::::::{php_supply.PRIMARY_FINGERPRINT}:\n"
        )
        self.signature = (
            "CLOCK|1791331200\n"
            f"[GNUPG:] VALIDSIG {php_supply.PRIMARY_FINGERPRINT} 2026-10-01 1 0 4 0 1 10 01 "
            f"{php_supply.PRIMARY_FINGERPRINT}\n"
            "Origin: deb.sury.org\nSuite: noble\nCodename: noble\n"
            "Date: Thu, 01 Oct 2026 12:01:15 UTC\nArchitectures: amd64 arm64 armhf\n"
            "Components: main\n"
        )
        self.policy = "".join(
            f"{package}:\n  Candidate: 1.2\n  Version table:\n     1.2 700\n"
            "        -1 https://packages.sury.org/php noble/main arm64 Packages\n"
            for package in php_supply.allowed_packages()
        )
        self.shell.results.update(
            {
                php_source.STATE: CommandResult(0, resources),
                php_source.ENVIRONMENT: CommandResult(0, ""),
                php_source.KEY_STATE: CommandResult(0, self.keys),
                php_trust.index_authentication(releases.NOBLE): CommandResult(0, self.signature),
                php_trust.policies(): CommandResult(0, self.policy),
            }
        )

    def admission(self) -> bool:
        return php_trust.collect(self.shell, releases.NOBLE, "arm64", Privilege.ROOT).admitted

    def test_complete_current_signed_own_source_is_admitted(self) -> None:
        self.assertTrue(self.admission())

    def test_signatures_require_current_approved_primary_and_unique_verified_fields(self) -> None:
        for evidence in (
            self.signature.replace(php_supply.PRIMARY_FINGERPRINT, "A" * 40),
            self.signature.replace("1791331200", "1791504000"),
            self.signature.replace("Origin: deb.sury.org", "Origin: Ubuntu"),
            self.signature.replace("Suite: noble", "Suite: resolute"),
            self.signature.replace("Architectures: amd64 arm64 armhf", "Architectures: amd64"),
            self.signature + "Date: Wed, 07 Oct 2026 12:00:00 UTC\n",
            self.signature + "[GNUPG:] EXPKEYSIG 123 Publisher\n",
            self.signature + "[GNUPG:] REVKEYSIG 123 Publisher\n",
            self.signature + "UNVERIFIED\n",
        ):
            with self.subTest(evidence=evidence):
                self.shell.results[php_trust.index_authentication(releases.NOBLE)] = CommandResult(
                    0, evidence
                )
                self.assertFalse(self.admission())

    def test_missing_or_interfering_native_selection_refuses(self) -> None:
        for command, output in (
            (php_source.ENVIRONMENT, "/etc/apt/preferences.d/other\n"),
            (php_source.STATE, f"{php_supply.SOURCE_FILE}|absent\n"),
            (php_trust.policies(), self.policy.replace("1.2 700", "1.2 1001")),
            (php_source.KEY_STATE, self.keys.replace("1833274803", "1790000000")),
            (php_source.KEY_STATE, self.keys.replace("pub:-:", "pub:r:")),
            (
                php_source.KEY_STATE,
                self.keys.replace(php_supply.PRIMARY_FINGERPRINT, "A" * 40),
            ),
            (
                php_source.KEY_STATE,
                self.keys + self.keys.replace(php_supply.PRIMARY_FINGERPRINT, "A" * 40),
            ),
            (
                php_source.KEY_STATE,
                self.keys + self.keys.replace(php_supply.KEY_FILE, "/etc/apt/trusted.gpg"),
            ),
        ):
            previous = self.shell.results[command]
            with self.subTest(command=command):
                self.shell.results[command] = CommandResult(0, output)
                self.assertFalse(self.admission())
            self.shell.results[command] = previous

    def test_truncated_authentication_refuses(self) -> None:
        self.shell.results[php_trust.index_authentication(releases.NOBLE)] = CommandResult(
            0, self.signature, truncated=True
        )
        self.assertFalse(self.admission())


class SourceOfferAdmissionTests(SimpleTestCase):
    def evidence(self) -> Evidence:
        shell = FakeServer()
        UbuntuServer().answer(shell)
        evidence = inspection.inspect(shell, Action.PHP)
        apt, packages = evidence.apt, evidence.packages
        if apt is None or packages is None or packages.simulation is None:
            raise AssertionError("The native-shaped baseline package evidence is incomplete.")
        source = php_supply.SOURCE_URL.rstrip("/")
        version = "8.3.35-source1"
        transitions = tuple(
            t._replace(version=version, origins=("noble",)) if t.package.startswith("php") else t
            for t in packages.simulation.transitions
        )
        transitions = (
            *transitions,
            Transition("Inst", "psmisc", "", "23.7-1", "amd64", ("Ubuntu:24.04/noble",)),
            Transition("Conf", "psmisc", "", "23.7-1", "amd64", ("Ubuntu:24.04/noble",)),
        )
        offered = tuple(
            Offer(o.package, version, source, "noble", "main", "amd64")
            if o.package.startswith("php")
            else o
            for o in packages.offers
        )
        offered = (
            *offered,
            Offer("psmisc", "23.7-1", apt.targets[0].site, "noble", "main", "amd64"),
        )
        return replace(
            evidence,
            apt=replace(
                apt,
                targets=(
                    *apt.targets,
                    IndexTarget(
                        "deb.sury.org", "noble", "noble", "noble", True, "main", "amd64", source
                    ),
                ),
            ),
            packages=replace(
                packages,
                states=(*packages.states, PackageState("psmisc", "", "", "un ")),
                simulation=packages.simulation._replace(transitions=transitions),
                offers=offered,
            ),
            php_source=PhpSourceEvidence(True, digest="a" * 64),
        )

    def test_exact_non_php_version_from_two_ubuntu_instances_refuses_source_transaction(
        self,
    ) -> None:
        evidence = self.evidence()
        with patch("bootstrap.php_supply.qualified", return_value=True):
            accepted = review.review(Action.PHP, evidence, version="8.3", supply="sury")
        self.assertTrue(accepted.eligible, accepted.refusals)
        apt, packages = evidence.apt, evidence.packages
        if apt is None or packages is None:
            raise AssertionError("The source-admitted package evidence is incomplete.")
        dependency = next(o for o in packages.offers if not o.package.startswith("php"))
        duplicate = dependency._replace(release="noble-security")
        evidence = replace(
            evidence, packages=replace(packages, offers=(*packages.offers, duplicate))
        )
        with patch("bootstrap.php_supply.qualified", return_value=True):
            refused = review.review(Action.PHP, evidence, version="8.3", supply="sury")
        self.assertFalse(refused.eligible)
        self.assertTrue(any("multiple source instances" in text for _, text in refused.refusals))

    def test_expired_resolved_release_default_refuses_new_blank_selection(self) -> None:
        shell = FakeServer()
        UbuntuServer().answer(shell)
        evidence = inspection.inspect(shell, Action.PHP)
        with patch("bootstrap.php_supply.supported", return_value=False) as supported:
            refused = review.review(Action.PHP, evidence)
        self.assertFalse(refused.eligible)
        self.assertEqual(supported.call_args.args[0], "8.3")
        self.assertTrue(any("security cutoff" in text for _, text in refused.refusals))

    def test_unselected_source_offer_for_a_non_php_dependency_still_refuses(self) -> None:
        evidence = self.evidence()
        packages = evidence.packages
        if packages is None:
            raise AssertionError("The source-admitted package evidence is incomplete.")
        evidence = replace(
            evidence,
            packages=replace(
                packages,
                offers=(
                    *packages.offers,
                    Offer(
                        "psmisc",
                        "0.1-unselected-source",
                        php_supply.SOURCE_URL.rstrip("/"),
                        "noble",
                        "main",
                        "amd64",
                    ),
                ),
            ),
        )
        with patch("bootstrap.php_supply.qualified", return_value=True):
            refused = review.review(Action.PHP, evidence, version="8.3", supply="sury")
        self.assertFalse(refused.eligible)
        self.assertTrue(any("psmisc" in text for _, text in refused.refusals))
