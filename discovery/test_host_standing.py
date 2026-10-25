"""Host-standing judgments replayed from the native transcript set."""

from typing import ClassVar
from unittest import TestCase

from bootstrap.standing import Standing

from . import recorded
from .models import ObservationOutcome
from .observations import collect
from .recorded import ReplayShell


class RecordedHostStandingTests(TestCase):
    cases: ClassVar[dict[str, tuple[Standing, tuple[str, ...]]]] = {
        "pristine-26.04": (Standing.FRESH, ()),
        "foundation-26.04": (Standing.TARGET_STACK, ()),
        "http-site-26.04": (Standing.TARGET_STACK, ()),
        "runtime-defaults-26.04": (Standing.TARGET_STACK, ()),
        "site-node-26.04": (Standing.TARGET_STACK, ()),
        "site-node-interrupted-26.04": (Standing.TARGET_STACK, ()),
        "http-site-unsafe-master-26.04": (Standing.TARGET_STACK, ()),
        "reconstruction-26.04": (Standing.TARGET_STACK, ()),
        "judge-by-shape-26.04": (Standing.TARGET_STACK, ()),
        "race-lock-busy-26.04": (Standing.TARGET_STACK, ()),
        "unknown-runtime-26.04": (Standing.TARGET_STACK, ()),
        "runtime-protection-fault-26.04": (Standing.TARGET_STACK, ()),
        "site-database-26.04": (Standing.TARGET_STACK, ()),
        "laravel-create-26.04": (Standing.TARGET_STACK, ()),
        "automation-wordpress-26.04": (Standing.TARGET_STACK, ()),
        "automation-laravel-26.04": (Standing.TARGET_STACK, ()),
        "fence-wordpress-26.04": (Standing.TARGET_STACK, ()),
        "valkey-installed-26.04": (Standing.TARGET_STACK, ()),
        "object-cache-26.04": (Standing.TARGET_STACK, ()),
        "object-cache-edited-26.04": (Standing.TARGET_STACK, ()),
        "nginx-26.04": (Standing.NOT_MANAGEABLE, ("Nginx packages",)),
        "apache-26.04": (Standing.NOT_MANAGEABLE, ("Apache packages",)),
        "apt-php-26.04": (Standing.NOT_MANAGEABLE, ("APT PHP packages",)),
        "earlier-barectl-26.04": (
            Standing.NOT_MANAGEABLE,
            ("Earlier Barectl layouts are not managed.",),
        ),
        "ubuntu-24.04": (
            Standing.NOT_MANAGEABLE,
            ("Ubuntu 24.04 is outside supported settings.",),
        ),
        "nix-build-user-collision-26.04": (
            Standing.NOT_MANAGEABLE,
            ("The Nix build-user ID range is occupied or could not be checked.",),
        ),
        "partial-nix-26.04": (
            Standing.NOT_MANAGEABLE,
            ("Nix installation incomplete.",),
        ),
        "apt-daily-active-26.04": (
            Standing.NOT_MANAGEABLE,
            ("APT background package activity",),
        ),
    }

    def test_each_native_host_transcript_has_the_expected_judgment(self) -> None:
        self.assertEqual(set(recorded.stored()), set(self.cases))
        for state, (expected_standing, reason_fragments) in self.cases.items():
            with self.subTest(state=state):
                snapshot = collect(ReplayShell(recorded.load(state)))
                standing = snapshot.standing
                self.assertIsNotNone(standing)
                if standing is None:
                    self.fail(f"The transcript of {state} did not produce host standing.")
                self.assertEqual(standing.standing, expected_standing)
                if expected_standing == Standing.TARGET_STACK:
                    # Every recorded foundation has no certificate contact email line.
                    self.assertEqual(snapshot.certificate_email_state, "absent")
                    self.assertEqual(snapshot.certificate_email, "")
                else:
                    self.assertEqual(snapshot.certificate_email_state, "")
                for fragment in reason_fragments:
                    self.assertTrue(
                        any(fragment in reason for reason in standing.reasons),
                        standing.reasons,
                    )

    def test_a_foreign_web_stack_is_judged_without_reading_its_sites(self) -> None:
        shell = ReplayShell(recorded.load("nginx-26.04"))
        snapshot = collect(shell)
        self.assertEqual(snapshot.sites.outcome, ObservationOutcome.ABSENT)
        self.assertEqual(snapshot.sites.value, ())
        self.assertFalse([command for command in shell.commands if "/etc/nginx" in command])
