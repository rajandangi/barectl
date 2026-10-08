"""WP-CLI tool setup: its admission, payload and outcomes (docs/wordpress.md).

``wordpress/test_setup_remote.py`` establishes the native behaviour on both releases.
"""

import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native
from bootstrap.evidence import OsRelease, Platform
from bootstrap.models import Action, Execution, PlanEffect, PlanRefusal, Privilege
from bootstrap.native import UnitEvidence
from bootstrap.releases import NOBLE
from bootstrap.review import Draft

from . import setup, setup_apply, setup_native
from .fakes import WpcliServer
from .setup import WpcliState

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
SHELL = shutil.which("dash") or shutil.which("sh") or "sh"

State = WpcliState


def syntax(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "script"
        script.write_text(text)
        return subprocess.run(  # noqa: S603 - a syntax check of the tests' own scripts
            [SHELL, "-n", str(script)], capture_output=True, text=True, check=False
        )


def state(**changes: object) -> WpcliState:
    base = WpcliState(
        paths={
            "/usr": ("directory", "root", "root", "755", "12"),
            "/usr/local": ("directory", "root", "root", "755", "10"),
            "/usr/local/lib": ("directory", "root", "root", "755", "6"),
        },
        absent={setup_native.PHAR},
        tools={"gpg": True, "curl": True},
        version="gpg (GnuPG) 2.4.4",
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def installed_state() -> WpcliState:
    satisfied = state()
    satisfied.paths[setup_native.DIRECTORY] = ("directory", "root", "root", "755", "2")
    satisfied.absent.clear()
    satisfied.paths[setup_native.PHAR] = ("regular file", "root", "root", "644", "1")
    satisfied.sha[setup_native.PHAR] = setup_native.SHA256
    satisfied.entries = [("f", "644", "0", "0", setup_native.PHAR)]
    return satisfied


def draft() -> setup.SetupDraft:
    platform = Platform(
        boot_id=BOOT,
        uptime_centiseconds=10**9,
        os=OsRelease("Ubuntu", "24.04", "Ubuntu 24.04 LTS"),
        systemd=True,
        architecture="amd64",
        tools={},
        privilege=Privilege.SUDO,
        listener_privilege=False,
    )
    base = Draft(Action.WPCLI, setup.INTENT, platform, NOBLE)
    return setup.SetupDraft(**vars(base))


class ParseTests(SimpleTestCase):
    def test_the_fixed_read_is_parsed_by_kind(self) -> None:
        server = WpcliServer(phar="installed", directory="ok")
        parsed = setup.parse_state(server.state())
        self.assertEqual(parsed, installed_state())

    def test_unexpected_output_refuses(self) -> None:
        with self.assertRaises(setup.Unreadable):
            setup.parse_state("unexpected output\n")


class AdmissionTests(SimpleTestCase):
    def prepared(self, observed: WpcliState) -> setup.SetupDraft:
        reviewed = draft()
        setup.admit(reviewed, observed)
        return reviewed

    def test_an_absent_tool_on_a_satisfied_server_is_eligible(self) -> None:
        reviewed = self.prepared(state())
        self.assertEqual(reviewed.refusals, [])
        self.assertFalse(reviewed.installed)
        self.assertTrue(reviewed.creates_directory)
        kinds = [kind for kind, _ in reviewed.effects]
        for kind in (Effect.TOOL_DOWNLOAD, Effect.TOOL_INSTALL, Effect.NO_ROLLBACK):
            self.assertIn(kind, kinds)
        self.assertIsNotNone(reviewed.payload_bytes)
        self.assertLess(reviewed.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD)

    def test_an_existing_directory_without_foreign_entries_admits(self) -> None:
        observed = state()
        observed.paths[setup_native.DIRECTORY] = ("directory", "root", "root", "755", "2")
        reviewed = self.prepared(observed)
        self.assertEqual(reviewed.refusals, [])
        self.assertFalse(reviewed.creates_directory)

    def test_the_exact_installed_artifact_requires_no_changes(self) -> None:
        reviewed = self.prepared(installed_state())
        self.assertEqual(reviewed.refusals, [])
        self.assertTrue(reviewed.installed)
        self.assertTrue(reviewed.no_changes)

    def test_a_foreign_artifact_is_never_overwritten(self) -> None:
        wrong_mode = ("regular file", "root", "root", "755", "1")
        for changes in (
            {"sha": {setup_native.PHAR: "0" * 64}},
            {"paths": {**state().paths, setup_native.PHAR: wrong_mode}},
        ):
            with self.subTest(changes=changes):
                observed = installed_state()
                observed = replace(observed, **changes)
                if "paths" in changes:
                    observed.sha[setup_native.PHAR] = setup_native.SHA256
                reviewed = self.prepared(observed)
                self.assertFalse(reviewed.eligible)
                self.assertEqual(reviewed.refusals[0][0], Reason.COLLISION)
                self.assertIn("does not overwrite foreign tools", reviewed.refusals[0][1])

    def test_a_foreign_directory_or_entries_refuse(self) -> None:
        foreign_directory = state()
        foreign_directory.paths[setup_native.DIRECTORY] = ("directory", "root", "root", "777", "2")
        with_entries = state()
        with_entries.paths[setup_native.DIRECTORY] = ("directory", "root", "root", "755", "2")
        with_entries.entries = [("f", "755", "0", "0", f"{setup_native.DIRECTORY}/wp")]
        for observed in (foreign_directory, with_entries):
            with self.subTest(entries=observed.entries):
                reviewed = self.prepared(observed)
                self.assertFalse(reviewed.eligible)
                self.assertEqual(reviewed.refusals[0][0], Reason.UNSUPPORTED_LAYOUT)

    def test_missing_native_tools_refuse(self) -> None:
        observed = state()
        observed.tools = {"gpg": True, "curl": False}
        reviewed = self.prepared(observed)
        self.assertFalse(reviewed.eligible)
        self.assertEqual(reviewed.refusals[0][0], Reason.PREREQUISITE)
        self.assertIn("/usr/bin/curl", reviewed.refusals[0][1])

    def test_unsafe_ancestry_refuses(self) -> None:
        observed = state()
        observed.paths["/usr/local"] = ("directory", "root", "root", "777", "10")
        reviewed = self.prepared(observed)
        self.assertFalse(reviewed.eligible)
        self.assertEqual(reviewed.refusals[0][0], Reason.UNSUPPORTED_LAYOUT)
        self.assertIn("/usr/local", reviewed.refusals[0][1])


class PayloadTests(SimpleTestCase):
    def payload(self) -> str:
        return setup_native.setup_payload(UNIT, BOOT, 10**12, digest="c" * 64)

    def test_the_steps_are_named_and_valid_shell(self) -> None:
        steps = setup_native.setup_steps(UNIT, BOOT, 10**12, digest="c" * 64)
        self.assertEqual(
            [step.name for step in steps],
            [
                "admission",
                "helpers",
                "revalidation",
                "tools",
                "keyring",
                "download",
                "verify",
                "install",
                "check",
            ],
        )
        result = syntax("; ".join(step.text for step in steps))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_payload_pins_the_artifacts_and_the_signing_identity(self) -> None:
        payload = self.payload()
        for pinned in (
            setup_native.PHAR_URL,
            setup_native.SIGNATURE_URL,
            setup_native.KEY_URL,
            setup_native.FINGERPRINT,
            setup_native.SHA256,
        ):
            self.assertIn(pinned, payload)
        self.assertIn("gpg --batch --yes --import", payload)
        # The artifact is never executed anywhere in the payload.
        self.assertNotIn("php", payload.replace("wordpress", ""))

    def test_the_signature_is_verified_before_publication(self) -> None:
        payload = self.payload()
        self.assertLess(payload.index("--verify"), payload.index("ln -T"))

    def test_an_invalid_digest_refuses_the_payload(self) -> None:
        with self.assertRaises(ValueError):
            setup_native.setup_steps(UNIT, BOOT, 10**12, digest="not a digest")


class OutcomeTests(SimpleTestCase):
    def evidence(self, status: int) -> UnitEvidence:
        return UnitEvidence(
            unit=UNIT,
            boot_id=BOOT,
            found=True,
            active_state="failed",
            sub_state="dead",
            result="exit-code",
            exec_main_code=bootstrap_native.CLD_EXITED,
            exec_main_status=status,
            invocation_id="b" * 32,
            populated=False,
        )

    def test_each_refusal_names_its_boundary(self) -> None:
        cases = {
            setup_native.Exit.TOOLS: "/usr/bin/gpg and /usr/bin/curl",
            setup_native.Exit.KEY: "did not authenticate",
            setup_native.Exit.SIGNATURE: "did not authenticate",
            setup_native.Exit.DOWNLOAD: "could not be downloaded",
        }
        for status, text in cases.items():
            with self.subTest(status=status):
                outcome = setup_apply.execution(self.evidence(status))
                self.assertEqual(outcome, Execution.TOOL_REFUSED)
                self.assertIn(text, setup_apply.failure(None, outcome, status))
                self.assertIn(Execution.TOOL_REFUSED, Execution.refused_before_changes())

    def test_a_publication_boundary_is_partly_applied(self) -> None:
        status = setup_native.Exit.FILE
        outcome = setup_apply.execution(self.evidence(status))
        self.assertEqual(outcome, Execution.PARTIAL)
        self.assertIn("Stopped at exit status", setup_apply.failure(None, outcome, status))

    def test_problems_name_the_reviewed_installation(self) -> None:
        self.assertEqual(setup_apply._problems(installed_state()), [])
        staged = installed_state()
        staged.entries = [
            ("f", "644", "0", "0", setup_native.PHAR),
            ("f", "644", "0", "0", f"{setup_native.DIRECTORY}/.2.12.0.phar.abc"),
        ]
        problems = setup_apply._problems(staged)
        self.assertEqual(len(problems), 2)
        missing = WpcliState()
        self.assertTrue(setup_apply._problems(missing))
