"""Certbot renewal setup: its files, admission, payload and outcomes (docs/tls.md).

``tls/test_setup_remote.py`` establishes the native behaviour on Ubuntu 26.04.
"""

import ast
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native
from bootstrap.models import Action, Execution, PackageTransition, PlanEffect, PlanRefusal
from bootstrap.native import UnitEvidence
from bootstrap.profiles import profile
from bootstrap.releases import RESOLUTE
from bootstrap.review import Draft, RootDraft, TransitionDraft
from sites.convention import Stage, render_site

from . import renewal, setup, setup_apply, setup_native

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
SHELL = shutil.which("dash") or shutil.which("sh") or "sh"
# The Certbot closure as APT's simulation lists it.
CLOSURE = [
    "python3-cffi-backend",
    "python3-bcrypt",
    "python3-cryptography",
    "python3-openssl",
    "python3-josepy",
    "python3-pytz",
    "python3-certifi",
    "python3-chardet",
    "python3-idna",
    "python3-urllib3",
    "python3-requests",
    "python3-rfc3339",
    "python3-acme",
    "python3-configargparse",
    "python3-configobj",
    "python3-distro",
    "python3-parsedatetime",
    "python3-certbot",
    "certbot",
]


def syntax(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "script"
        script.write_text(text)
        return subprocess.run(  # noqa: S603 - a syntax check of the tests' own scripts
            [SHELL, "-n", str(script)], capture_output=True, text=True, check=False
        )


def pristine(*, installed: bool, **changes: object) -> setup.RenewalState:
    state = setup.RenewalState(
        paths={
            "/usr": ("directory", "root", "root", "755", "12"),
            "/usr/local": ("directory", "root", "root", "755", "10"),
            "/usr/local/sbin": ("directory", "root", "root", "755", "2"),
            "/etc/systemd/system": ("directory", "root", "root", "755", "20"),
        },
        absent={"/root/.config/letsencrypt", renewal.WRAPPER, renewal.DEPLOY_HOOK},
        units={
            "certbot.service": {"Id": "certbot.service", "DropInPaths": ""},
            "certbot.timer": {
                "Id": "certbot.timer",
                "DropInPaths": "",
                "UnitFileState": "disabled",
            },
        },
    )
    if installed:
        state.letsencrypt = [("f", "644", "0", "0", "/etc/letsencrypt/cli.ini")]
        state.cron = ["/etc/cron.d/certbot"]
        state.md5 = {"/etc/cron.d/certbot": "c" * 32}
        state.conffiles = {"/etc/cron.d/certbot": "c" * 32}
        state.version = "certbot 4.0.0"
    return replace(state, **changes)  # type: ignore[arg-type]


def satisfied() -> setup.RenewalState:
    state = pristine(installed=True)
    state.paths["/etc/letsencrypt"] = ("directory", "root", "root", "755", "6")
    state.md5["/etc/letsencrypt/cli.ini"] = "d" * 32
    state.conffiles["/etc/letsencrypt/cli.ini"] = "d" * 32
    for file in renewal.files():
        state.paths[file.path] = ("regular file", "root", "root", file.mode.lstrip("0"), "1")
        state.sha[file.path] = file.sha256
    state.paths[renewal.DROP_IN_DIRECTORY] = ("directory", "root", "root", "755", "2")
    state.absent -= {renewal.WRAPPER, renewal.DEPLOY_HOOK}
    state.systemd = [
        ("d", renewal.DROP_IN_DIRECTORY, ""),
        (
            "l",
            "/etc/systemd/system/timers.target.wants/certbot.timer",
            "/usr/lib/systemd/system/certbot.timer",
        ),
    ]
    state.units["certbot.service"]["DropInPaths"] = renewal.DROP_IN
    state.units["certbot.timer"].update(
        UnitFileState="enabled", ActiveState="active", RandomizedDelayUSec="12h"
    )
    state.syntax = {renewal.WRAPPER, renewal.DEPLOY_HOOK}
    return state


def draft(*, installed: bool) -> setup.SetupDraft:
    certbot = profile(RESOLUTE, Action.CERTBOT)
    base = Draft(Action.CERTBOT, certbot.intent, None, RESOLUTE)
    if installed:
        base.roots = [RootDraft("certbot", "4.0.0-4", installed=True)]
        base.effects = [(Effect.NO_CHANGES, "No changes.")]
    else:
        base.roots = [RootDraft("certbot", "4.0.0-4", installed=False)]
        base.transitions = [
            TransitionDraft(PackageTransition.Step.INSTALL, "certbot", "all", "4.0.0-4", ())
        ]
        base.effects = [(Effect.PACKAGES, "Installs.")]
    return setup.SetupDraft(**vars(base))


def payload(*, install: bool = True) -> list[str]:
    certbot = profile(RESOLUTE, Action.CERTBOT)
    actions = [
        bootstrap_native.PackageAction(unpack, name, "4.0.0-4", "arm64")
        for name in CLOSURE
        for unpack in (True, False)
    ]
    steps = setup_native.setup_steps(
        UNIT,
        BOOT,
        10**12,
        apt="a" * 64,
        packages="b" * 64,
        scope=certbot.revalidation,
        digest="c" * 64,
        roots=[("certbot", "4.0.0-4")] if install else [],
        actions=actions if install else [],
        check=certbot.check,
    )
    return [step.name for step in steps], "; ".join(step.text for step in steps)  # type: ignore[return-value]


class RenewalFileTests(SimpleTestCase):
    def test_the_wrapper_takes_the_lock_with_the_payloads_own_steps(self) -> None:
        wrapper = renewal.wrapper()
        applied = bootstrap_native.lock_steps("UNSAFE", "HELD")
        for line in applied[1:]:
            prefix = line.split("UNSAFE")[0].split("HELD")[0]
            self.assertIn(prefix, wrapper)
        self.assertIn("flock -n 9 || { echo 'barectl-renew: skipped", wrapper)
        order = [
            wrapper.index(text) for text in ("flock -n 9", "barectl-apply-*", "certbot -q renew")
        ]
        self.assertEqual(order, sorted(order))
        self.assertIn(
            "--no-directory-hooks --deploy-hook /usr/local/sbin/barectl-certbot-deploy", wrapper
        )

    def test_the_scripts_are_valid_shell_and_the_verifier_valid_python(self) -> None:
        for text in (renewal.wrapper(), renewal.deploy_hook()):
            result = syntax(text)
            self.assertEqual(result.returncode, 0, result.stderr)
        script = renewal.wrapper().split("python3 -I -c '", 1)[1].split("' $n", 1)[0]
        self.assertNotIn("'", script)
        ast.parse(script)

    def test_the_hook_checks_nginx_before_reloading(self) -> None:
        hook = renewal.deploy_hook()
        self.assertLess(hook.index("nginx -t -q"), hook.index("systemctl reload nginx.service"))
        self.assertNotIn("flock", hook)

    def test_the_drop_in_replaces_the_command_and_bounds_the_run(self) -> None:
        self.assertEqual(
            renewal.drop_in().splitlines()[1:],
            [
                "[Service]",
                "ExecStart=",
                "ExecStart=/usr/bin/sh /usr/local/sbin/barectl-certbot-renew",
                "SuccessExitStatus=75 76",
                "TimeoutStartSec=30min",
                "TimeoutStopSec=60",
                "KillMode=control-group",
            ],
        )


class ConventionDocumentTests(SimpleTestCase):
    def test_the_convention_documents_the_exact_bytes(self) -> None:
        document = (Path(__file__).parent.parent / "docs/site-conventions.md").read_text()
        for file in renewal.files():
            with self.subTest(path=file.path):
                self.assertIn(f"\n{file.content}```", document)
        challenge = render_site("xyzzy", ("names.example",), ipv6=True, stage=Stage.CHALLENGE)
        placeholders = challenge.replace("xyzzy", "<identifier>").replace(
            "names.example", "<names>"
        )
        self.assertIn(placeholders, document)


class AdmissionTests(SimpleTestCase):
    def test_existing_accounts_are_allowed_only_in_a_read_only_guarded_review(self) -> None:
        state = satisfied()
        state.letsencrypt.append(("d", "700", "0", "0", "/etc/letsencrypt/accounts"))
        reviewed = draft(installed=True)
        setup._certbot_state(reviewed, state, installed=True, guarded=True)
        self.assertEqual(reviewed.refusals, [])
        mutating = draft(installed=True)
        setup.admit(mutating, state)
        self.assertFalse(mutating.eligible)

    def test_guarded_review_refuses_modified_cli_or_writable_configuration(self) -> None:
        for change in ("cli", "directory", "missing-checksum"):
            with self.subTest(change=change):
                state = satisfied()
                if change == "cli":
                    state.md5["/etc/letsencrypt/cli.ini"] = "e" * 32
                elif change == "directory":
                    state.paths["/etc/letsencrypt"] = ("directory", "root", "root", "777", "6")
                else:
                    del state.conffiles["/etc/letsencrypt/cli.ini"]
                reviewed = draft(installed=True)
                setup._certbot_state(reviewed, state, installed=True, guarded=True)
                self.assertFalse(reviewed.eligible)

    def test_guarded_review_refuses_unknown_files_and_directory_hooks(self) -> None:
        for path in ("/etc/letsencrypt/custom.ini", "/etc/letsencrypt/renewal-hooks/pre/custom"):
            with self.subTest(path=path):
                state = satisfied()
                state.letsencrypt.append(("f", "644", "0", "0", path))
                reviewed = draft(installed=True)
                setup._certbot_state(reviewed, state, installed=True, guarded=True)
                self.assertFalse(reviewed.eligible)

    def test_a_server_without_certbot_gets_the_whole_setup(self) -> None:
        reviewed = draft(installed=False)
        setup.admit(reviewed, pristine(installed=False))
        self.assertEqual(reviewed.refusals, [])
        self.assertEqual(set(reviewed.publishes), {file.path for file in renewal.files()})
        kinds = [kind for kind, _ in reviewed.effects]
        self.assertIn(Effect.RENEWAL_INTEGRATION, kinds)
        self.assertIn(Effect.COMPATIBLE_CLIENTS, kinds)
        self.assertNotIn(Effect.NO_CHANGES, kinds)

    def test_an_installed_pristine_certbot_gets_the_integration_with_inhibition(self) -> None:
        reviewed = draft(installed=True)
        setup.admit(reviewed, pristine(installed=True))
        self.assertEqual(reviewed.refusals, [])
        self.assertEqual(reviewed.effects[0][0], Effect.SERVICE_INHIBITION)
        self.assertFalse(reviewed.no_changes)

    def test_a_guarded_setup_has_no_changes(self) -> None:
        reviewed = draft(installed=True)
        setup.admit(reviewed, satisfied())
        self.assertEqual(reviewed.refusals, [])
        self.assertTrue(reviewed.no_changes)

    def test_an_interrupted_setup_is_offered_the_rest(self) -> None:
        state = satisfied()
        state.units["certbot.timer"].update(UnitFileState="disabled", ActiveState="inactive")
        state.systemd = [item for item in state.systemd if item[0] == "d"]
        reviewed = draft(installed=True)
        setup.admit(reviewed, state)
        self.assertEqual(reviewed.refusals, [])
        self.assertFalse(reviewed.no_changes)
        self.assertEqual(reviewed.publishes, ())

    def test_state_or_automation_it_cannot_account_for_is_refused(self) -> None:
        cases: dict[str, tuple[setup.RenewalState, Reason]] = {
            "lineage": (
                pristine(
                    installed=True,
                    letsencrypt=[
                        ("f", "644", "0", "0", "/etc/letsencrypt/cli.ini"),
                        ("d", "700", "0", "0", "/etc/letsencrypt/live"),
                    ],
                ),
                Reason.AUTOMATION,
            ),
            "hook": (
                pristine(
                    installed=True,
                    letsencrypt=[
                        ("f", "644", "0", "0", "/etc/letsencrypt/cli.ini"),
                        ("d", "755", "0", "0", "/etc/letsencrypt/renewal-hooks"),
                        ("d", "755", "0", "0", "/etc/letsencrypt/renewal-hooks/deploy"),
                        ("f", "755", "0", "0", "/etc/letsencrypt/renewal-hooks/deploy/x"),
                    ],
                ),
                Reason.AUTOMATION,
            ),
            "snap": (pristine(installed=False, snaps=["certbot"]), Reason.AUTOMATION),
            "timer": (
                pristine(installed=False, unit_files=["acme-renew.timer"]),
                Reason.AUTOMATION,
            ),
            "cron": (pristine(installed=False, cron=["/etc/cron.d/acme"]), Reason.AUTOMATION),
            "changed cron": (
                pristine(installed=True, md5={"/etc/cron.d/certbot": "d" * 32}),
                Reason.AUTOMATION,
            ),
            "runtime mask": (
                pristine(
                    installed=True,
                    systemd=[("l", "/run/systemd/system/certbot.timer", "/dev/null")],
                ),
                Reason.SERVICE_UNIT,
            ),
            "override": (
                pristine(
                    installed=True, systemd=[("d", "/etc/systemd/system/certbot.timer.d", "")]
                ),
                Reason.AUTOMATION,
            ),
            "home": (pristine(installed=True, absent=set()), Reason.AUTOMATION),
            "changed file": (
                pristine(
                    installed=True,
                    paths={
                        **pristine(installed=True).paths,
                        renewal.WRAPPER: ("regular file", "root", "root", "755", "1"),
                    },
                    sha={renewal.WRAPPER: "0" * 64},
                ),
                Reason.UNSUPPORTED_LAYOUT,
            ),
            "writable": (
                pristine(
                    installed=True,
                    paths={
                        **pristine(installed=True).paths,
                        "/usr/local/sbin": ("directory", "root", "staff", "775", "2"),
                    },
                ),
                Reason.UNSUPPORTED_LAYOUT,
            ),
            "version": (
                pristine(installed=True, version="certbot 3.0.0"),
                Reason.UNSUPPORTED_VERSION,
            ),
            "working files": (
                pristine(installed=True, lib=[("f", "644", "0", "0", "/var/lib/letsencrypt/x")]),
                Reason.AUTOMATION,
            ),
        }
        for case, (state, reason) in cases.items():
            with self.subTest(case=case):
                reviewed = draft(installed=not case.startswith(("snap", "timer", "cron")))
                setup.admit(reviewed, state)
                self.assertIn(reason, [item for item, _ in reviewed.refusals], reviewed.refusals)

    def test_site_webroots_are_not_other_tools_files(self) -> None:
        state = pristine(
            installed=False, lib=[("d", "750", "0", "33", "/var/lib/letsencrypt/shop")]
        )
        reviewed = draft(installed=False)
        setup.admit(reviewed, state)
        self.assertEqual(reviewed.refusals, [])

    def test_the_state_is_read_strictly(self) -> None:
        text = (
            "path directory|root|root|755|12|/usr\n"
            "absent /root/.config/letsencrypt\n"
            "unit l /etc/systemd/system/timers.target.wants/certbot.timer "
            "/usr/lib/systemd/system/certbot.timer\n"
            f"sha {'a' * 64} /etc/letsencrypt/cli.ini\n"
            f"md5 {'b' * 32} /etc/cron.d/certbot\n"
            "letsencrypt f 644 0 0 /etc/letsencrypt/cli.ini\n"
            "cron /etc/cron.d/certbot\n"
            f"conffile {'b' * 32} /etc/cron.d/certbot\n"
            "show certbot.timer UnitFileState=enabled\n"
            "show certbot.timer RandomizedDelayUSec=12h\n"
            "syntax ok /usr/local/sbin/barectl-certbot-renew\n"
            "version certbot 4.0.0\n"
        )
        state = setup.parse_state(text)
        self.assertEqual(state.units["certbot.timer"]["RandomizedDelayUSec"], "12h")
        self.assertEqual(state.conffiles, {"/etc/cron.d/certbot": "b" * 32})
        with self.assertRaises(setup.Unreadable):
            setup.parse_state(text + "unexpected output\n")


class PayloadTests(SimpleTestCase):
    def test_the_fragments_are_ordered_and_fit_one_submission(self) -> None:
        names, text = payload()
        self.assertEqual(
            names,
            [
                "admission",
                "helpers",
                "revalidation",
                "inhibition",
                "installation",
                "files",
                "override",
                "timer",
                "check",
            ],
        )
        # The closure is fixed; versions may grow a little with updates.
        self.assertLessEqual(len(text.encode()), bootstrap_native.MAX_PAYLOAD - 1024)
        bootstrap_native.submission(UNIT, text)
        result = subprocess.run(  # noqa: S603 - a syntax check of the tests' own payload
            [SHELL, "-n", "-c", text], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload(install=False)[0][4], "files")

    def test_renewal_is_inhibited_before_anything_changes_and_enabled_last(self) -> None:
        _, text = payload()
        order = [
            text.index(marker)
            for marker in (
                "flock -n 9 || exit 10",
                "exit 25",
                "exit 15",
                "systemctl mask --runtime certbot.timer certbot.service",
                "apt-get -q -y",
                "w /usr/local/sbin barectl-certbot-deploy",
                "systemctl daemon-reload",
                "systemctl unmask --runtime certbot.service >/dev/null 2>&1 || exit 29",
                "systemctl unmask --runtime certbot.timer >/dev/null 2>&1 &&",
                "systemctl enable --now certbot.timer",
            )
        ]
        self.assertEqual(order, sorted(order))
        # Exits that leave nothing changed first remove the masks.
        for code in (15, 16, 21, 23, 25):
            self.assertIn(f"{{ u; exit {code}; }}", text)
        self.assertIn("|| exit 20", text)
        for code in (27, 28, 29, 30, 24):
            self.assertRegex(text, rf"exit {code}\b")

    def test_every_published_file_is_the_reviewed_one(self) -> None:
        _, text = payload()
        for file in renewal.files():
            self.assertIn(file.sha256, text)
        self.assertIn(setup_native.renewal_digest(), text)


class OutcomeTests(SimpleTestCase):
    def evidence(self, status: int) -> UnitEvidence:
        return UnitEvidence(
            UNIT, BOOT, True, "failed", "failed", "exit-code", 1, status, "i" * 32, False
        )

    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            27: Execution.INHIBITION_FAILED,
            28: Execution.PARTIAL,
            29: Execution.PARTIAL,
            30: Execution.PARTIAL,
            25: Execution.RENEWAL_ACTIVE,
            15: Execution.DRIFT,
            21: Execution.TRANSACTION_REFUSED,
            20: Execution.INSTALL_FAILED,
            24: Execution.VALIDATION_FAILED,
        }
        for status, execution in cases.items():
            with self.subTest(status=status):
                self.assertEqual(setup_apply.execution(self.evidence(status)), execution)
        self.assertIn("stay masked at runtime", setup_apply.failure(None, Execution.PARTIAL, 28))
        self.assertIn(
            "systemctl cat certbot.service", setup_apply.failure(None, Execution.PARTIAL, 29)
        )
        self.assertIn(
            "stay masked at runtime", setup_apply.failure(None, Execution.INSTALL_FAILED, 20)
        )
        self.assertIn(
            "refused to mask",
            setup_apply.failure(None, Execution.INHIBITION_FAILED, 27),
        )
