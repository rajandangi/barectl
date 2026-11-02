"""The Restart server change kind (Phase E #305): review, body, verification and wording."""

import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest import skipUnless

from django.test import SimpleTestCase

from discovery.models import ObservationOutcome
from discovery.snapshot import CollectedSnapshot, Observation
from discovery.ssh import CommandResult, RemoteShell
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import ChangeReview, Consent
from security import restart
from security.observation import RestartState, SecurityState
from security.presentation import present
from security.testing import check, ok_state

BOOT_ID = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
OTHER_BOOT = "7a2d5f2b-4b9f-4c60-8e3f-8d1c9b0e2f34"
UNIT = "barectl-apply-" + "b" * 32 + ".service"


def evidence(
    *,
    required: bool = True,
    packages: tuple[str, ...] = ("linux-image-generic", "libssl3t64"),
    active: tuple[tuple[str, str], ...] | None = None,
) -> restart.RestartEvidence:
    services = (
        "caddy.service",
        "mariadb.service",
        "haproxy-site@alpha.service",
        "php-fpm-site-php84@alpha.service",
    )
    return restart.RestartEvidence(
        RestartState(required, packages),
        "",
        "Target stack",
        "x86_64",
        BOOT_ID,
        500000,
        "apt 3.2.0 (amd64)",
        "Debian 'dpkg' package management program version 1.23.1 (amd64).",
        "systemd 259 (259-1ubuntu1)",
        ("alpha",),
        (restart.SiteTarget("alpha.example.com", "/health", True),),
        services,
        active if active is not None else tuple((unit, "active") for unit in services),
        10 * 1024**3,
        1024 * 1024,
    )


class RestartReviewTests(SimpleTestCase):
    def test_every_restart_refusal_and_result_reason_is_in_the_engine_contract(self) -> None:
        from operations import engine

        for reason in ("restart_work", "restart_evidence", "restart_apply"):
            self.assertIn(reason, engine.RESULT_REASONS)
            self.assertIn(reason, engine._REFUSED_REASONS)
    def test_the_restart_is_a_shared_server_change_naming_sites_and_packages(self) -> None:
        draft = restart.review(evidence(), PreparationInputs("on"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.kind, restart.SLUG)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.current_sites, ("alpha",))
        self.assertIn("Restart the server", draft.effects[0].text)
        self.assertIn("linux-image-generic", cast(list[str], draft.document["packages"]))
        details = {
            row["label"]: row["value"]
            for row in cast(list[dict[str, str]], draft.document["details"])
        }
        self.assertIn("linux-image-generic", details["Needed by"])
        self.assertIn("alpha", details["Affected sites"])
        self.assertIn("queue workers", details["Scheduled tasks and queue workers"])
        self.assertIn("provider's console", details["If it does not return"])
        self.assertIn("Web server", details["Services"])
        self.assertIn("Database", details["Services"])

    def test_a_non_target_server_refuses(self) -> None:
        draft = restart.review(
            replace(evidence(), standing="Not manageable"), PreparationInputs("on")
        )
        self.assertIn("Set up and verify the host foundation", " ".join(draft.refusals))

    def test_unreadable_restart_evidence_refuses(self) -> None:
        draft = restart.review(
            replace(evidence(), restart=None, restart_warning=""), PreparationInputs("on")
        )
        self.assertIn("could not read whether the server needs a restart", " ".join(draft.refusals))

    def test_a_same_selection_and_every_reviewed_field_round_trip_through_the_body(self) -> None:
        draft = restart.review(evidence(), PreparationInputs("on"))
        body = restart.body(draft.document, BodyContext(UNIT, BOOT_ID, 90000))
        self.assertEqual(body.arguments[0], BOOT_ID)
        self.assertEqual(body.arguments[1], "libssl3t64\nlinux-image-generic")
        forged = dict(draft.document)
        forged["packages"] = ["Bad Package"]
        with self.assertRaises(ValueError):
            restart.body(forged, BodyContext(UNIT, BOOT_ID, 90000))

    def test_the_restart_check_offers_one_action_only_with_shared_permission(self) -> None:
        state = replace(ok_state(), restart=check(RestartState(True, ("linux-image-generic",))))
        read_at = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
        shown = present(
            replace(_collected(), security=_observed(state)),
            read_at,
            restart_url="/servers/1/security/restart/prepare/",
            can_change=True,
        )
        restart_check = next(item for item in shown if item.name == "Restart needed")
        self.assertEqual(restart_check.action, "Restart server")
        self.assertEqual(restart_check.action_form, "/servers/1/security/restart/prepare/")
        viewer = present(
            replace(_collected(), security=_observed(state)),
            read_at,
            restart_url="/servers/1/security/restart/prepare/",
            can_change=False,
        )
        self.assertEqual(
            next(item for item in viewer if item.name == "Restart needed").action,
            "Not available yet",
        )


def _collected() -> CollectedSnapshot:
    from discovery.fakes import COLLECTED

    return COLLECTED


def _observed(state: SecurityState) -> Observation[SecurityState]:
    return Observation(ObservationOutcome.OBSERVED, ("a read",), "", state)


class _Shell:
    """A small recording shell for verification over one fresh connection."""

    def __init__(
        self, *, boot: str, reboot_required: str = "", states: dict[str, str] | None = None
    ) -> None:
        self.boot = boot
        self.reboot_required = reboot_required
        self.states = states or {}
        self.commands: list[str] = []

    def run(self, command: str) -> CommandResult:
        self.commands.append(command)
        if command == "id -u":
            return CommandResult(0, "0\n")
        if command == "cat /proc/sys/kernel/random/boot_id":
            return CommandResult(0, f"{self.boot}\n")
        if command == "cat /run/reboot-required 2>/dev/null || true":
            return CommandResult(0, self.reboot_required)
        if command.startswith("systemctl is-active "):
            units = command.removeprefix("systemctl is-active ").replace("'", "").split()
            return CommandResult(
                0 if all(self.states.get(unit, "active") == "active" for unit in units) else 1,
                "".join(f"{self.states.get(unit, 'active')}\n" for unit in units),
            )
        if command.startswith("curl "):
            return CommandResult(0, "200")
        raise AssertionError(f"unexpected command: {command}")


class RestartVerifyTests(SimpleTestCase):
    def stored(self) -> ChangeReview:
        draft = restart.review(evidence(), PreparationInputs("on"))
        return ChangeReview(document=draft.document)

    def test_a_new_boot_with_every_service_and_site_ready_passes(self) -> None:
        shell = _Shell(boot=OTHER_BOOT)
        self.assertTrue(restart.verify(cast(RemoteShell, shell), self.stored()))

    def test_the_same_boot_never_passes(self) -> None:
        shell = _Shell(boot=BOOT_ID)
        self.assertFalse(restart.verify(cast(RemoteShell, shell), self.stored()))

    def test_a_service_that_did_not_return_fails(self) -> None:
        shell = _Shell(boot=OTHER_BOOT, states={"caddy.service": "inactive"})
        self.assertFalse(restart.verify(cast(RemoteShell, shell), self.stored()))

    def test_a_restart_that_is_still_required_fails(self) -> None:
        shell = _Shell(boot=OTHER_BOOT, reboot_required="linux-image-generic\n")
        self.assertFalse(restart.verify(cast(RemoteShell, shell), self.stored()))

    def test_a_site_that_does_not_answer_readiness_fails(self) -> None:
        shell = _Shell(boot=OTHER_BOOT)
        shell.run = lambda command: (  # type: ignore[method-assign]
            CommandResult(0, "500") if command.startswith("curl ") else _Shell.run(shell, command)
        )
        self.assertFalse(restart.verify(cast(RemoteShell, shell), self.stored()))


@skipUnless(shutil.which("shellcheck") is not None, "shellcheck is not installed")
class RestartBodyTests(SimpleTestCase):
    def test_the_checked_in_body_passes_shellcheck(self) -> None:
        path = Path(__file__).resolve().parents[1] / "bodies" / "restart.sh"
        subprocess.run(["shellcheck", "-s", "sh", str(path)], check=True)  # noqa: S603, S607
