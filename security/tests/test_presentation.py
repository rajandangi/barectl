from datetime import UTC, datetime

from django.test import SimpleTestCase

from discovery.models import ObservationOutcome
from discovery.snapshot import CollectedSnapshot, FilesystemSize, Observation, OsRelease
from security.observation import (
    AutoUpdatesState,
    Check,
    FirewallState,
    Listener,
    PendingUpdate,
    RestartState,
    SecurityState,
    SshState,
    UpdatesState,
)
from security.presentation import ATTENTION, OK, OUTSIDE, UNKNOWN, ShownCheck, present

READ_AT = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - an observed address, never bound


def _check[T](
    value: T | None, status: ObservationOutcome = ObservationOutcome.OBSERVED
) -> Check[T]:
    return Check(status, ("read",), "" if value is not None else "Could not read it.", value)


def _state(
    *,
    firewall: Check[FirewallState] | None = None,
    listeners: Check[tuple[Listener, ...]] | None = None,
    ssh: Check[SshState] | None = None,
    auto_updates: Check[AutoUpdatesState] | None = None,
    updates: Check[UpdatesState] | None = None,
    restart: Check[RestartState] | None = None,
) -> SecurityState:
    return SecurityState(
        firewall=firewall
        or _check(
            FirewallState(
                False,
                None,
                "",
                "",
                "",
                None,
                "",
                (),
                (),
                None,
            )
        ),
        listeners=listeners or _check(()),
        ssh=ssh or _check(SshState("no", "no", "prohibit-password", (22,), (22,), (), "yes")),
        auto_updates=auto_updates
        or _check(AutoUpdatesState(True, "active", "active", False, (), True, "", None)),
        updates=updates or _check(UpdatesState(3600, ())),
        restart=restart or _check(RestartState(False, ())),
    )


def _observed[T](value: T) -> Observation[T]:
    return Observation(ObservationOutcome.OBSERVED, (), "", value)


def _collected(state: SecurityState | None) -> CollectedSnapshot:
    return CollectedSnapshot(
        os=_observed(OsRelease("Ubuntu 26.04 LTS", "Ubuntu", "ubuntu", "26.04")),
        architecture=_observed("x86_64"),
        cpu_count=_observed(2),
        memory_bytes=_observed(2048),
        filesystem=_observed(FilesystemSize(1_000, 500)),
        components=(),
        sites=_observed(()),
        security=_observed(state),
    )


def _by_name(checks: tuple[ShownCheck, ...]) -> dict[str, ShownCheck]:
    return {check.name: check for check in checks}


class SecurityPresentationTests(SimpleTestCase):
    def test_without_an_observation_every_check_says_it_could_not_be_checked(self) -> None:
        checks = present(_collected(None), READ_AT)
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(check.state == UNKNOWN for check in checks))
        self.assertEqual(checks[0].action, "Not available yet")
        self.assertEqual(checks[0].read_at, READ_AT)

    def test_a_firewall_outside_the_supported_settings_blocks_only_that_check(self) -> None:
        state = _state(
            firewall=_check(
                FirewallState(
                    True,
                    True,
                    "deny",
                    "allow",
                    "deny",
                    True,
                    "on (low)",
                    (),
                    ("Docker is active and publishes ports ahead of a host firewall.",),
                    True,
                )
            )
        )
        checks = _by_name(present(_collected(state), READ_AT))
        firewall = checks["Firewall"]
        self.assertEqual(firewall.state, OUTSIDE)
        self.assertIn("cloud provider", firewall.note)
        self.assertEqual(checks["SSH sign-in"].state, OK)

    def test_an_unexpected_public_listener_names_its_process(self) -> None:
        state = _state(
            listeners=_check(
                (
                    Listener(ALL_INTERFACES, 22, "tcp", "sshd", True),
                    Listener(ALL_INTERFACES, 5432, "tcp", "postgres", True),
                )
            )
        )
        check = _by_name(present(_collected(state), READ_AT))["Public ports"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("postgres", check.what)
        self.assertIn("5432/tcp", check.what)

    def test_weak_ssh_sign_in_is_attention_and_names_accounts_without_keys(self) -> None:
        state = _state(ssh=_check(SshState("yes", "no", "yes", (22,), (22,), ("deploy",), "no")))
        check = _by_name(present(_collected(state), READ_AT))["SSH sign-in"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("passwords can sign in", check.what)
        self.assertIn("deploy", " ".join(check.details))

    def test_customised_automatic_updates_are_reported_and_left_alone(self) -> None:
        state = _state(
            auto_updates=_check(
                AutoUpdatesState(
                    True, "active", "active", False, ("Ubuntu:resolute",), False, "", None
                )
            )
        )
        check = _by_name(present(_collected(state), READ_AT))["Automatic security updates"]
        self.assertEqual(check.state, OUTSIDE)

    def test_security_updates_are_counted_and_prioritised(self) -> None:
        state = _state(
            updates=_check(
                UpdatesState(
                    7200,
                    (
                        PendingUpdate(
                            "openssl", "3.0.0", "3.0.1", "resolute-security/main", "security"
                        ),
                        PendingUpdate("curl", "8.0", "8.1", "resolute-updates/main", "other"),
                    ),
                )
            )
        )
        check = _by_name(present(_collected(state), READ_AT))["Ubuntu updates"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("1 security update", check.what)
        self.assertIn("2 hours ago", " ".join(check.details))

    def test_a_restart_names_the_packages_that_need_it(self) -> None:
        state = _state(restart=_check(RestartState(True, ("linux-image-generic",))))
        check = _by_name(present(_collected(state), READ_AT))["Restart needed"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("linux-image-generic", " ".join(check.details))

    def test_opening_the_section_reads_no_remote_evidence(self) -> None:
        from unittest import mock

        with mock.patch("discovery.ssh.connect") as connect:
            present(_collected(_state()), READ_AT)
        connect.assert_not_called()
