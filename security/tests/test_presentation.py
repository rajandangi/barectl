from dataclasses import replace
from datetime import UTC, datetime

from django.test import SimpleTestCase

from discovery.models import ObservationOutcome
from discovery.snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    OsRelease,
)
from runtimes.observation import RuntimeObservation as ObservedRuntime
from security.observation import (
    DEFAULT_ALLOWED_ORIGINS,
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
from security.testing import check as read_check

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
        or read_check(
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
        listeners=listeners or read_check(()),
        ssh=ssh or read_check(SshState("no", "no", "prohibit-password", (22,), (22,), (), "yes")),
        auto_updates=auto_updates
        or read_check(
            AutoUpdatesState(
                True, "enabled", "enabled", False, DEFAULT_ALLOWED_ORIGINS, True, "", None, True
            )
        ),
        updates=updates or read_check(UpdatesState(3600, ())),
        restart=restart or read_check(RestartState(False, ())),
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
        self.assertEqual(len(checks), 6)
        self.assertTrue(all(check.state == UNKNOWN for check in checks))
        self.assertEqual(checks[0].action, "Not available yet")
        self.assertEqual(checks[0].read_at, READ_AT)

    def test_a_firewall_outside_the_supported_settings_blocks_only_thatread_check(self) -> None:
        state = _state(
            firewall=read_check(
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
            listeners=read_check(
                (
                    Listener(ALL_INTERFACES, 22, "tcp", "sshd", True),
                    Listener(ALL_INTERFACES, 5432, "tcp", "postgres", True),
                )
            )
        )
        check = _by_name(present(_collected(state), READ_AT))["Firewall"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("Database", check.what)
        self.assertIn("5432/tcp", check.what)

    def test_weak_ssh_sign_in_is_attention_and_names_accounts_without_keys(self) -> None:
        state = _state(
            ssh=read_check(SshState("yes", "no", "yes", (22,), (22,), ("deploy",), "no"))
        )
        check = _by_name(present(_collected(state), READ_AT))["SSH sign-in"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("passwords can sign in", check.what)
        self.assertIn("deploy", " ".join(check.details))

    def test_customised_automatic_updates_are_reported_and_left_alone(self) -> None:
        state = _state(
            auto_updates=read_check(
                AutoUpdatesState(
                    True, "enabled", "enabled", False, ("Ubuntu:resolute",), False, "", None, True
                )
            )
        )
        check = _by_name(present(_collected(state), READ_AT))["Automatic security updates"]
        self.assertEqual(check.state, OUTSIDE)
        self.assertEqual(check.action, "Not available yet")
        self.assertIn("allowed update sources", " ".join(check.details))

    def test_the_check_offers_turn_on_and_shows_ubuntu_history_to_a_permitted_operator(
        self,
    ) -> None:
        state = _state(
            auto_updates=read_check(
                AutoUpdatesState(
                    False,
                    "enabled",
                    "enabled",
                    False,
                    DEFAULT_ALLOWED_ORIGINS,
                    True,
                    "Packages that were upgraded: openssl",
                    3600,
                    True,
                )
            )
        )
        check = _by_name(
            present(
                _collected(state),
                READ_AT,
                auto_updates_url="/servers/1/security/automatic-updates/prepare/",
                can_change=True,
            )
        )["Automatic security updates"]
        self.assertEqual(check.action, "Turn on")
        self.assertEqual(check.action_form, "/servers/1/security/automatic-updates/prepare/")
        self.assertEqual(check.action_value, "on")
        self.assertIn("Ubuntu's own history", " ".join(check.details))
        self.assertIn("Valkey", check.note)

    def test_without_change_permission_the_automatic_updates_control_is_absent(self) -> None:
        state = _state(
            auto_updates=read_check(
                AutoUpdatesState(
                    False,
                    "enabled",
                    "enabled",
                    False,
                    DEFAULT_ALLOWED_ORIGINS,
                    True,
                    "",
                    None,
                    True,
                )
            )
        )
        check = _by_name(
            present(
                _collected(state),
                READ_AT,
                auto_updates_url="/servers/1/security/automatic-updates/prepare/",
            )
        )["Automatic security updates"]
        self.assertEqual(check.action, "Not available yet")
        self.assertEqual(check.action_form, "")

    def test_security_updates_are_counted_and_prioritised(self) -> None:
        state = _state(
            updates=read_check(
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
        state = _state(restart=read_check(RestartState(True, ("linux-image-generic",))))
        check = _by_name(present(_collected(state), READ_AT))["Restart needed"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("linux-image-generic", " ".join(check.details))

    def test_root_without_password_is_key_sign_in_not_a_password(self) -> None:
        state = _state(
            ssh=read_check(SshState("no", "no", "without-password", (22,), (22,), (), "no"))
        )
        check = _by_name(present(_collected(state), READ_AT))["SSH sign-in"]
        self.assertEqual(check.state, OK)

    def test_a_runtime_protection_problem_is_attention_and_never_safe(self) -> None:
        runtime = ObservedRuntime(
            "php84",
            "/nix/store/old-php",
            "12",
            "8.4.10",
            (),
            "active",
            (("opcache.validate_permission", "0"),),
            "Protection fault. Pool changes on this master are blocked.",
        )
        collected = replace(_collected(_state()), runtimes=(runtime,))
        check = _by_name(present(collected, READ_AT))["Web runtimes"]
        self.assertEqual(check.state, ATTENTION)
        self.assertIn("do not match", " ".join(check.details))

    def test_a_runtime_shows_its_build_and_age(self) -> None:
        runtime = ObservedRuntime(
            "php84",
            "/nix/store/old-php",
            "12",
            "8.4.10",
            (),
            "active",
            (),
            "",
            installed_at=int(READ_AT.timestamp()) - 7200,
        )
        collected = replace(_collected(_state()), runtimes=(runtime,))
        check = _by_name(present(collected, READ_AT))["Web runtimes"]
        self.assertIn("PHP 8.4: build 12, installed 2 hours ago", check.details)

    def test_an_unread_architecture_is_could_not_check(self) -> None:
        runtime = ObservedRuntime(
            "php84", "/nix/store/old-php", "12", "8.4.10", (), "active", (), ""
        )
        collected = replace(
            _collected(_state()),
            architecture=Observation(ObservationOutcome.UNSUPPORTED, (), "", None),
            runtimes=(runtime,),
        )
        check = _by_name(present(collected, READ_AT))["Web runtimes"]
        self.assertEqual(check.state, UNKNOWN)
        self.assertIn("architecture", check.what)

    def test_opening_the_section_reads_no_remote_evidence(self) -> None:
        from unittest import mock

        with mock.patch("discovery.ssh.connect") as connect:
            present(_collected(_state()), READ_AT)
        connect.assert_not_called()
