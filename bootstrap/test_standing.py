from dataclasses import replace
from unittest import TestCase

from .standing import HostEvidence, Standing, judge


def fresh_evidence() -> HostEvidence:
    return HostEvidence(
        release="26.04",
        architecture="amd64",
        apt_series="3.2",
        dpkg_series="1.23",
        systemd_series="259",
        privileged=True,
        free_disk_bytes=20 * 1024**3,
        available_memory_bytes=4 * 1024**3,
        foreign_web_stacks=(),
        privileged_listeners=(),
        panel_paths=(),
        nix_shape="absent",
        nix_build_uid_range_free=True,
        required_tools_missing=(),
        clock_synchronized=True,
        apt_daily_active=False,
        foundation=("absent",) * 5,
    )


class HostStandingTests(TestCase):
    def test_qualified_empty_host_is_fresh(self) -> None:
        result = judge(fresh_evidence())
        self.assertEqual(result.standing, Standing.FRESH)
        self.assertEqual(result.reasons, ())

    def test_foreign_web_stack_makes_host_not_manageable(self) -> None:
        result = judge(replace(fresh_evidence(), foreign_web_stacks=("nginx",)))
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertEqual(
            result.reasons,
            ("Another web stack is installed: nginx.",),
        )

    def test_apache_and_apt_php_are_named_as_foreign_installations(self) -> None:
        evidence = replace(
            fresh_evidence(),
            foreign_web_stacks=("Apache packages: apache2", "APT PHP packages: php8.3-fpm"),
        )
        result = judge(evidence)
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertEqual(
            result.reasons,
            (
                (
                    "Another web stack is installed: Apache packages: apache2, "
                    "APT PHP packages: php8.3-fpm."
                ),
            ),
        )

    def test_legacy_nginx_and_apt_php_share_foreign_stack_judgment(self) -> None:
        result = judge(replace(fresh_evidence(), foreign_web_stacks=("nginx", "APT PHP")))
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertIn("Earlier Barectl layouts are not managed.", result.reasons)

    def test_listener_and_panel_are_named_as_foreign_evidence(self) -> None:
        result = judge(
            replace(
                fresh_evidence(),
                privileged_listeners=("users:(('nginx',pid=55,fd=6))",),
                panel_paths=("/usr/local/cpanel",),
            )
        )
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertTrue(any("Ports 80 or 443" in reason for reason in result.reasons))
        self.assertTrue(any("/usr/local/cpanel" in reason for reason in result.reasons))

    def test_missing_evidence_is_not_misreported_as_absent(self) -> None:
        result = judge(replace(fresh_evidence(), release=None))
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertIn("The operating system could not be read.", result.reasons)

    def test_unreadable_foreign_stack_inventory_is_not_shown_as_empty(self) -> None:
        result = judge(replace(fresh_evidence(), foreign_stacks_readable=False))
        self.assertIn(("Foreign web stacks", "Could not be read"), result.evidence)

    def test_unsupported_release_and_build_user_collision_refuse_changes(self) -> None:
        evidence = replace(fresh_evidence(), release="24.04", nix_build_uid_range_free=False)
        result = judge(evidence)
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertIn("Ubuntu 24.04 is outside supported settings.", result.reasons)
        self.assertIn(
            "The Nix build-user ID range is occupied or could not be checked.", result.reasons
        )

    def test_partial_nix_and_active_apt_activity_refuse_changes(self) -> None:
        evidence = replace(fresh_evidence(), nix_shape="partial", apt_daily_active=True)
        result = judge(evidence)
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertIn(
            "The Nix installation is partial and needs ordinary administration.", result.reasons
        )
        self.assertIn(
            "APT background package activity is running or could not be checked.", result.reasons
        )

    def test_unrecognized_nix_and_missing_tools_are_named(self) -> None:
        result = judge(
            replace(
                fresh_evidence(),
                nix_shape="unrecognized",
                required_tools_missing=("ss",),
            )
        )
        self.assertIn("An unrecognized Nix installation is present.", result.reasons)
        self.assertIn("Required tools are missing: ss.", result.reasons)

    def test_non_root_connection_is_not_manageable(self) -> None:
        result = judge(replace(fresh_evidence(), privileged=False))
        self.assertIn("The discovery connection is not running as root.", result.reasons)

    def test_low_headroom_reason_keeps_provisional_threshold_disclosed(self) -> None:
        evidence = replace(fresh_evidence(), free_disk_bytes=1, available_memory_bytes=1)
        result = judge(evidence)
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertTrue(any("provisional 10 GiB" in reason for reason in result.reasons))
        self.assertTrue(any("provisional 2 GiB" in reason for reason in result.reasons))

    def test_clock_is_warning_only(self) -> None:
        result = judge(replace(fresh_evidence(), clock_synchronized=False))
        self.assertEqual(result.standing, Standing.FRESH)
        self.assertEqual(result.warnings, ("The server clock is not synchronized.",))

    def test_unknown_clock_is_warning_only(self) -> None:
        result = judge(replace(fresh_evidence(), clock_synchronized=None))
        self.assertEqual(result.standing, Standing.FRESH)
        self.assertEqual(result.warnings, ("Clock synchronization could not be checked.",))

    def test_present_foundation_stage_is_incomplete_not_target_stack(self) -> None:
        partial = ("present", "absent", "absent", "absent", "absent")
        result = judge(replace(fresh_evidence(), foundation=partial))
        self.assertEqual(result.standing, Standing.INCOMPLETE_FOUNDATION)

    def test_complete_foundation_is_target_stack(self) -> None:
        result = judge(replace(fresh_evidence(), foundation=("present",) * 5))
        self.assertEqual(result.standing, Standing.TARGET_STACK)

    def test_unreadable_foundation_stage_is_not_reported_absent(self) -> None:
        foundation = ("absent", "unreadable", "absent", "absent", "absent")
        result = judge(replace(fresh_evidence(), foundation=foundation))
        self.assertEqual(result.standing, Standing.NOT_MANAGEABLE)
        self.assertIn("One or more foundation stages could not be read.", result.reasons)
