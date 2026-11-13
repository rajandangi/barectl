"""Journal retention reconstruction from fixed native facts (#549).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md.
"""

import hashlib

from django.test import SimpleTestCase

from .journal_retention import (
    DISK_CAP_CHOICES,
    MANAGED,
    MAX_AGE_CHOICES,
    NOT_CONFIGURED,
    OUTSIDE,
    SHAPE,
    RetentionObservation,
    reconstruct,
    render,
)


def file_fact(
    content: str,
    *,
    uid: int = 0,
    gid: int = 0,
    mode: str = "644",
    links: int = 1,
) -> str:
    digest = hashlib.sha256(content.encode()).hexdigest()
    return f"{uid} {gid} {mode} {links} file {digest}"


def non_file_fact(
    kind: str, *, uid: int = 0, gid: int = 0, mode: str = "644", links: int = 1
) -> str:
    return f"{uid} {gid} {mode} {links} {kind}"


class RenderTests(SimpleTestCase):
    def test_every_supported_pair_renders_the_one_native_file(self) -> None:
        for disk_cap in DISK_CAP_CHOICES:
            for max_age in MAX_AGE_CHOICES:
                with self.subTest(disk_cap=disk_cap, max_age=max_age):
                    self.assertEqual(
                        render(disk_cap, max_age),
                        f"[Journal]\nSystemMaxUse={disk_cap}\nMaxRetentionSec={max_age}\n",
                    )

    def test_a_value_outside_the_fixed_choices_is_refused(self) -> None:
        for disk_cap, max_age in (("5G", "1week"), ("250M", "2weeks"), ("250", "1year")):
            with self.subTest(disk_cap=disk_cap, max_age=max_age), self.assertRaises(ValueError):
                render(disk_cap, max_age)


class ReconstructTests(SimpleTestCase):
    def test_an_absent_file_is_not_configured_whatever_journald_reports(self) -> None:
        for disk_cap, max_age in (("", ""), ("4G", "1year"), ("100M", "2weeks")):
            with self.subTest(disk_cap=disk_cap, max_age=max_age):
                self.assertEqual(
                    reconstruct("missing", disk_cap, max_age),
                    RetentionObservation(NOT_CONFIGURED),
                )

    def test_an_exact_root_owned_file_with_matching_effective_values_is_managed(self) -> None:
        self.assertEqual(
            reconstruct(file_fact(render("2G", "3months")), "2G", "3months"),
            RetentionObservation(MANAGED, "", "2G", "3months"),
        )

    def test_vacuuming_changes_no_fact_so_a_managed_state_stays_managed(self) -> None:
        fact = file_fact(render("1G", "1month"))
        self.assertEqual(reconstruct(fact, "1G", "1month").state, MANAGED)
        self.assertEqual(reconstruct(fact, "1G", "1month").state, MANAGED)

    def test_deleting_the_file_returns_not_configured(self) -> None:
        self.assertEqual(reconstruct("missing", "1G", "1month").state, NOT_CONFIGURED)

    def test_a_hand_edited_file_is_outside(self) -> None:
        cases = (
            render("1G", "1month") + "# edited by hand\n",
            "[Journal]\nSystemMaxUse=1G\n",
            "[Journal]\nMaxRetentionSec=1month\n",
            "[Journal]\nSystemMaxUse=1G\nMaxRetentionSec=1month\nStorage=volatile\n",
            "[Journal]\nSystemMaxUse=500M\nMaxRetentionSec=1month\n",
        )
        for content in cases:
            with self.subTest(content=content):
                self.assertEqual(reconstruct(file_fact(content), "1G", "1month").state, OUTSIDE)

    def test_a_wrong_owner_group_mode_or_link_count_is_outside(self) -> None:
        content = render("1G", "1month")
        for fact in (
            file_fact(content, uid=1000),
            file_fact(content, gid=1000),
            file_fact(content, mode="664"),
            file_fact(content, mode="600"),
            file_fact(content, links=2),
        ):
            with self.subTest(fact=fact):
                self.assertEqual(reconstruct(fact, "1G", "1month").state, OUTSIDE)

    def test_an_empty_regular_file_is_outside(self) -> None:
        observation = reconstruct(file_fact(""), "", "")
        self.assertEqual(observation.state, OUTSIDE)
        self.assertIn("exact content", observation.reason)

    def test_a_symlink_directory_or_other_object_is_outside(self) -> None:
        for kind in ("symlink", "directory", "other"):
            with self.subTest(kind=kind):
                observation = reconstruct(non_file_fact(kind), "1G", "1month")
                self.assertEqual(observation.state, OUTSIDE)
                self.assertIn("not a regular file", observation.reason)

    def test_a_later_value_outside_the_choices_is_outside(self) -> None:
        fact = file_fact(render("1G", "1month"))
        for disk_cap, max_age in (("10%", "1month"), ("0", "1month"), ("1G", "0")):
            with self.subTest(disk_cap=disk_cap, max_age=max_age):
                observation = reconstruct(fact, disk_cap, max_age)
                self.assertEqual(observation.state, OUTSIDE)
                self.assertIn("later configuration overrides", observation.reason)

    def test_a_later_drop_in_override_is_outside_with_a_plain_reason(self) -> None:
        observation = reconstruct(file_fact(render("2G", "3months")), "1G", "1month")
        self.assertEqual(observation.state, OUTSIDE)
        self.assertIn("later configuration overrides", observation.reason)

    def test_an_unreadable_file_or_missing_effective_value_is_outside(self) -> None:
        content = render("1G", "1month")
        cases = (
            reconstruct("", "1G", "1month"),
            reconstruct("garbage", "1G", "1month"),
            reconstruct(file_fact(content), "", "1month"),
            reconstruct(file_fact(content), "1G", ""),
        )
        for observation in cases:
            with self.subTest(observation=observation):
                self.assertEqual(observation.state, OUTSIDE)
                self.assertTrue(observation.reason)


class ShapeTests(SimpleTestCase):
    def test_the_promised_shape_matches_the_rendered_file(self) -> None:
        self.assertEqual(
            SHAPE.replace("<disk-cap>", "250M").replace("<max-age>", "1week"),
            render("250M", "1week"),
        )
