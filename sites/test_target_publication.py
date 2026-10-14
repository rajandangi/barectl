"""Scratch filesystem refusals preserve existing content without staging a replacement."""

import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .bodies.common import replace_caddy
from .bodies.pool import supported_pool
from .configuration import SiteSettings, render_pool


class TargetPublicationTests(SimpleTestCase):
    def test_a_disappeared_reviewed_preimage_is_not_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "keep.txt"
            existing.write_text("foreign-content")
            target = root / "shop.caddy"
            with self.assertRaisesMessage(ValueError, "preimage changed"):
                replace_caddy(target, "candidate", "reviewed-old-content")
            self.assertFalse(target.exists())
            self.assertEqual(existing.read_text(), "foreign-content")
            self.assertEqual(tuple(root.iterdir()), (existing,))

    def test_an_unsafe_directory_refuses_before_any_candidate_file_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o777)
            target = root / "shop.caddy"
            with self.assertRaisesMessage(ValueError, "preimage changed"):
                replace_caddy(target, "candidate", None)
            self.assertEqual(tuple(root.iterdir()), ())
            self.assertEqual(root.stat().st_mode & 0o777, 0o777)

    def test_the_pool_boundary_rejects_the_child_count_refused_by_native_fpm(self) -> None:
        for runtime in ("php84", "php85"):
            with self.subTest(runtime=runtime):
                settings = SiteSettings("shop", ("shop.example.com",), runtime)
                original = render_pool(settings)
                self.assertTrue(supported_pool("shop", runtime, original))
                invalid = original.replace("pm.max_children = 2", "pm.max_children = 0")
                self.assertFalse(supported_pool("shop", runtime, invalid))
