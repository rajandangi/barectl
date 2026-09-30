from django.test import SimpleTestCase

from . import versions


class CompareTests(SimpleTestCase):
    def test_versions_sort_as_dpkg_sorts_them(self) -> None:
        ordered = [
            "1.0~rc1",
            "1.0",
            "1.0-0ubuntu0.1",
            "1.0-1",
            "1.0-1ubuntu0.1",
            "1.0a",
            "1.0+b1",
            "1.0.1",
            "1.10",
            "1:0.1",
            "1:10.11.13-0ubuntu0.24.04.1",
            "1:10.11.14-0ubuntu0.24.04.1",
            "1:11.8.6-5ubuntu0.1",
            "2:0",
        ]
        for index, lower in enumerate(ordered):
            self.assertEqual(versions.compare(lower, lower), 0, lower)
            for higher in ordered[index + 1 :]:
                self.assertLess(versions.compare(lower, higher), 0, (lower, higher))
                self.assertGreater(versions.compare(higher, lower), 0, (higher, lower))

    def test_hyphens_in_the_upstream_version_split_at_the_last(self) -> None:
        self.assertLess(versions.compare("1.0-rc-1", "1.0-rc-2"), 0)
        self.assertEqual(versions.compare("1.0-01", "1.0-1"), 0)
