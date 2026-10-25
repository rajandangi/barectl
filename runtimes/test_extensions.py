"""The object-cache client decision and the catalog build that supplies it (#390)."""

from django.test import SimpleTestCase

from .catalog import Architecture, Kind, load
from .extensions import (
    CLIENT,
    ENTRIES,
    PHPHREDIS_AVAILABLE,
    available,
    build,
    entry_for,
    path,
    shared_object,
)
from .presentation import shown_catalog


class RedisExtensionTests(SimpleTestCase):
    def test_the_decision_is_phpredis_from_the_locked_catalog_build(self) -> None:
        self.assertEqual(CLIENT, "phpredis")
        self.assertTrue(PHPHREDIS_AVAILABLE)
        catalog = load()
        for architecture in Architecture:
            with self.subTest(architecture=architecture):
                for runtime, entry in ENTRIES.items():
                    item = build(architecture, runtime)
                    self.assertIsNotNone(item)
                    if item is None:
                        continue
                    self.assertEqual(
                        (item.entry, item.kind, item.version), (entry, Kind.EXTENSION, "6.3.0")
                    )
                    self.assertTrue(available(architecture, runtime))
                    self.assertEqual(
                        path(architecture, runtime),
                        item.path + "/lib/php/extensions/redis.so",
                    )
                    self.assertEqual(
                        shared_object(item), item.path + "/lib/php/extensions/redis.so"
                    )
                    self.assertEqual(catalog.identify(architecture, item.path), item)

    def test_the_extensions_are_catalog_builds_but_never_shown_as_runtimes(self) -> None:
        shown = shown_catalog(checked=True, machine="aarch64")
        self.assertEqual(
            [row.entry for row in shown.runtimes], ["php84", "php85", "nodejs_22", "nodejs_24"]
        )
        offered_tools = {row.entry for row in shown.tools}
        self.assertNotIn("php84_redis", offered_tools)
        self.assertNotIn("php85_redis", offered_tools)
        self.assertNotIn("php84_redis", {row.entry for row in shown.runtimes})

    def test_a_catalog_build_that_is_not_a_runtime_has_no_extension(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a PHP runtime"):
            entry_for("caddy")
        self.assertFalse(available(Architecture.AARCH64, "nodejs_24"))
        self.assertIsNone(build(Architecture.AARCH64, "nodejs_24"))
