import hashlib
import json
from collections.abc import Mapping, Sequence

from django.test import SimpleTestCase

from .catalog import Architecture, Build, Catalog, CatalogLockError, Kind, load, parse
from .lock_generation import (
    PINS_PATH,
    GenerationError,
    Pin,
    Pins,
    check,
    generate,
    read_pins,
    trusted_installer,
)

OLD = "1" * 40
NEW = "2" * 40
# The builds each nixpkgs revision evaluates to, by entry; caddy did not change.
VERSIONS = {
    OLD: {"php83": "8.3.30", "php84": "8.4.25", "caddy": "2.11.7"},
    NEW: {"php84": "8.4.26", "caddy": "2.11.7"},
}
KINDS = {"php83": Kind.PHP, "php84": Kind.PHP, "caddy": Kind.TOOL}


def store_path(name: str, version: str, architecture: Architecture) -> str:
    digest = hashlib.sha256(f"{name}{version}{architecture}".encode()).hexdigest()
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
    return f"/nix/store/{''.join(alphabet[int(c, 16)] for c in digest[:32])}-{name}-{version}"


class FakeNix:
    def evaluate(self, pin: Pin, architecture: Architecture) -> Mapping[str, tuple[str, str]]:
        versions = VERSIONS[pin.nixpkgs]
        return {
            name: (store_path(name, versions[name], architecture), versions[name])
            for name in pin.entries
        }

    def sizes(self, paths: Sequence[str]) -> Mapping[str, tuple[int, int]]:
        return {path: (4 * (100 + len(path)), 100 + len(path)) for path in paths}

    def installer_sha256(self, version: str, architecture: Architecture) -> str:
        return hashlib.sha256(f"{version}{architecture}".encode()).hexdigest()


def pin(nixpkgs: str) -> Pin:
    return Pin(nixpkgs, "0" * 52, {name: (KINDS[name], name) for name in VERSIONS[nixpkgs]})


PINS = Pins("2.35.2", (pin(OLD), pin(NEW)))


def described(build: Build | None) -> tuple[str, str, str, bool] | None:
    return None if build is None else (build.entry, build.version, build.nixpkgs, build.retired)


class CatalogLookupTests(SimpleTestCase):
    def test_lookup_tells_offered_retired_and_unknown_builds_apart_on_both_architectures(
        self,
    ) -> None:
        catalog = parse(generate(PINS, FakeNix()))
        for architecture in Architecture:
            with self.subTest(architecture=architecture):
                for version, expected in (
                    ("8.4.26", ("php84", "8.4.26", NEW, False)),
                    ("8.4.25", ("php84", "8.4.25", OLD, True)),
                    ("8.4.27", None),
                ):
                    path = store_path("php84", version, architecture)
                    self.assertEqual(described(catalog.identify(architecture, path)), expected)
        other = store_path("php84", "8.4.26", Architecture.AARCH64)
        self.assertIsNone(catalog.identify(Architecture.X86_64, other))

    def test_retired_builds_are_recognized_but_never_offered(self) -> None:
        catalog = parse(generate(PINS, FakeNix()))
        for architecture in Architecture:
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    [described(b) for b in catalog.offered(architecture)],
                    [("php84", "8.4.26", NEW, False), ("caddy", "2.11.7", NEW, False)],
                )
                dropped = store_path("php83", "8.3.30", architecture)
                self.assertEqual(
                    described(catalog.identify(architecture, dropped)),
                    ("php83", "8.3.30", OLD, True),
                )

    def test_regeneration_is_byte_identical_and_never_drops_a_locked_build(self) -> None:
        text = generate(PINS, FakeNix())
        self.assertEqual(generate(PINS, FakeNix(), parse(text)), text)
        with self.assertRaisesRegex(GenerationError, "never removed.*php83"):
            generate(Pins("2.35.2", (pin(NEW),)), FakeNix(), parse(text))

    def test_check_detects_hand_edits_and_judges_retirement_against_the_base_lock(self) -> None:
        base = generate(PINS, FakeNix())
        self.assertIsNone(check(PINS, FakeNix(), base, base))
        edited = base.replace('"version": "8.4.26"', '"version": "8.4.99"', 1)
        self.assertIn('-          "version": "8.4.99"', check(PINS, FakeNix(), edited, base) or "")
        # A change that drops the old revision and regenerates is consistent with its own
        # pins, yet still drops builds the base branch lists.
        dropped = Pins("2.35.2", (pin(NEW),))
        regenerated = generate(dropped, FakeNix())
        self.assertIsNone(check(dropped, FakeNix(), regenerated, None))
        with self.assertRaisesRegex(GenerationError, "never removed.*php83"):
            check(dropped, FakeNix(), regenerated, base)

    def test_hand_edited_locks_are_refused(self) -> None:
        text = generate(PINS, FakeNix())
        lock = json.loads(text)
        del lock["entries"]["php84"]["builds"]["aarch64-linux"]
        self.assert_refused(lock, "one architecture removed")
        lock = json.loads(text)
        lock["entries"]["php84"]["builds"]["x86_64-linux"]["path"] = "/usr/bin/php"
        self.assert_refused(lock, "a path outside the store")
        lock = json.loads(text)
        retired = lock["retired"][0]
        retired["path"] = lock["entries"]["php84"]["builds"][retired["architecture"]]["path"]
        self.assert_refused(lock, "a build listed twice")
        lock = json.loads(text)
        lock["nix"]["installers"]["x86_64-linux"]["url"] = "https://example.com/nix.tar.xz"
        self.assert_refused(lock, "an installer from elsewhere")

    def test_a_retired_build_of_the_current_revision_and_a_boolean_format_are_refused(
        self,
    ) -> None:
        text = generate(PINS, FakeNix())
        lock = json.loads(text)
        lock["retired"][0]["nixpkgs"] = NEW
        self.assert_refused(lock, "retired from the current revision")
        lock = json.loads(text)
        lock["format"] = True
        self.assert_refused(lock, "a boolean format")
        with self.assertRaises(CatalogLockError):
            Catalog(NEW, (), ()).installer(Architecture.X86_64)

    def assert_refused(self, lock: object, edit: str) -> None:
        with self.subTest(edit), self.assertRaises(CatalogLockError):
            parse(json.dumps(lock))

    def test_committed_lock_offers_every_pinned_entry_on_both_architectures(self) -> None:
        catalog = load()
        current = read_pins(PINS_PATH.read_text(encoding="utf-8")).revisions[-1]
        self.assertEqual(catalog.nixpkgs, current.nixpkgs)
        for architecture in Architecture:
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    {(b.entry, b.kind) for b in catalog.offered(architecture)},
                    {(name, kind) for name, (kind, _) in current.entries.items()},
                )
                self.assertTrue(
                    catalog.installer(architecture).url.endswith(f"-{architecture}.tar.xz")
                )


def unreachable(url: str) -> str:
    raise AssertionError(f"{url} was fetched although the base lock pins this release.")


class TrustedInstallerTests(SimpleTestCase):
    def lock(self, nix: str, digest: str = "") -> Catalog:
        lock = json.loads(generate(Pins(nix, (pin(NEW),)), FakeNix()))
        if digest:
            lock["nix"]["installers"]["x86_64-linux"]["sha256"] = digest
        return parse(json.dumps(lock))

    def test_an_unchanged_release_must_keep_the_base_digest(self) -> None:
        base = self.lock("2.35.2")
        installer = trusted_installer(base, base, Architecture.X86_64, unreachable)
        self.assertEqual(installer.url, base.installer(Architecture.X86_64).url)
        with self.assertRaisesRegex(GenerationError, "not the trusted one"):
            trusted_installer(self.lock("2.35.2", "f" * 64), base, Architecture.X86_64, unreachable)

    def test_a_new_release_must_match_its_published_digest(self) -> None:
        base = self.lock("2.35.2")
        changed = self.lock("2.36.0")
        published = changed.installer(Architecture.X86_64).sha256
        url = changed.installer(Architecture.X86_64).url
        self.assertEqual(
            trusted_installer(
                changed, base, Architecture.X86_64, {f"{url}.sha256": f"{published}\n"}.__getitem__
            ).sha256,
            published,
        )
        with self.assertRaisesRegex(GenerationError, "not the trusted one"):
            trusted_installer(
                changed, None, Architecture.X86_64, {f"{url}.sha256": "e" * 64}.__getitem__
            )


class PinsTests(SimpleTestCase):
    def test_malformed_pins_are_refused(self) -> None:
        revision = {
            "nixpkgs": NEW,
            "sha256": "0" * 52,
            "entries": {"php84": {"kind": "php", "attribute": "php84"}},
        }
        cases = {
            "not JSON": "{",
            "a revision pinned twice": {"nix": "2.35.2", "revisions": [revision, revision]},
            "no entries": {"nix": "2.35.2", "revisions": [{**revision, "entries": {}}]},
            "an invalid entry name": {
                "nix": "2.35.2",
                "revisions": [
                    {**revision, "entries": {"PHP 8.4": {"kind": "php", "attribute": "php84"}}}
                ],
            },
            "no tarball digest": {"nix": "2.35.2", "revisions": [{**revision, "sha256": ""}]},
        }
        for name, pins in cases.items():
            with self.subTest(name), self.assertRaises(GenerationError):
                read_pins(pins if isinstance(pins, str) else json.dumps(pins))
