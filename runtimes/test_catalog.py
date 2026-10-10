import hashlib
import json
from collections.abc import Mapping, Sequence

from django.test import SimpleTestCase

from .catalog import Architecture, Build, CatalogLockError, Kind, load, parse
from .lock_generation import PINS_PATH, GenerationError, Pin, Pins, generate, read_pins

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
    def evaluate(
        self, nixpkgs: str, architecture: Architecture, attributes: Mapping[str, str]
    ) -> Mapping[str, tuple[str, str]]:
        versions = VERSIONS[nixpkgs]
        return {
            name: (store_path(name, versions[name], architecture), versions[name])
            for name in attributes
        }

    def sizes(self, paths: Sequence[str]) -> Mapping[str, tuple[int, int]]:
        return {path: (4 * (100 + len(path)), 100 + len(path)) for path in paths}

    def installer_sha256(self, version: str, architecture: Architecture) -> str:
        return hashlib.sha256(f"{version}{architecture}".encode()).hexdigest()


def pin(nixpkgs: str) -> Pin:
    return Pin(nixpkgs, {name: (KINDS[name], name) for name in VERSIONS[nixpkgs]})


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
