"""A catalog update keeps every request served and an unused runtime can be removed (#386).

A test catalog generation gives ``php84`` a second, locally valid build so the update moves
a live site away and back through ADR 0038's admission drain. The site's requests are driven
through Caddy throughout. A second case updates to a broken build and proves the run is
reported incomplete while the site still serves; the previous generation stays installed.
"""

import importlib
import json
import shlex
import shutil
import tempfile
import time
from pathlib import Path
from typing import cast, override

from django.test import tag

from operations.inputs import PreparationInputs
from runtimes import catalog as runtime_catalog
from runtimes import remove as runtime_remove
from runtimes import revert as runtime_revert
from runtimes import update as runtime_update
from sites import observation as site_observation
from sites import php_change
from sites.change import CREATE_SITE

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

PROFILE = "/nix/var/nix/profiles/barectl"
NIX = "/nix/var/nix/profiles/default/bin"
REQUESTS = "/run/s386cat-requests"


class CatalogScenario(ScenarioTestCase):
    """Shared catalog fixture, profile restoration and request driver."""

    layer = "L1"
    exclusive = True
    prefix = "s386cat"
    site = "s386cat"

    @override
    def setUp(self) -> None:
        super().setUp()
        self.original_lock = runtime_catalog.LOCK_PATH
        self.original_php84 = self.native(f"readlink -f {PROFILE}/php84").strip()
        self.original_php85 = self.native(f"readlink -f {PROFILE}/php85").strip()
        self.added_builds: list[str] = []
        self.fixture_directory = ""
        self.requests = "0"
        self.failures = 0

    @override
    def tearDown(self) -> None:
        try:
            self.native(
                f"{NIX}/nix-env --profile {PROFILE}/php84 --set "
                + shlex.quote(self.original_php84)
                + " >/dev/null 2>&1 || true; "
                + f"{NIX}/nix-env --profile {PROFILE}/php85 --set "
                + shlex.quote(self.original_php85)
                + " >/dev/null 2>&1 || true; "
                + "systemctl reset-failed php-fpm@php84.service php-fpm@php85.service || true"
            )
            for path in self.added_builds:
                self.native(f"{NIX}/nix-store --delete {shlex.quote(path)} 2>/dev/null || true")
            if self.fixture_directory:
                shutil.rmtree(self.fixture_directory, ignore_errors=True)
            if self.original_lock != runtime_catalog.LOCK_PATH:
                runtime_catalog.LOCK_PATH = self.original_lock
                runtime_catalog.load.cache_clear()
                for module in (
                    site_observation,
                    php_change,
                    runtime_update,
                    runtime_remove,
                    runtime_revert,
                ):
                    importlib.reload(module)
        finally:
            super().tearDown()

    def create_site(self) -> None:
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", self.site, (f"{self.site}.example.com",)),
        )

    def runtime_version(self) -> str:
        body = self.native(
            "curl --fail --silent --header "
            + shlex.quote(f"Host: {self.site}.example.com")
            + " http://127.0.0.1/"
        )
        return str(json.loads(body)["runtime"])

    def shell_for_runtime(self, entry: str) -> runtime_remove.RemovalEvidence:
        with self.shell() as shell:
            return runtime_remove.inspect(shell, PreparationInputs(entry))

    def add_build(self, source: str, *, complete: bool = True) -> str:
        names = ("php", "php-fpm", ".php-fpm-wrapped") if complete else ("php",)
        base = source.split("/")[-1].split("-", 1)[1]
        parent = self.native("mktemp -d /run/s386cat-build.XXXXXX").strip()
        content = parent + "/" + base
        try:
            command = f"mkdir -p {shlex.quote(content + '/bin')}; " + "".join(
                f"ln -s {shlex.quote(source + '/bin/' + name)} "
                + shlex.quote(content + "/bin/" + name)
                + "; "
                for name in names
            )
            self.native(command)
            path = (
                self.native(f"{NIX}/nix-store --add {shlex.quote(content)}")
                .strip()
                .splitlines()[-1]
            )
        finally:
            self.native(f"rm -rf {shlex.quote(parent)}")
        self.added_builds.append(path)
        self.assertIn("/nix/store/", path)
        self.assertTrue(path.endswith("-" + base))
        return path

    def add_mismatched_build(self, source: str) -> str:
        """A build whose configuration passes but whose module list differs from its service."""
        base = source.split("/")[-1].split("-", 1)[1]
        wrapper = "/run/s386cat-build"
        parent = self.native(f"mktemp -d {wrapper}.XXXXXX").strip()
        content = parent + "/" + base
        script = (
            "#!/bin/sh\n"
            'if [ "$1" = "-m" ]; then\n'
            "  printf '[PHP Modules]\\njson\\n\\n[Zend Modules]\\nZend OPcache\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exec " + shlex.quote(source + "/bin/php-fpm") + ' "$@"\n'
        )
        try:
            self.native(
                f"mkdir -p {shlex.quote(content + '/bin')}; "
                f"ln -s {shlex.quote(source + '/bin/php')} "
                f"{shlex.quote(content + '/bin/php')}; "
                f"ln -s {shlex.quote(source + '/bin/.php-fpm-wrapped')} "
                f"{shlex.quote(content + '/bin/.php-fpm-wrapped')}; "
                f"printf %s {shlex.quote(script)} > {shlex.quote(content + '/bin/php-fpm')}; "
                f"chmod 755 {shlex.quote(content + '/bin/php-fpm')}"
            )
            path = (
                self.native(f"{NIX}/nix-store --add {shlex.quote(content)}")
                .strip()
                .splitlines()[-1]
            )
        finally:
            self.native(f"rm -rf {shlex.quote(parent)}")
        self.added_builds.append(path)
        self.assertIn("/nix/store/", path)
        self.assertTrue(path.endswith("-" + base))
        return path

    def fixture(self, path: str, version: str) -> dict[str, object]:
        architecture = runtime_catalog.architecture_of(self.native("uname -m").strip())
        if architecture is None:
            self.fail("No supported architecture.")
        document: dict[str, object] = json.loads(self.original_lock.read_text())
        entries = cast(dict[str, dict[str, object]], document["entries"])
        builds = cast(dict[str, dict[str, object]], entries["php84"]["builds"])
        entry = builds[str(architecture)]
        retired = cast(list[dict[str, object]], document["retired"])
        retired.append(
            {
                **entry,
                "entry": "php84",
                "kind": "php",
                "architecture": str(architecture),
                "nixpkgs": document["nixpkgs"],
            }
        )
        document["nixpkgs"] = "1" * 40
        builds[str(architecture)] = {**entry, "path": path, "version": version}
        return document

    def use_catalog(self, document: dict[str, object]) -> None:
        self.fixture_directory = tempfile.mkdtemp()
        fixture = Path(self.fixture_directory) / "catalog_lock.json"
        fixture.write_text(json.dumps(document))
        runtime_catalog.LOCK_PATH = fixture
        runtime_catalog.load.cache_clear()
        for module in (
            site_observation,
            php_change,
            runtime_update,
            runtime_remove,
            runtime_revert,
        ):
            importlib.reload(module)

    def start_requests(self) -> None:
        self.native(
            f"install -d -m 755 {REQUESTS}; rm -f {REQUESTS}/*; "
            "systemd-run --collect --unit=s386cat-client-requests -- /bin/sh -c "
            + shlex.quote(
                "count=0; failures=0; "
                f"while [ ! -e {REQUESTS}/stop ]; do "
                "code=$(curl --silent --output /dev/null --write-out '%{http_code}' "
                f"--header 'Host: {self.site}.example.com' http://127.0.0.1/ || echo 000); "
                'count=$((count + 1)); [ "$code" = 200 ] || failures=$((failures + 1)); '
                'done; printf \'%s %s\\n\' "$count" "$failures" >'
                f"{REQUESTS}/result"
            )
        )
        time.sleep(1)

    def stop_requests(self) -> None:
        self.native(f"touch {REQUESTS}/stop")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.native(f"cat {REQUESTS}/result 2>/dev/null || true").strip()
            if result:
                self.requests, failures = result.split()
                self.failures = int(failures)
                return
            time.sleep(0.2)
        self.fail("The request loop did not report.")

    def assert_no_failures(self) -> None:
        self.assertEqual(self.failures, 0, f"{self.failures} of {self.requests} requests failed")
        self.assertGreater(int(self.requests), 0)


@tag(SCENARIO_TAG)
class CatalogRuntimeUpdate(CatalogScenario):
    prefix = "s386cat"
    site = "s386cat"

    def test_update_moves_a_live_site_without_refused_requests_and_removes_an_unused_runtime(
        self,
    ) -> None:
        self.create_site()
        fake = self.add_build(self.original_php84)
        self.use_catalog(self.fixture(fake, "8.4.26"))
        before = self.native(
            f"systemctl show caddy.service haproxy-site@{self.site}.service "
            "-p MainPID -p InvocationID"
        )
        self.start_requests()
        try:
            review = apply_change(
                self, runtime_update.UPDATE_CATALOG, PreparationInputs(), timeout=120
            )
        finally:
            self.stop_requests()
        self.assert_no_failures()
        self.assertEqual(self.runtime_version(), "8.4")
        self.assertEqual(self.native(f"readlink -f {PROFILE}/php84").strip(), fake)
        self.assertEqual(review.document["entries"][0]["entry"], "php84")
        self.assertGreaterEqual(
            len(
                self.native(
                    f"{NIX}/nix-env --profile {PROFILE}/php84 --list-generations"
                ).splitlines()
            ),
            2,
        )
        self.native(f"{NIX}/nix-store --check-validity {shlex.quote(self.original_php84)}")
        self.assertEqual(self.native("systemctl is-active php-fpm@php84.service").strip(), "active")
        # The PHP update never restarts Caddy or the site's private proxy.
        self.assertEqual(
            self.native(
                f"systemctl show caddy.service haproxy-site@{self.site}.service "
                "-p MainPID -p InvocationID"
            ),
            before,
        )
        used = runtime_remove.review(self.shell_for_runtime("php84"), PreparationInputs("php84"))
        self.assertFalse(used.eligible)
        self.assertIn(self.site, " ".join(used.refusals))
        removed = apply_change(
            self, runtime_remove.REMOVE_RUNTIME, PreparationInputs("php85"), timeout=120
        )
        self.assertEqual(removed.document["entry"], "php85")
        self.native(f"test ! -e {PROFILE}/php85; test ! -e /etc/php-fpm/php85")


@tag(SCENARIO_TAG)
class CatalogRuntimeUpdateFailure(CatalogScenario):
    prefix = "s386catf"
    site = "s386catf"

    def test_a_broken_new_build_is_reported_incomplete_and_the_previous_generation_stays(
        self,
    ) -> None:
        self.create_site()
        broken = self.add_mismatched_build(self.original_php84)
        self.use_catalog(self.fixture(broken, "8.4.26"))
        apply_change(
            self,
            runtime_update.UPDATE_CATALOG,
            PreparationInputs(),
            timeout=120,
            expected="partial",
        )
        self.assertEqual(self.native(f"readlink -f {PROFILE}/php84").strip(), broken)
        self.assertEqual(self.runtime_version(), "8.5")
        generations = self.native(f"{NIX}/nix-env --profile {PROFILE}/php84 --list-generations")
        self.assertGreaterEqual(len(generations.splitlines()), 2)
        self.native(f"{NIX}/nix-store --check-validity {shlex.quote(self.original_php84)}")
