"""Prove the current release keeps managing a server the v0.4.0 release built.

docs/v1.0-qualification.md and docs/quality.md#native-layer. ``PrepareV040`` boots the
ordinary L0 snapshot and runs the ``v0.4.0`` tag's own controller from a detached worktree
against it: the host foundation, both PHP runtimes and one plain site. It commits that
server as the keyed ``V040`` layer, so the compatibility scenario starts from native
v0.4.0 evidence rather than a current snapshot relabelled.

``V040ServerCompatibility`` then uses this release to discover the fixture and apply one
ordinary change. It fingerprints the relevant native paths before discovery and asserts
they are unchanged afterwards, so no server-side edit can precede the change.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import override_settings, tag

from bootstrap.standing import Standing
from discovery.fakes import run_worker
from discovery.models import SiteState
from discovery.services import read_discovery, request_discovery
from operations.inputs import PreparationInputs
from servers.models import Server
from servers.registration import SaveOutcome, save_server
from servers.ssh_config import ConnectionTarget
from sites.php_change import SET_SITE_PHP

from . import images
from .change_testing import apply_change
from .docker import docker
from .foundation_testing import assert_foundation_runtimes
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

V040_IDENTIFIER = "v040fixture"
V040_DOMAIN = "v040fixture.example.com"
GIT = shutil.which("git") or "git"

# The controller runs from the tag's own worktree with this release's interpreter: the tag
# and this release declare the same dependencies, and every project import resolves from the
# worktree because the subprocess starts there. It drives the tag's four-member change
# engine directly, then reads the site back through a fresh SSH connection.
_V040_CONTROLLER = """
import json
import os
import shlex
import time
from contextlib import contextmanager

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from bootstrap import foundation
from bootstrap.standing import Standing
from dashboard.settings_views import barectl_version
from discovery.observations import collect
from discovery.ssh import connect_alias
from disposable.change_testing import apply_change
from operations.inputs import PreparationInputs
from runtimes import change as runtime_change
from sites import change as site_change

identifier = os.environ["V040_IDENTIFIER"]
domain = os.environ["V040_DOMAIN"]


class Controller:
    @contextmanager
    def shell(self):
        os.environ["SSH_AUTH_SOCK"] = ""
        with connect_alias("v040") as connection:
            yield connection

    def wait_for_target_stack(self, timeout=60):
        end = time.monotonic() + timeout
        while True:
            with self.shell() as shell:
                standing = collect(shell, sites=False).standing
            if standing is not None and standing.standing is Standing.TARGET_STACK:
                return
            if time.monotonic() >= end:
                raise AssertionError(f"The host did not become the target stack: {standing}")
            time.sleep(0.5)

    def assertTrue(self, value, message=""):
        if not value:
            raise AssertionError(str(message))

    def assertEqual(self, first, second, message=""):
        if first != second:
            raise AssertionError(f"{first!r} != {second!r}: {message}")

    def fail(self, message):
        raise AssertionError(message)


controller = Controller()
version = barectl_version()
if version != "0.4.0":
    raise AssertionError(f"The detached worktree is not the v0.4.0 product: {version}")

apply_change(controller, foundation.HOST_FOUNDATION, PreparationInputs(), timeout=180)
for entry in ("php84", "php85"):
    apply_change(controller, runtime_change.ADD_RUNTIME, PreparationInputs(entry), timeout=180)
apply_change(
    controller,
    site_change.CREATE_SITE,
    PreparationInputs("php84", identifier, (domain,)),
    timeout=180,
)

with controller.shell() as shell:
    served = shell.run(
        "curl --fail --silent -H " + shlex.quote("Host: " + domain) + " http://127.0.0.1/"
    )
if served.exit_status != 0 or identifier not in served.stdout:
    raise AssertionError(
        f"The v0.4.0 site did not serve its marker: {served.exit_status} {served.stdout!r}"
    )

print(json.dumps({"version": version, "identifier": identifier, "domain": domain}))
"""

# Stat metadata, symlink targets and sizes for every native path a product change owns.
# Discovery reads these paths; a write would change a size, mode, owner or mtime.
_NATIVE_FINGERPRINT = r"""
set -e
for root in \
    /etc/caddy /etc/haproxy /etc/php-fpm /etc/systemd/system \
    /etc/passwd /etc/group /etc/shadow /etc/sudoers.d \
    /var/lib/caddy /var/lib/haproxy /var/lib/php-fpm /var/www \
    /nix/var/nix/profiles/barectl \
    /usr/local/bin /usr/local/libexec /usr/local/sbin /run/barectl; do
    if [ -e "$root" ] || [ -L "$root" ]; then
        find "$root" -xdev -printf '%p|%y|%m|%u|%g|%s|%T@|%l\n' 2>/dev/null | sort
    else
        echo "absent|$root"
    fi
done
"""


def _ssh_config(target: ConnectionTarget, path: Path) -> None:
    path.write_text(
        "Host v040\n"
        f"  HostName {target.hostname}\n"
        f"  Port {target.port}\n"
        f"  User {target.user}\n"
        f"  IdentityFile {target.identity_files[0]}\n"
        f"  UserKnownHostsFile {target.known_hosts_files[0]}\n",
        encoding="utf-8",
    )


@tag(SCENARIO_TAG)
class PrepareV040(ScenarioTestCase):
    """Build the v0.4.0 fixture from the tag itself and commit it as the V040 layer."""

    layer = "L0"
    exclusive = True
    prefix = ""
    preparation = True

    def test_commits_a_server_managed_by_the_v040_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="barectl-v040-") as directory:
            root = Path(directory)
            tree = root / "tree"
            self._tag_commit()
            added = subprocess.run(  # noqa: S603 - this repository's own git
                [GIT, "-C", str(images.REPOSITORY), "worktree", "add", "--detach",
                 str(tree), images.V040_COMMIT],
                check=False,
                capture_output=True,
                text=True,
            )  # fmt: skip
            try:
                if added.returncode != 0:
                    self.fail(
                        "The v0.4.0 worktree could not be created; the V040 fixture cannot "
                        "be built:\n" + added.stdout + added.stderr
                    )
                report = self._run_v040_controller(root, tree)
                self.assertEqual(report["version"], "0.4.0", report)
                served = self.native(
                    f"curl --fail --silent -H 'Host: {V040_DOMAIN}' http://127.0.0.1/"
                )
                self.assertIn(V040_IDENTIFIER, served)
                # The snapshot starts clean: the next boot regenerates host keys and the
                # harness reinstalls its own authorized key (as L1 does).
                self._commit_fixture()
            finally:
                subprocess.run(  # noqa: S603 - this repository's own git
                    [GIT, "-C", str(images.REPOSITORY), "worktree", "remove", "--force",
                     str(tree)],
                    check=False,
                    capture_output=True,
                    text=True,
                )  # fmt: skip
                shutil.rmtree(root, ignore_errors=True)

    def _commit_fixture(self) -> None:
        self.native("systemctl stop caddy.service nix-daemon.service nix-daemon.socket")
        self.native(
            "rm -f /root/.ssh/authorized_keys /etc/ssh/ssh_host_* /run/foundation-admin-listeners"
        )
        image = images.tag("V040")
        if not images.exists(image):
            docker(
                "commit",
                "--change",
                f"LABEL barectl.v040-commit={images.V040_COMMIT}",
                os.environ["BARECTL_SSH_TEST_CONTAINER"],
                image,
                timeout=60,
            )
        self.assertEqual(images.ensure("V040"), image)

    def _tag_commit(self) -> None:
        resolved = subprocess.run(  # noqa: S603 - this repository's own git
            [GIT, "-C", str(images.REPOSITORY), "rev-parse",
             f"{images.V040_TAG}^{{commit}}"],
            check=False,
            capture_output=True,
            text=True,
        )  # fmt: skip
        commit = resolved.stdout.strip()
        if resolved.returncode != 0 or commit != images.V040_COMMIT:
            self.fail(
                f"The {images.V040_TAG} tag is missing or is not {images.V040_COMMIT}; "
                "fetch tags (CI uses fetch-depth: 0) before preparing V040.\n"
                + resolved.stdout
                + resolved.stderr
            )

    def _run_v040_controller(self, root: Path, tree: Path) -> dict[str, object]:
        target = self.target()
        configuration = root / "ssh_config"
        _ssh_config(target, configuration)
        environment = os.environ | {
            "BARECTL_SSH_CONFIG": str(configuration),
            "BARECTL_SSH_KNOWN_HOSTS": str(target.known_hosts_files[0]),
            "SSH_AUTH_SOCK": "",
            "DJANGO_SETTINGS_MODULE": "config.settings",
            "V040_IDENTIFIER": V040_IDENTIFIER,
            "V040_DOMAIN": V040_DOMAIN,
        }
        result = subprocess.run(  # noqa: S603 - the tag's own controller
            [sys.executable, "-c", _V040_CONTROLLER],
            cwd=tree,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=170,
        )
        if result.returncode != 0:
            self.fail(
                "The v0.4.0 controller could not build the fixture; the V040 snapshot "
                "cannot be produced:\n" + result.stdout + result.stderr
            )
        lines = result.stdout.splitlines()
        if not lines:
            self.fail("The v0.4.0 controller reported no result.")
        value = json.loads(lines[-1])
        if not isinstance(value, dict):
            self.fail("The v0.4.0 controller reported no result object.")
        return value


@tag(SCENARIO_TAG)
class V040ServerCompatibility(ScenarioTestCase):
    """Discover and change a server that the v0.4.0 release created."""

    layer = "V040"
    exclusive = True
    prefix = V040_IDENTIFIER

    def test_current_release_discovers_and_changes_a_v040_managed_server(self) -> None:
        before = self.native(_NATIVE_FINGERPRINT)
        target = self.target()
        user = get_user_model().objects.create_superuser(username="scenario")
        with tempfile.TemporaryDirectory(prefix="barectl-v040-compat-") as directory:
            configuration = Path(directory) / "ssh_config"
            _ssh_config(target, configuration)
            with (
                override_settings(
                    SSH_CONFIG_PATH=str(configuration),
                    SSH_KNOWN_HOSTS_PATH=str(target.known_hosts_files[0]),
                ),
                _no_agent(),
            ):
                server = Server(name="V040 fixture", ssh_alias="v040")
                self.assertEqual(save_server(server, user=user), SaveOutcome.QUEUED)
                run_worker()
                discovered = read_discovery(server)
                if discovered.snapshot is None:
                    attempt = discovered.attempt
                    self.fail(
                        "Current discovery could not reconstruct the v0.4.0 server: "
                        + (attempt.failure if attempt is not None else "no attempt")
                    )
                snapshot = discovered.snapshot.collected
                after = self.native(_NATIVE_FINGERPRINT)
                self.assertEqual(after, before, "Discovery wrote to the fixture server.")

                if snapshot.standing is None:
                    self.fail("Current discovery did not judge the fixture's host standing.")
                self.assertEqual(
                    snapshot.standing.standing, Standing.TARGET_STACK, snapshot.standing.reasons
                )
                assert_foundation_runtimes(self, snapshot)
                defaults = snapshot.runtime_defaults
                if defaults is None:
                    self.fail("Current discovery did not read the server's runtime defaults.")
                self.assertEqual(defaults.php_choices, ("php84", "php85"))
                sites = {site.identifier: site for site in snapshot.sites.value}
                self.assertIn(V040_IDENTIFIER, sites, snapshot.sites.warning)
                site = sites[V040_IDENTIFIER]
                self.assertEqual(site.state, SiteState.MANAGED, site)
                self.assertEqual(site.php_version, "php84", site)
                self.assertEqual(site.server_names, (V040_DOMAIN,), site)
                self.assertIsNotNone(site.account, site)

                apply_change(self, SET_SITE_PHP, PreparationInputs("php85", V040_IDENTIFIER))
                served = self.native(
                    f"curl --fail --silent -H 'Host: {V040_DOMAIN}' http://127.0.0.1/"
                )
                self.assertIn(V040_IDENTIFIER, served)

                request_discovery(server)
                run_worker()
                refreshed = read_discovery(server).snapshot
                if refreshed is None:
                    self.fail("Current discovery lost the fixture after the change.")
                sites = {row.identifier: row for row in refreshed.collected.sites.value}
                self.assertIn(V040_IDENTIFIER, sites, refreshed.collected.sites.warning)
                self.assertEqual(sites[V040_IDENTIFIER].php_version, "php85")


@contextmanager
def _no_agent() -> Iterator[None]:
    """Keep the controller's discovery away from the developer's SSH agent."""
    previous = os.environ.get("SSH_AUTH_SOCK")
    os.environ["SSH_AUTH_SOCK"] = ""
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SSH_AUTH_SOCK", None)
        else:
            os.environ["SSH_AUTH_SOCK"] = previous
