"""Shared runtime checks and canonical L1 snapshot cleanup."""

import os

from discovery.snapshot import CollectedSnapshot

from . import images
from .docker import docker
from .scenario_testing import ScenarioTestCase


def assert_foundation_runtimes(test: ScenarioTestCase, observed: CollectedSnapshot) -> None:
    test.assertEqual({row.entry for row in observed.runtimes}, {"php84", "php85"})
    test.assertTrue(
        all(row.manageable and row.master_state == "active" for row in observed.runtimes)
    )
    for entry in ("php84", "php85"):
        test.native(
            f"/nix/var/nix/profiles/barectl/{entry}/bin/php-fpm -t "
            f"-y /etc/php-fpm/{entry}/php-fpm.conf -c /etc/php-fpm/{entry}/php.ini"
        )
        test.assertIn("0600", test.native(f"stat -c '0%a' /run/php-fpm/{entry}/diagnostic.sock"))


def commit_foundation(test: ScenarioTestCase) -> None:
    test.native("systemctl stop caddy.service nix-daemon.service nix-daemon.socket")
    test.native(
        "rm -f /root/.ssh/authorized_keys /etc/ssh/ssh_host_* /run/foundation-admin-listeners"
    )
    image = images.tag("L1")
    if not images.exists(image):
        docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
    test.assertEqual(images.ensure("L1"), image)
    first = docker("image", "inspect", "--format", "{{.Id}}", image).strip()
    test.assertEqual(images.ensure("L1"), image)
    test.assertEqual(docker("image", "inspect", "--format", "{{.Id}}", image).strip(), first)
