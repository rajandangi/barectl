"""The draft apply payload a site plan must fit, built at preparation (docs/sites.md#applying)."""

import hashlib
import shutil
import subprocess
from dataclasses import replace

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native

from . import native
from .convention import SitePaths, render_placeholder, render_pool, render_probe, render_site
from .names import MAX_NAME_OCTETS, MAX_NAMES

UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
PROBE = "0123456789abcdef0123456789abcdef"
SHELL = shutil.which("dash") or shutil.which("sh")


def change(identifier: str, names: tuple[str, ...], php: str = "8.3") -> native.SiteChange:
    paths = SitePaths(identifier, php)

    def generated(path: str, owner: str, group: str, mode: str, text: str) -> native.GeneratedFile:
        directory, _, name = path.rpartition("/")
        return native.GeneratedFile(directory, name, owner, group, mode, text)

    return native.SiteChange(
        paths=paths,
        names=names,
        ipv6=True,
        token=PROBE,
        digest="d" * 64,
        uid_range=(1000, 60000),
        gid_range=(1000, 60000),
        placeholder=generated(
            paths.placeholder, paths.user, "www-data", "0640", render_placeholder(identifier)
        ),
        probe=generated(paths.probe(PROBE), "root", paths.user, "0640", render_probe(PROBE)),
        pool=generated(paths.pool, "root", "root", "0644", render_pool(identifier)),
        site=generated(
            paths.source, "root", "root", "0644", render_site(identifier, names, ipv6=True)
        ),
    )


def longest() -> native.SiteChange:
    label = "a" * (MAX_NAME_OCTETS - len(".example") - 1)
    names = tuple(f"{label}{index}.example" for index in range(MAX_NAMES))
    return change("a" * 24, names, "8.5")


class PayloadTests(SimpleTestCase):
    def test_the_maximum_admitted_request_fits_one_submission_with_headroom(self) -> None:
        maximum = longest()
        self.assertTrue(all(len(name) == MAX_NAME_OCTETS for name in maximum.names))
        payload = native.site_payload(UNIT, BOOT, 10**12, maximum)
        self.assertLessEqual(len(payload.encode()), bootstrap_native.MAX_PAYLOAD - 2048)
        # The submission itself accepts it.
        bootstrap_native.submission(UNIT, payload)

    def test_the_payload_is_valid_shell(self) -> None:
        payload = native.site_payload(UNIT, BOOT, 10**12, longest())
        self.assertIsNotNone(SHELL)
        result = subprocess.run(  # noqa: S603 - a syntax check of the tests' own payload
            [SHELL or "sh", "-n", "-c", payload], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_fragments_are_ordered_and_name_every_boundary(self) -> None:
        steps = native.site_steps(UNIT, BOOT, 10**12, longest())
        self.assertEqual(
            [step.name for step in steps],
            [
                "admission",
                "helpers",
                "revalidation",
                "account",
                "directories",
                "placeholder",
                "probe",
                "document root",
                "pool",
                "pool validation",
                "pool reload",
                "site file",
                "site link",
                "site validation",
                "site reload",
                "serving",
                "probe removal",
            ],
        )
        payload = native.site_payload(UNIT, BOOT, 10**12, longest())
        for name, code in vars(native.Exit).items():
            if name.isupper():
                self.assertRegex(payload, rf"(exit|x) {int(code)}\b", name)

    def test_the_payload_rechecks_the_same_digest_command_as_preparation(self) -> None:
        maximum = longest()
        payload = native.site_payload(UNIT, BOOT, 10**12, maximum)
        read = native.script(native.site_digest(maximum.paths))
        self.assertEqual(read[:2], ["/usr/bin/sh", "-c"])
        self.assertIn(f'[ "$({read[2]} | cut -d" " -f1)" = {"d" * 64} ]', payload)

    def test_published_bytes_are_checked_against_their_reviewed_digest(self) -> None:
        maximum = longest()
        payload = native.site_payload(UNIT, BOOT, 10**12, maximum)
        for item in (maximum.site, maximum.pool, maximum.placeholder, maximum.probe):
            self.assertEqual(item.sha256, hashlib.sha256(item.text.encode()).hexdigest())
            self.assertIn(item.sha256, payload)

    def test_parameters_are_validated(self) -> None:
        maximum = longest()
        with self.assertRaises(ValueError):
            native.site_payload(UNIT, BOOT, 1, replace(maximum, digest="x"))
        with self.assertRaises(ValueError):
            native.site_payload(UNIT, BOOT, 1, replace(maximum, names=("a.example; reboot",)))
        with self.assertRaises(ValueError):
            native.site_payload(UNIT, BOOT, 1, replace(maximum, uid_range=(0, 10)))
        with self.assertRaises(ValueError):
            native.site_payload("unit; reboot", BOOT, 1, maximum)
        with self.assertRaises(ValueError):
            native.content("/etc/shadow")
