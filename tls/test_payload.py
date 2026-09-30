"""The challenge route's apply payload (docs/tls.md#applying)."""

import shutil
import subprocess
from dataclasses import replace

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import SitePaths, Stage, render_site
from sites.names import MAX_NAME_OCTETS, MAX_NAMES

from . import native

UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
PROBE = "0123456789abcdef0123456789abcdef"
SHELL = shutil.which("dash") or shutil.which("sh")


def longest() -> native.ChallengeChange:
    label = "a" * (MAX_NAME_OCTETS - len(".example") - 1)
    names = tuple(f"{label}{index}.example" for index in range(MAX_NAMES))
    identifier = "a" * 24
    return native.ChallengeChange(
        paths=SitePaths(identifier, "8.5"),
        names=names,
        ipv6=True,
        token=PROBE,
        digest="d" * 64,
        preimage=render_site(identifier, names, ipv6=True),
        content=render_site(identifier, names, ipv6=True, stage=Stage.CHALLENGE),
    )


class ChallengePayloadTests(SimpleTestCase):
    def test_the_maximum_admitted_route_fits_one_submission(self) -> None:
        payload = native.challenge_payload(UNIT, BOOT, 10**12, longest())
        self.assertLessEqual(len(payload.encode()), bootstrap_native.MAX_PAYLOAD - 2048)
        bootstrap_native.submission(UNIT, payload)

    def test_the_payload_is_valid_shell_that_starts_nothing_in_the_background(self) -> None:
        payload = native.challenge_payload(UNIT, BOOT, 10**12, longest())
        result = subprocess.run(  # noqa: S603 - a syntax check of the tests' own payload
            [SHELL or "sh", "-n", "-c", payload], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("&", payload.replace("&&", "").replace(">&", "").replace(" & 022", ""))

    def test_the_fragments_are_ordered_and_name_every_boundary(self) -> None:
        steps = native.challenge_steps(UNIT, BOOT, 10**12, longest())
        self.assertEqual(
            [step.name for step in steps],
            [
                "admission",
                "helpers",
                "revalidation",
                "directories",
                "replacement",
                "validation",
                "reload",
                "probe",
                "serving",
                "probe removal",
            ],
        )
        payload = native.challenge_payload(UNIT, BOOT, 10**12, longest())
        for name, code in vars(native.Exit).items():
            if name.isupper():
                self.assertRegex(payload, rf"(exit|x) {int(code)}\b", name)
        # The backup exists before the file is replaced; nginx -t precedes the reload.
        order = [
            payload.index(text)
            for text in (">/var/backups/nginx/", "mv -T", "nginx -t -q", "systemctl reload")
        ]
        self.assertEqual(order, sorted(order))

    def test_the_payload_rechecks_the_site_digest_and_preimage(self) -> None:
        change = longest()
        payload = native.challenge_payload(UNIT, BOOT, 10**12, change)
        read = site_native.script(site_native.site_digest(change.paths))
        self.assertIn(f'[ "$({read[2]} | cut -d" " -f1)" = {"d" * 64} ]', payload)
        self.assertIn(change.preimage_sha256, payload)
        self.assertIn(change.content_sha256, payload)
        self.assertIn(f"/var/backups/nginx/{'a' * 24}.conf.{'a' * 32}", payload)

    def test_values_other_than_the_conventions_are_refused(self) -> None:
        change = longest()
        cases = {
            "digest": replace(change, digest="x"),
            "names": replace(change, names=("a.example; reboot",)),
            "token": replace(change, token="../x"),  # noqa: S106 - not a secret
            "preimage": replace(change, preimage=change.preimage + "# x\n"),
            "content": replace(change, content=change.preimage),
            "listeners": replace(change, ipv6=False),
        }
        for case, tampered in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                native.challenge_payload(UNIT, BOOT, 1, tampered)
        with self.assertRaises(ValueError):
            native.challenge_payload("unit; reboot", BOOT, 1, change)
