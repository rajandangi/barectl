"""The WordPress installation's native body: its text, archive admission and verification read
(docs/wordpress.md#applying-an-installation).

Pure tests. ``wordpress/test_install_apply_remote.py`` establishes the native behaviour on both
releases.
"""

import base64
import gzip
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import replace
from pathlib import Path

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native
from bootstrap.native import UnitEvidence
from bootstrap.models import Execution

from . import convention, core_native, install_apply, install_native
from .models import PlanWordpressInstall

SHELL = shutil.which("dash") or shutil.which("sh") or "sh"
UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
SUFFIX = "a" * 32
DIGEST = "e" * 64
GATE = "# gate\n"
READY = "# ready\n"


def row(**changes: object) -> PlanWordpressInstall:
    base = PlanWordpressInstall(
        identifier="shop",
        php_version="8.3",
        php_supply="ubuntu",
        site_revision=4,
        site_user="sshop",
        uid=1003,
        gid=1003,
        socket="/run/php/sshop-php8.3.sock",
        ipv6=True,
        names="shop.test www.shop.test",
        canonical_name="www.shop.test",
        url="https://www.shop.test",
        title="Shop & Sons",
        admin_login="owner",
        admin_email="owner@example.com",
        certificate_sha256="c" * 64,
        certificate_not_after="Oct 1 2027",
        tool_version="2.12.0",
        tool_path="/usr/local/lib/wp-cli/wp-cli-2.12.0.phar",
        tool_sha256="d" * 64,
        core_version=core_native.VERSION,
        core_locale=core_native.LOCALE,
        archive_url=core_native.ARCHIVE_URL,
        archive_bytes=core_native.ARCHIVE_BYTES,
        archive_sha256=core_native.ARCHIVE_SHA256,
        max_archive_bytes=core_native.MAX_ARCHIVE_BYTES,
        max_tree_bytes=core_native.MAX_TREE_BYTES,
        max_entries=core_native.MAX_ENTRIES,
        max_file_bytes=core_native.MAX_FILE_BYTES,
        memory_max_bytes=core_native.MEMORY_MAX_BYTES,
        runtime_limit_seconds=core_native.RUNTIME_LIMIT_SECONDS,
        preimage_sha256="b" * 64,
        gate_sha256=install_native.digest(GATE),
        gate_content=GATE,
        ready_sha256=install_native.digest(READY),
        ready_content=READY,
        placeholder_sha256="a" * 64,
        placeholder_present=True,
        loader_sha256="f" * 64,
        public_root="/var/www/shop/public",
        private_configuration="/var/www/shop/private/wp-config.php",
        database_name="sshop",
        engine_other=False,
        body_sha256="",
        payload_bytes=None,
    )
    for name, value in changes.items():
        setattr(base, name, value)
    return base


def evidence() -> install_native.Evidence:
    return install_native.Evidence(*([DIGEST] * 8))


def syntax(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "script"
        script.write_text(text)
        return subprocess.run(  # noqa: S603 - a syntax check of the tests' own scripts
            [SHELL, "-n", str(script)], capture_output=True, text=True, check=False
        )


class BodyTests(SimpleTestCase):
    def test_the_body_and_its_payload_are_valid_shell(self) -> None:
        body = install_native.body(row(), evidence(), "24.04")
        payload = install_native.payload(UNIT, BOOT, 123456, row(), evidence(), "24.04")
        for name, text in (("body", body), ("payload", payload)):
            result = syntax(text)
            self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")

    def test_the_fragments_run_in_the_documented_order(self) -> None:
        steps = [step.name for step in install_native.body_steps(row(), evidence(), "24.04")]
        self.assertEqual(
            steps,
            [
                "helpers",
                "tools",
                "revalidation",
                "stage",
                "download",
                "archive",
                "extract",
                "checksums",
                "gate",
                "publish",
                "placeholder",
                "loader",
                "configuration",
                "install",
                "schema",
                "integrity",
                "access",
                "ready",
                "serving",
                "finish",
            ],
        )

    def test_nothing_changes_before_the_artifact_is_admitted_and_the_gate_verified(self) -> None:
        steps = {s.name: s.text for s in install_native.body_steps(row(), evidence(), "24.04")}
        before = "; ".join(
            steps[name]
            for name in ("tools", "revalidation", "download", "archive", "extract", "checksums")
        )
        # The staging area is the only thing created, and no routing or public file is touched.
        for forbidden in ('mv -T -- "$sn"', "systemctl reload", "ln -T", 'chown "$u:www-data"'):
            self.assertNotIn(forbidden, before)
        self.assertLess(steps["gate"].index("gate verified"), len(steps["gate"]))
        self.assertIn("until gv", steps["gate"])
        publication = [
            "publish",
            "placeholder",
            "loader",
            "configuration",
            "install",
        ]
        self.assertTrue(all(name in steps for name in publication))

    def test_every_step_that_changes_the_server_names_its_exit_boundary(self) -> None:
        steps = {s.name: s.text for s in install_native.body_steps(row(), evidence(), "24.04")}
        for name, status in {
            "download": install_native.Exit.DOWNLOAD,
            "archive": install_native.Exit.ARCHIVE,
            "extract": install_native.Exit.EXTRACT,
            "gate": install_native.Exit.GATE,
            "publish": install_native.Exit.PUBLISH,
            "loader": install_native.Exit.LOADER,
            "configuration": install_native.Exit.CONFIGURATION,
            "install": install_native.Exit.INSTALL,
            "schema": install_native.Exit.SCHEMA,
            "integrity": install_native.Exit.INTEGRITY,
            "access": install_native.Exit.ACCESS,
            "ready": install_native.Exit.READY,
        }.items():
            self.assertIn(f"exit {status}", steps[name], name)

    def test_the_body_depends_only_on_the_review(self) -> None:
        first = install_native.body(row(), evidence(), "24.04")
        second = install_native.body(row(), evidence(), "24.04")
        self.assertEqual(first, second)
        other = install_native.body(row(title="Another"), evidence(), "24.04")
        self.assertNotEqual(first, other)
        self.assertNotIn(UNIT, first)

    def test_the_title_and_login_are_quoted_as_data(self) -> None:
        body = install_native.body(
            row(title="x'; touch /tmp/owned; '", admin_login="owner"), evidence(), "24.04"
        )
        self.assertEqual(syntax(body).returncode, 0)
        self.assertIn("'--title=x'\"'\"'; touch /tmp/owned; '\"'\"''", body)

    def test_a_review_that_is_not_the_convention_is_refused(self) -> None:
        for changes in (
            {"canonical_name": "other.test"},
            {"url": "http://www.shop.test"},
            {"database_name": "swp"},
            {"public_root": "/var/www/other/public"},
            {"socket": "/run/php/other.sock"},
            {"uid": 0},
            {"gate_content": "tampered"},
            {"preimage_sha256": "short"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                install_native.body(row(**changes), evidence(), "24.04")
        with self.assertRaises(ValueError):
            install_native.body(row(), replace(evidence(), site="x"), "24.04")
        with self.assertRaises(ValueError):
            install_native.body(row(), evidence(), "20.04")

    def test_the_unit_suffix_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            install_native.payload("barectl-apply-x.service", BOOT, 1, row(), evidence(), "24.04")


class StagedBodyTests(SimpleTestCase):
    def test_the_payload_carries_a_body_that_decodes_to_the_reviewed_text(self) -> None:
        body = install_native.body(row(), evidence(), "24.04")
        steps = bootstrap_native.staged(body)
        packed = steps[0].split("'")[1]
        self.assertEqual(gzip.decompress(base64.b64decode(packed)).decode(), body)
        self.assertIn(hashlib.sha256(body.encode()).hexdigest(), steps[1])
        self.assertEqual(steps[2], 'eval "$b"')

    def test_the_payload_is_deterministic_and_fits_the_native_limit(self) -> None:
        payload = install_native.payload(UNIT, BOOT, 123456, row(), evidence(), "24.04")
        again = install_native.payload(UNIT, BOOT, 123456, row(), evidence(), "24.04")
        self.assertEqual(payload, again)
        self.assertLess(len(payload.encode()), bootstrap_native.MAX_PAYLOAD)
        body = install_native.body(row(), evidence(), "24.04")
        self.assertLess(len(body.encode()), bootstrap_native.MAX_BODY)

    def test_the_decoder_runs_the_body_only_when_its_digest_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            body = f"echo ran > {marker}; exit 0"
            decoder = "; ".join(bootstrap_native.staged(body))
            subprocess.run([SHELL, "-c", decoder], check=True)  # noqa: S603
            self.assertEqual(marker.read_text(), "ran\n")
            marker.unlink()
            digest = hashlib.sha256(body.encode()).hexdigest()
            tampered = decoder.replace(digest, "0" * 64)
            result = subprocess.run([SHELL, "-c", tampered], check=False)  # noqa: S603
            self.assertEqual(result.returncode, bootstrap_native.Exit.DRIFT)
            self.assertFalse(marker.exists())

    def test_a_body_that_cannot_be_staged_is_refused(self) -> None:
        for body in (
            "",
            "ends with a newline\n",
            "nul\0byte",
            "x" * (bootstrap_native.MAX_BODY + 1),
        ):
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                bootstrap_native.staged(body)

    def test_the_unit_limits_are_native_properties(self) -> None:
        argv = bootstrap_native.submission(UNIT, "true", limits=install_native.limits())
        self.assertIn(f"--property=LimitFSIZE={core_native.MAX_FILE_BYTES}", argv)
        self.assertIn(f"--property=MemoryMax={core_native.MEMORY_MAX_BYTES}", argv)
        self.assertIn("--property=MemorySwapMax=0", argv)
        self.assertLess(argv.index("--property=MemoryMax=536870912"), argv.index("/usr/bin/sh"))
        plain = bootstrap_native.submission(UNIT, "true")
        self.assertFalse([item for item in plain if "LimitFSIZE" in item or "MemoryMax" in item])
        for limits in (bootstrap_native.Limits(0, 1), bootstrap_native.Limits(1, -1)):
            with self.assertRaises(ValueError):
                limits.properties()


def archive(
    members: list[tuple[str, bytes | None, int]], *, types: dict[str, bytes] | None = None
) -> bytes:
    """A gzip tar of ``members``: (name, content or None for a directory, mode)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content, mode in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        for name, kind in (types or {}).items():
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "wordpress/index.php"
            tar.addfile(info)
    return buffer.getvalue()


class AdmissionTests(SimpleTestCase):
    """The archive's admission script, as the site user runs it on the server."""

    def admit(
        self, data: bytes, *, entries: int = 100, tree: int = 10_000, single: int = 5_000
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar.gz"
            path.write_bytes(data)
            return subprocess.run(  # noqa: S603 - the tests' own script on the tests' own archive
                [
                    sys.executable,
                    "-I",
                    "-c",
                    install_native.ADMISSION,
                    str(path),
                    *map(str, (entries, tree, single)),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def good(self) -> list[tuple[str, bytes | None, int]]:
        return [
            ("wordpress/", None, 0o755),
            ("wordpress/index.php", b"<?php\n", 0o644),
            ("wordpress/wp-content/", None, 0o755),
            ("wordpress/wp-content/themes/a,b-1.2@x/style.css", b"/* */", 0o644),
        ]

    def test_a_plain_tree_under_the_prefix_is_admitted(self) -> None:
        result = self.admit(archive(self.good()))
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "entries 4 bytes 11"))

    def test_links_devices_and_special_files_are_refused(self) -> None:
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                data = archive(self.good(), types={"wordpress/link": kind})
                self.assertEqual(self.admit(data).returncode, 5)

    def test_names_outside_the_prefix_or_with_traversal_are_refused(self) -> None:
        for name in (
            "other/index.php",
            "/etc/passwd",
            "wordpress/../etc/passwd",
            "wordpress/a/../b",
            "wordpress//x",
            "wordpress/./x",
            "../wordpress/x",
            "wordpress-extra/x",
        ):
            with self.subTest(name=name):
                data = archive([(name, b"x", 0o644)])
                self.assertEqual(self.admit(data).returncode, 3)

    def test_unsafe_characters_and_mode_bits_are_refused(self) -> None:
        for name in (
            "wordpress/a b",
            "wordpress/a;b",
            "wordpress/$x",
            "wordpress/a\nb",
            "wordpress/é",
        ):
            with self.subTest(name=name):
                self.assertEqual(self.admit(archive([(name, b"x", 0o644)])).returncode, 3)
        for mode in (0o4755, 0o2755, 0o1755):
            with self.subTest(mode=oct(mode)):
                self.assertEqual(self.admit(archive([("wordpress/x", b"x", mode)])).returncode, 3)

    def test_the_reviewed_limits_refuse_a_larger_archive(self) -> None:
        data = archive(self.good())
        self.assertEqual(self.admit(data, entries=3).returncode, 3)
        self.assertEqual(self.admit(data, tree=10).returncode, 6)
        self.assertEqual(self.admit(data, single=4).returncode, 4)

    def test_an_archive_that_is_not_a_gzip_tar_is_refused(self) -> None:
        self.assertNotEqual(self.admit(b"not an archive").returncode, 0)
        self.assertNotEqual(self.admit(b"").returncode, 0)


class OperativeFilesTests(SimpleTestCase):
    def test_the_private_configuration_is_the_convention_with_server_made_salts(self) -> None:
        head, tail = install_native.split_configuration("shop")
        salts = ["a1" * 32] * len(convention.SALTS)
        built = (
            head
            + "".join(
                f"define( '{key}', '{salt}' );\n"
                for key, salt in zip(convention.SALTS, salts, strict=True)
            )
            + tail
        )
        self.assertEqual(built, convention.render_private_configuration("shop", salts))
        self.assertIn("define( 'DB_PASSWORD', '' );", head)
        self.assertTrue(tail.startswith("$table_prefix"))

    def test_the_schema_expectation_covers_each_core_table(self) -> None:
        digest = install_native.expected_schema_digest("sshop")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(len(convention.CORE_TABLES), 12)
        self.assertEqual(
            install_native.expected_options("https://a.test"),
            "home\thttps://a.test\nsiteurl\thttps://a.test\n",
        )
        with self.assertRaises(ValueError):
            install_native.table_count_command("sshop'; DROP")

    def test_the_probe_names_its_token_by_file_and_loads_wordpress(self) -> None:
        text = install_native.render_probe("shop")
        self.assertIn("require '/var/www/shop/public/wp-load.php';", text)
        self.assertIn('substr(basename(__FILE__,".php"),10)', text)
        self.assertEqual("wpinstall-"[:10], "wpinstall-")
        token = "a" * 32
        path = install_native.probe_path("shop", token)
        self.assertEqual(Path(path).name[10:-4], token)
        with self.assertRaises(ValueError):
            install_native.probe_path("shop", "short")

    def test_the_install_script_feeds_the_prompt_from_one_process(self) -> None:
        script = install_native.INSTALL_SCRIPT
        self.assertIn("/dev/urandom", script)
        self.assertIn('printf "%s\\n" "$p" | "$@" >/dev/null 2>&1', script)
        self.assertIn("unset p", script)
        self.assertNotIn("export", script)
        self.assertNotIn("echo", script)
        self.assertEqual(syntax(script).returncode, 0)


class OutcomeTests(SimpleTestCase):
    def evidence(self, status: int, **changes: object) -> UnitEvidence:
        base = UnitEvidence(
            unit=UNIT,
            boot_id=BOOT,
            found=True,
            active_state="failed",
            sub_state="failed",
            result="exit-code",
            exec_main_code=1,
            exec_main_status=status,
            invocation_id="1" * 32,
            populated=False,
        )
        return replace(base, **changes)

    def test_each_status_maps_to_one_execution(self) -> None:
        Exit = install_native.Exit
        for status in install_native.ARTIFACT_REFUSALS:
            self.assertEqual(
                install_apply.execution(self.evidence(status)), Execution.ARTIFACT_REFUSED
            )
        for status in install_native.PARTIAL:
            self.assertEqual(install_apply.execution(self.evidence(status)), Execution.PARTIAL)
        mapped = {
            Exit.GATE: Execution.GATE_REFUSED,
            Exit.GATE_NOT_SERVING: Execution.GATE_REFUSED,
            Exit.NOT_SERVING: Execution.NOT_SERVING,
            Exit.EXPOSED: Execution.EXPOSURE_UNCERTAIN,
            Exit.DRIFT: Execution.DRIFT,
            bootstrap_native.Exit.LOCK_CONFLICT: Execution.LOCK_CONFLICT,
            bootstrap_native.Exit.BOOT_CHANGED: Execution.BOOT_CHANGED,
            bootstrap_native.Exit.EXPIRED: Execution.EXPIRED,
            bootstrap_native.Exit.RENEWAL_ACTIVE: Execution.RENEWAL_ACTIVE,
            143: Execution.FAILED,
        }
        for status, execution in mapped.items():
            self.assertEqual(install_apply.execution(self.evidence(status)), execution, status)

    def test_a_signal_a_timeout_and_a_running_unit_keep_their_native_outcome(self) -> None:
        killed = self.evidence(0, exec_main_code=2)
        self.assertEqual(install_apply.execution(killed), Execution.KILLED)
        timeout = self.evidence(143, result="timeout")
        self.assertEqual(install_apply.execution(timeout), Execution.TIMED_OUT)
        running = self.evidence(0, active_state="active", sub_state="running", populated=True)
        self.assertEqual(install_apply.execution(running), Execution.RUNNING)
        self.assertEqual(
            install_apply.execution(self.evidence(0, found=False)), Execution.NOT_FOUND
        )
        ok = self.evidence(0, active_state="active", sub_state="exited", result="success")
        self.assertEqual(install_apply.execution(ok), Execution.SUCCEEDED)

    def test_the_artifact_refusals_and_the_gate_restorations_change_nothing(self) -> None:
        refused = Execution.refused_before_changes()
        self.assertIn(Execution.ARTIFACT_REFUSED, refused)
        self.assertIn(Execution.GATE_REFUSED, refused)
        for execution in (Execution.PARTIAL, Execution.NOT_SERVING, Execution.EXPOSURE_UNCERTAIN):
            self.assertNotIn(execution, refused)

    def test_the_exit_statuses_are_distinct_and_clear_of_bootstrap_statuses(self) -> None:
        own = {
            value
            for name, value in vars(install_native.Exit).items()
            if name.isupper() and name != "DRIFT"
        }
        self.assertEqual(len(own), len([n for n in vars(install_native.Exit) if n.isupper()]) - 1)
        self.assertFalse(own & {int(item) for item in bootstrap_native.Exit})
