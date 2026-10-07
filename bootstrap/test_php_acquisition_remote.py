"""Native isolated acquisition faults, using Ubuntu's authenticated hello package.

This qualifies the shared acquisition engine independently of PHP source admission and
does not establish Sury package or PHP runtime qualification.
"""

import os
import shlex
import subprocess
import time
from typing import override
from unittest import skipUnless

from django.test import SimpleTestCase, tag

from . import native

CONFIGURED = bool(os.environ.get("BARECTL_SSH_TEST_CONTAINER"))
FIXTURE = "/srv/barectl-acquisition-fixture"
SCOPE = "{ sha256sum /var/lib/dpkg/status; } 2>/dev/null | sha256sum"
HTTP_FIXTURE = r"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import time

root = Path("/srv/barectl-acquisition-fixture")

class ArchiveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        (root / "requested").write_text(self.path)
        mode = (root / "mode").read_text().strip()
        if mode == "wait":
            time.sleep(120)
        data = (root / ("bad.deb" if mode == "corrupt" else "good.deb")).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if mode == "partial":
            self.wfile.write(data[:64])
            self.wfile.flush()
            (root / "partial-sent").write_text("64")
            self.close_connection = True
            return
        self.wfile.write(data)

ThreadingHTTPServer(("127.0.0.1", 8752), ArchiveHandler).serve_forever()
"""


@tag("ssh")
@skipUnless(CONFIGURED, "Requires a disposable native Ubuntu server.")
class IsolatedArchiveAcquisitionTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.units: list[str] = []
        self.shared = ""
        self.addCleanup(self.clear)
        self.administer(
            "set -e; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq hello >/dev/null; "
            f"mkdir -p {FIXTURE}; cd {FIXTURE}; apt-get download hello >/dev/null; "
            "f=$(find . -maxdepth 1 -name 'hello_*.deb' -print -quit); "
            'cp "$f" good.deb; cp good.deb bad.deb; '
            "printf X | dd of=bad.deb bs=1 seek=100 conv=notrunc status=none; "
            "printf good >mode; rm -f requested hook-ran"
        )
        self.version, self.architecture = self.administer(
            f"dpkg-deb -f {FIXTURE}/good.deb Version; dpkg-deb -f {FIXTURE}/good.deb Architecture"
        ).splitlines()
        self.shared = (
            f"{native.ARCHIVES}hello_{self.version.replace(':', '%3a')}_{self.architecture}.deb"
        )
        self.administer(
            f"cat >{FIXTURE}/proxy.py <<'PY'\n{HTTP_FIXTURE}\nPY\n"
            "systemd-run --quiet --unit=barectl-acquisition-http "
            f"/usr/bin/python3 {FIXTURE}/proxy.py"
        )
        self.wait_for("ss -Hltn sport = :8752 | grep -q .")
        hook = (
            f"touch {FIXTURE}/hook-ran; echo acquisition-hook-before-guard; "
            "for d in /run/barectl-apt-*/archives; do "
            'stat -c \'%F %U %G %a\' "$d" "$d/partial"; done'
        )
        self.administer(f"cat >{FIXTURE}/hook.sh <<'HOOK'\n{hook}\nHOOK")
        configuration = (
            'Acquire::http::Proxy "http://127.0.0.1:8752";\n'
            f'DPkg::Pre-Install-Pkgs {{ "/usr/bin/sh {FIXTURE}/hook.sh"; }};\n'
        )
        self.administer(
            f"cat >/etc/apt/apt.conf.d/99barectl-acquisition-fixture <<'CONF'\n{configuration}CONF"
        )

    def administer(self, script: str) -> str:
        result = subprocess.run(  # noqa: S603 - runner-owned disposable fixture commands
            ["docker", "exec", os.environ["BARECTL_SSH_TEST_CONTAINER"], "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        return result.stdout

    def clear(self) -> None:
        for unit in self.units:
            self.administer(
                f"systemctl kill --signal=SIGKILL {unit} 2>/dev/null; "
                f"systemctl stop {unit} 2>/dev/null; "
                f"systemctl reset-failed {unit} 2>/dev/null; true"
            )
        if self.shared:
            self.administer(f"rm -f {self.shared}")
        self.administer(
            "systemctl stop barectl-acquisition-http barectl-acquisition-lock "
            "2>/dev/null; systemctl reset-failed barectl-acquisition-http "
            "barectl-acquisition-lock 2>/dev/null; "
            "rm -f /etc/apt/apt.conf.d/99barectl-acquisition-fixture; "
            f"rm -rf {FIXTURE}; true"
        )

    def wait_for(self, command: str, *, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while self.administer(f"if {command}; then echo yes; fi").strip() != "yes":
            if time.monotonic() > deadline:
                self.fail(f"Native fixture did not become ready: {command}")
            time.sleep(0.1)

    def package_state(self) -> str:
        return self.administer(
            "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states; wc -l </var/log/dpkg.log"
        )

    def payload(self, unit: str, actions: list[native.PackageAction] | None = None) -> str:
        boot, uptime = self.administer(
            "cat /proc/sys/kernel/random/boot_id; cut -d' ' -f1 /proc/uptime"
        ).splitlines()
        approved = (
            actions
            if actions is not None
            else [
                native.PackageAction(True, "hello", self.version, self.architecture),
                native.PackageAction(False, "hello", self.version, self.architecture),
            ]
        )
        return native.package_change(
            unit,
            boot,
            int(float(uptime) * 100) + 60_000,
            apt=native.parse_digest(self.administer(native.APT_DIGEST)),
            packages=native.parse_digest(self.administer(SCOPE)),
            scope=SCOPE,
            roots=[("hello", self.version)],
            actions=approved,
            services=(),
            enable=False,
            start=False,
            check=native.Check(("/usr/bin/hello",), "Hello, world!"),
            isolated_archives=True,
        )

    def submit(self, unit: str, payload: str, *, timeout: bool = False) -> None:
        argv = native.submission(unit, payload, isolated_archives=True)
        if timeout:
            argv = [
                "--property=RuntimeMaxSec=2s"
                if argument.startswith("--property=RuntimeMaxSec=")
                else "--property=TimeoutStopSec=1s"
                if argument.startswith("--property=TimeoutStopSec=")
                else argument
                for argument in argv
            ]
        self.units.append(unit)
        self.administer(shlex.join(argv))

    def wait_terminal(self, unit: str) -> dict[str, str]:
        deadline = time.monotonic() + 60
        while True:
            shown = self.administer(
                f"systemctl show -p MainPID -p SubState -p Result -p ExecMainStatus {unit}"
            )
            state = dict(line.split("=", 1) for line in shown.splitlines())
            if state["MainPID"] == "0" and state["SubState"] in {"exited", "failed", "dead"}:
                return state
            if time.monotonic() > deadline:
                self.fail(self.journal(unit))
            time.sleep(0.1)

    def journal(self, unit: str) -> str:
        return self.administer(f"journalctl -q --no-pager -o cat -u {unit}")

    def assert_cache_removed(self, unit: str) -> None:
        root = native.archive_cache(unit).removesuffix("archives/")
        self.assertEqual(self.administer(f"test ! -e {root} && echo removed").strip(), "removed")

    def test_poisoned_shared_cache_is_ignored_and_verified_fetch_precedes_hooks(self) -> None:
        self.administer(f"cp {FIXTURE}/bad.deb {self.shared}")
        self.assertEqual(
            self.administer(f"stat -c '%s' {FIXTURE}/good.deb").strip(),
            self.administer(f"stat -c '%s' {self.shared}").strip(),
        )
        self.assertNotEqual(
            self.administer(f"sha256sum {FIXTURE}/good.deb").split()[0],
            self.administer(f"sha256sum {self.shared}").split()[0],
        )
        before = self.administer(f"sha256sum {self.shared}; stat -c '%s' {self.shared}")
        automatic_before = self.administer("apt-mark showauto")
        unit = native.new_unit_name()
        script = self.payload(unit)
        self.assertLessEqual(len(script.encode()), 16 * 1024)
        self.submit(unit, script)
        result = self.wait_terminal(unit)
        self.assertEqual(result["ExecMainStatus"], "0", self.journal(unit))
        self.assertEqual(result["Result"], "success", self.journal(unit))
        self.assertIn("hello_", self.administer(f"cat {FIXTURE}/requested"))
        self.assertEqual(
            before, self.administer(f"sha256sum {self.shared}; stat -c '%s' {self.shared}")
        )
        output = self.journal(unit)
        self.assertLess(
            output.index("acquisition-hook-before-guard"), output.index(native.GUARD_ADMITTED)
        )
        self.assertLess(output.index(native.GUARD_ADMITTED), output.index("Unpacking hello"))
        self.assertIn("directory root root 755", output)
        self.assertIn("directory _apt root 700", output)
        self.assertNotIn("Download is performed unsandboxed", output)
        self.assertEqual(self.administer("apt-mark showauto"), automatic_before)
        self.assertEqual(self.administer("apt-mark showmanual hello").strip(), "hello")
        self.assertEqual(
            self.administer(
                "dpkg-query -W -f='${Version} ${Architecture} ${db:Status-Abbrev}' hello"
            ).strip(),
            f"{self.version} {self.architecture} ii",
        )
        self.assert_cache_removed(unit)

    def test_corrupted_fresh_fetch_stops_before_executable_package_hooks(self) -> None:
        self.administer(f"printf corrupt >{FIXTURE}/mode")
        before = self.package_state()
        unit = native.new_unit_name()
        self.submit(unit, self.payload(unit))
        result = self.wait_terminal(unit)
        self.assertEqual(
            result["ExecMainStatus"], str(native.Exit.INSTALL_NOT_STARTED), self.journal(unit)
        )
        self.assertIn("Hash Sum mismatch", self.journal(unit))
        self.assertNotIn("acquisition-hook-before-guard", self.journal(unit))
        self.assertNotIn(native.GUARD_ADMITTED, self.journal(unit))
        self.assertEqual(
            self.administer(f"test ! -e {FIXTURE}/hook-ran && echo absent").strip(), "absent"
        )
        self.assertEqual(before, self.package_state())
        self.assert_cache_removed(unit)

    def test_nonempty_or_nonroot_runtime_cache_refuses_before_apt(self) -> None:
        for fault in ("touch {root}/foreign", "chown observer {root}"):
            with self.subTest(fault=fault):
                before = self.package_state()
                unit = native.new_unit_name()
                root = native.archive_cache(unit).removesuffix("archives/").rstrip("/")
                script = self.payload(unit).replace(
                    f"d={root};", f"{fault.format(root=root)}; d={root};", 1
                )
                self.submit(unit, script)
                result = self.wait_terminal(unit)
                self.assertEqual(
                    result["ExecMainStatus"],
                    str(native.Exit.TRANSACTION_REFUSED),
                    self.journal(unit),
                )
                self.assertEqual(before, self.package_state())
                self.assertEqual(
                    self.administer(f"test ! -e {FIXTURE}/requested && echo absent").strip(),
                    "absent",
                )
                self.assert_cache_removed(unit)

    def test_partial_fresh_transfer_stops_before_hooks_and_removes_its_cache(self) -> None:
        self.administer(f"printf partial >{FIXTURE}/mode")
        before = self.package_state()
        unit = native.new_unit_name()
        self.submit(unit, self.payload(unit))
        result = self.wait_terminal(unit)
        self.assertEqual(
            result["ExecMainStatus"], str(native.Exit.INSTALL_NOT_STARTED), self.journal(unit)
        )
        self.assertEqual(self.administer(f"cat {FIXTURE}/partial-sent").strip(), "64")
        self.assertIn("Failed to fetch", self.journal(unit))
        self.assertNotIn("acquisition-hook-before-guard", self.journal(unit))
        self.assertNotIn(native.GUARD_ADMITTED, self.journal(unit))
        self.assertEqual(
            self.administer(f"test ! -e {FIXTURE}/hook-ran && echo absent").strip(), "absent"
        )
        self.assertEqual(before, self.package_state())
        self.assert_cache_removed(unit)

    def test_native_apt_archive_lock_refuses_and_removes_its_cache(self) -> None:
        before = self.package_state()
        unit = native.new_unit_name()
        cache = native.archive_cache(unit)
        lock = (
            "import fcntl,pathlib,time; "
            f"f=open('{cache}lock','w'); fcntl.lockf(f,fcntl.LOCK_EX); "
            f"pathlib.Path('{FIXTURE}/lock-ready').touch(); time.sleep(30)"
        )
        inject = (
            "systemd-run --quiet --unit=barectl-acquisition-lock /usr/bin/python3 "
            f"-c {shlex.quote(lock)}; "
            f"while [ ! -e {FIXTURE}/lock-ready ]; do sleep 0.05; done; "
        )
        script = self.payload(unit).replace(
            'chown _apt:root "$d/archives/partial" || exit 23;',
            'chown _apt:root "$d/archives/partial" || exit 23; ' + inject,
            1,
        )
        self.submit(unit, script)
        result = self.wait_terminal(unit)
        self.assertEqual(
            result["ExecMainStatus"], str(native.Exit.PACKAGE_MANAGER_BUSY), self.journal(unit)
        )
        self.assertIn("Could not get lock", self.journal(unit))
        self.assertEqual(before, self.package_state())
        self.assert_cache_removed(unit)

    def test_mutation_lock_refuses_before_acquisition(self) -> None:
        before = self.package_state()
        self.administer(
            f"mkdir -m 700 {native.LOCK_DIRECTORY} 2>/dev/null; "
            "systemd-run --quiet --unit=barectl-acquisition-lock /usr/bin/sh -c "
            + shlex.quote(
                f"exec 9>>{native.LOCK_FILE}; flock -n 9; touch {FIXTURE}/lock-ready; sleep 30"
            )
        )
        self.wait_for(f"test -e {FIXTURE}/lock-ready")
        unit = native.new_unit_name()
        self.submit(unit, self.payload(unit))
        result = self.wait_terminal(unit)
        self.assertEqual(result["ExecMainStatus"], str(native.Exit.LOCK_CONFLICT))
        self.assertEqual(before, self.package_state())
        self.assertEqual(
            self.administer(f"test ! -e {FIXTURE}/requested && echo absent").strip(), "absent"
        )
        self.assert_cache_removed(unit)

    def test_verified_archive_still_refuses_a_different_transaction(self) -> None:
        before = self.package_state()
        unit = native.new_unit_name()
        actions = [native.PackageAction(True, "hello", self.version, self.architecture)]
        self.submit(unit, self.payload(unit, actions))
        result = self.wait_terminal(unit)
        self.assertEqual(result["ExecMainStatus"], str(native.Exit.TRANSACTION_REFUSED))
        output = self.journal(unit)
        self.assertLess(
            output.index("acquisition-hook-before-guard"), output.index(native.GUARD_REFUSED)
        )
        self.assertNotIn("Unpacking hello", output)
        self.assertEqual(before, self.package_state())
        self.assert_cache_removed(unit)

    def test_kill_and_runtime_timeout_remove_inflight_acquisition_cache(self) -> None:
        for timed_out in (False, True):
            with self.subTest(timeout=timed_out):
                self.administer(f"printf wait >{FIXTURE}/mode; rm -f {FIXTURE}/requested")
                before = self.package_state()
                unit = native.new_unit_name()
                self.submit(unit, self.payload(unit), timeout=timed_out)
                self.wait_for(f"test -e {FIXTURE}/requested")
                cache = native.archive_cache(unit)
                self.assertEqual(
                    self.administer(f"stat -c '%U %G %a' {cache}partial").strip(),
                    "_apt root 700",
                )
                if not timed_out:
                    self.administer(f"systemctl kill --kill-whom=all --signal=SIGKILL {unit}")
                result = self.wait_terminal(unit)
                self.assertEqual(
                    result["Result"], "timeout" if timed_out else "signal", self.journal(unit)
                )
                self.assertEqual(before, self.package_state())
                self.assertNotIn("acquisition-hook-before-guard", self.journal(unit))
                self.assert_cache_removed(unit)

    def test_oversize_reviewed_transaction_refuses_before_creating_a_unit(self) -> None:
        before = self.package_state()
        unit = native.new_unit_name()
        actions = [
            native.PackageAction(
                True, f"reviewed-dependency-{index}", self.version, self.architecture
            )
            for index in range(250)
        ]
        script = self.payload(unit, actions)
        self.assertGreater(len(script.encode()), 16 * 1024)
        with self.assertRaises(native.PayloadTooLarge):
            native.submission(unit, script, isolated_archives=True)
        self.assertEqual(before, self.package_state())
        self.assertEqual(
            self.administer(f"systemctl show -p LoadState --value {unit}").strip(), "not-found"
        )
