"""Fast validator: the supported per-site rotation file parses in the real logrotate."""

from typing import override

from django.test import tag

from sites.bodies.logrotate import logrotate_render

from .mirror import apt_sources
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

ROOT = "/run/v389logs"
CANDIDATE = f"{ROOT}/logrotate.conf"
SCRATCH = f"{ROOT}/logs"
APT = f"{ROOT}/apt"
# Every apt path this validator writes is private, so the host's own sources, lists, cache,
# extended states and logs stay untouched for the classes that follow
# (docs/quality.md#fast-snapshot-validators).
APT_OPTIONS = " ".join(
    (
        f"-o Dir::Etc::sourcelist={APT}/fixture.sources",
        "-o Dir::Etc::sourceparts=-",
        f"-o Dir::State::lists={APT}/lists",
        f"-o Dir::State::extended_states={APT}/extended_states",
        f"-o Dir::Cache={APT}/cache",
        f"-o Dir::Log={APT}/log",
    )
)
# The install starts logrotate's timer and, because L1 has no other listed dependency
# provider, cron (`Depends: cron | anacron | cron-daemon | systemd-sysv`); both are stopped.
STOPPED_UNITS = "logrotate.timer logrotate.service cron.service"


@tag(SCENARIO_TAG)
class LogRotationValidators(ScenarioTestCase):
    layer = "L1"
    prefix = "v389logs"
    validator = True

    @override
    def setUp(self) -> None:
        super().setUp()
        # Everything this class writes lives under ROOT, including the package's log files.
        self.addCleanup(self.native, f"rm -rf {ROOT}")
        # The package's timer and the cron daemon its dependency installs are the daemons
        # its install starts; a later class must not find a service this validator started.
        self.addCleanup(
            self.native,
            f"systemctl stop {STOPPED_UNITS} 2>/dev/null || true",
        )

    def install_logrotate(self) -> None:
        """Install logrotate from the fixture mirror through a private apt source and state."""
        self.native(f"umask 022 && install -d -m 0755 {ROOT}")
        if self.native("command -v logrotate || true").strip() == "/usr/sbin/logrotate":
            return
        self.native(
            f"umask 022 && install -d -m 0755 "
            f"{APT}/lists/partial {APT}/cache/archives/partial {APT}/log"
        )
        with self.shell() as shell:
            written = shell.run(
                f"umask 022 && install -D -m 0644 /dev/stdin {APT}/fixture.sources",
                stdin=apt_sources().encode(),
            )
            self.assertEqual(written.exit_status, 0, written.stdout)
        installed = self.native(
            f"apt-get {APT_OPTIONS} update -qq 2>&1 && "
            f"apt-get {APT_OPTIONS} install -y -qq --no-install-recommends logrotate 2>&1; "
            "printf '\nstatus=%s' $?"
        )
        self.assertTrue(installed.endswith("status=0"), installed)
        self.assertEqual(self.native("command -v logrotate || true").strip(), "/usr/sbin/logrotate")
        self.native(f"systemctl stop {STOPPED_UNITS} 2>/dev/null || true")
        self.restore_runtime_masters()

    def restore_runtime_masters(self) -> None:
        """Restart the PHP masters the package install's daemon-reload unsettled.

        Installing a package with systemd units makes dpkg run ``systemctl daemon-reload``,
        which resets the running masters' ``ExecStart`` runtime metadata to zero. The
        runtime read proves a master by that metadata, so without a restart a later class
        in the same container would see a protection fault on ``php84`` and refuse a site.
        """
        for unit in ("php-fpm@php84.service", "php-fpm@php85.service"):
            if self.native(f"systemctl is-active {unit} || true").strip() == "active":
                self.native(f"systemctl restart {unit}")

    def prepare_candidate(self) -> None:
        # The rendered file names the site's account, so the real rotation needs it to exist.
        self.addCleanup(self.native, "groupdel sv389logs 2>/dev/null || true")
        self.addCleanup(self.native, "userdel sv389logs 2>/dev/null || true")
        if not self.native("getent group sv389logs || true").strip():
            self.native("groupadd sv389logs")
        if not self.native("getent passwd sv389logs || true").strip():
            self.native("useradd -g sv389logs -M -s /usr/sbin/nologin sv389logs")

    def test_the_supported_file_passes_logrotate_debug(self) -> None:
        self.install_logrotate()
        self.prepare_candidate()
        with self.shell() as shell:
            written = shell.run(
                f"install -D -m 0644 /dev/stdin {CANDIDATE}",
                stdin=logrotate_render(
                    "v389logs", ("php-error.log", "php-slow.log", "wp-debug.log")
                ).encode(),
            )
            self.assertEqual(written.exit_status, 0, written.stdout)
        output = self.native(f"logrotate --debug {CANDIDATE} 2>&1")
        self.assertIn("php-error.log", output)
        self.assertIn("wp-debug.log", output)
        self.assertIn("5 rotations", output)
        self.assertIn("after 14 days", output)
        self.assertNotIn("access.json", output)

    def test_the_supported_file_rotates_and_recreates_the_site_log(self) -> None:
        """The exact rendered file, with its paths moved to a scratch tree, rotates for real."""
        self.install_logrotate()
        self.prepare_candidate()
        self.native(
            f"umask 022 && install -d -o root -g sv389logs -m 0750 {SCRATCH} && "
            f"install -o sv389logs -g sv389logs -m 0640 /dev/null {SCRATCH}/php-error.log && "
            f"install -o sv389logs -g sv389logs -m 0640 /dev/null {SCRATCH}/php-slow.log && "
            f"install -o sv389logs -g sv389logs -m 0640 /dev/null {SCRATCH}/wp-debug.log && "
            f"printf 'first line\\n' > {SCRATCH}/php-error.log"
        )
        rendered = logrotate_render(
            "v389logs", ("php-error.log", "php-slow.log", "wp-debug.log")
        ).replace("/var/www/v389logs/logs", SCRATCH)
        with self.shell() as shell:
            written = shell.run(
                f"install -D -m 0640 /dev/stdin {CANDIDATE}", stdin=rendered.encode()
            )
            self.assertEqual(written.exit_status, 0, written.stdout)
        # delaycompress keeps the first rotation as .1; the second compresses it.
        self.native(f"/usr/sbin/logrotate -f -v {CANDIDATE} 2>&1")
        self.assertEqual(
            self.native(f"test -e {SCRATCH}/php-error.log.1 && echo present").strip(),
            "present",
        )
        self.native(f"printf 'second line\\n' > {SCRATCH}/php-error.log")
        self.native(f"/usr/sbin/logrotate -f -v {CANDIDATE} 2>&1")
        rotated = self.native(f"ls -1 {SCRATCH}").split()
        compressed = next((name for name in rotated if name.endswith(".gz")), "")
        self.assertTrue(compressed, rotated)
        self.assertEqual(self.native(f"zcat {SCRATCH}/{compressed}").strip(), "first line")
        self.assertEqual(
            self.native(f"stat -c '%U %G %a' {SCRATCH}/php-error.log").strip(),
            "sv389logs sv389logs 640",
        )

    def test_an_unsupported_directive_is_rejected_by_logrotate(self) -> None:
        self.install_logrotate()
        self.prepare_candidate()
        broken = logrotate_render("v389logs", ("php-error.log", "php-slow.log")).replace(
            "rotate 5", "rotate banana"
        )
        with self.shell() as shell:
            written = shell.run(f"install -D -m 0644 /dev/stdin {CANDIDATE}", stdin=broken.encode())
            self.assertEqual(written.exit_status, 0, written.stdout)
        result = self.native(
            f"logrotate --debug {CANDIDATE} >/dev/null 2>&1; printf 'status=%s' $?"
        )
        self.assertNotEqual(result.strip(), "status=0")
