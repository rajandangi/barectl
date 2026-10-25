"""Fast validator: the supported per-site rotation file parses in the real logrotate."""

from django.test import tag

from sites.bodies.logrotate import logrotate_render

from .mirror import apt_sources
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

CANDIDATE = "/run/v389logs/logrotate.conf"


@tag(SCENARIO_TAG)
class LogRotationValidators(ScenarioTestCase):
    layer = "L1"
    prefix = "v389logs"
    validator = True

    def install_logrotate(self) -> None:
        with self.shell() as shell:
            written = shell.run(
                "install -D -m 0644 /dev/stdin /etc/apt/sources.list.d/barectl-fixture.sources",
                stdin=apt_sources().encode(),
            )
            self.assertEqual(written.exit_status, 0, written.stdout)
        self.native("rm -f /etc/apt/sources.list.d/ubuntu.sources")
        self.native("apt-get update -qq >/dev/null 2>&1")
        self.native("apt-get install -y -qq logrotate >/dev/null 2>&1")
        self.assertEqual(self.native("command -v logrotate").strip(), "/usr/sbin/logrotate")

    def prepare_candidate(self) -> None:
        self.addCleanup(self.native, f"rm -f {CANDIDATE}")
        self.addCleanup(self.native, "rm -rf /var/www/v389logs")
        self.addCleanup(self.native, "userdel sv389logs 2>/dev/null || true")
        self.addCleanup(self.native, "groupdel sv389logs 2>/dev/null || true")
        self.native("groupadd sv389logs")
        self.native("useradd -g sv389logs -M -s /usr/sbin/nologin sv389logs")
        self.native("install -d -o root -g root -m 0755 /var/www/v389logs/logs")
        for name in ("php-error.log", "php-slow.log", "wp-debug.log"):
            self.native(f"install -o root -g root -m 0640 /dev/null /var/www/v389logs/logs/{name}")

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
