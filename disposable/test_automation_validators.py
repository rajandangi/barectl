"""Rendered automation units load in the real systemd (Phase C #357, fast validator).

docs/quality.md#native-layer. The product's own convention renders the files into a scratch
directory; systemd's parser is the judge, so the fast layer never restates their text.
"""

import shlex

from django.test import tag

from automation import convention, workers
from discovery.ssh import RemoteShell

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "v357units"
ACCOUNT = f"s{IDENTIFIER}"
SCRATCH = f"/run/{IDENTIFIER}"


@tag(SCENARIO_TAG)
class AutomationValidators(ScenarioTestCase):
    layer = "L1"
    validator = True
    exclusive = False
    prefix = "v357units"

    def prepare(self) -> None:
        self.native(
            f"useradd --system --user-group --home-dir /var/www/{IDENTIFIER} "
            f"--shell /usr/sbin/nologin {ACCOUNT} 2>/dev/null || true"
        )
        self.addCleanup(
            self.native,
            f"pkill -u {ACCOUNT} 2>/dev/null || true; userdel {ACCOUNT} 2>/dev/null || true",
        )
        self.native(f"install -d -m 0755 /var/www/{IDENTIFIER}/current /var/www/{IDENTIFIER}/bin")
        self.native(f"install -m 0755 /bin/true /var/www/{IDENTIFIER}/bin/wp")
        self.native(f"install -m 0755 /bin/true /var/www/{IDENTIFIER}/bin/php")
        self.addCleanup(self.native, f"rm -rf /var/www/{IDENTIFIER}")
        self.native(f"rm -rf {SCRATCH} && install -d -m 0755 {SCRATCH}")
        self.addCleanup(self.native, f"rm -rf {SCRATCH}")

    def write(self, shell: RemoteShell, name: str, text: str) -> str:
        path = f"{SCRATCH}/{name}"
        result = shell.run(
            f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=text.encode()
        )
        self.assertEqual(result.exit_status, 0, result.stdout)
        return path

    def rendered(self) -> list[tuple[str, str]]:
        return [
            ("slice", convention.slice_name(IDENTIFIER)),
            ("service", convention.service_name(IDENTIFIER, convention.ROLE_WPCRON)),
            ("timer", convention.timer_name(IDENTIFIER, convention.ROLE_WPCRON)),
        ]

    def test_the_rendered_slice_service_and_timer_load_in_systemd(self) -> None:
        self.prepare()
        with self.shell() as shell:
            paths = [
                self.write(shell, name, convention.render(IDENTIFIER, convention.ROLE_WPCRON, kind))
                for kind, name in self.rendered()
            ]
        self.native(
            "systemd-analyze verify " + " ".join(shlex.quote(path) for path in paths) + " 2>&1"
        )

    def test_four_queue_processes_load_in_systemd(self) -> None:
        self.prepare()
        definition = workers.WorkerDefinition(("default", "mail"), 4, 900)
        units = workers.render_worker_units(IDENTIFIER, definition)
        with self.shell() as shell:
            paths = [self.write(shell, name, text) for _kind, name, text in units]
        self.native(
            "systemd-analyze verify " + " ".join(shlex.quote(path) for path in paths) + " 2>&1"
        )

    def test_a_worker_with_an_unknown_command_fails_before_publication(self) -> None:
        self.prepare()
        service = workers.render_worker_service(
            IDENTIFIER, 1, workers.WorkerDefinition(("default",), 1, 60)
        ).replace(f"ExecStart=/var/www/{IDENTIFIER}/bin/php", "ExecStart=/nonexistent/barectl-php")
        with self.shell() as shell:
            path = self.write(shell, "broken-queue.service", service)
        output = self.native(
            f"systemd-analyze verify {shlex.quote(path)} 2>&1; printf '\nstatus=%s\n' $?"
        )
        self.assertNotIn("status=0", output)
        self.assertIn("/nonexistent/barectl-php", output)

    def test_the_calendar_expression_is_the_one_systemd_parses(self) -> None:
        parsed = self.native(f"systemd-analyze calendar {shlex.quote(convention.ON_CALENDAR)} 2>&1")
        self.assertIn(f"Normalized form: {convention.ON_CALENDAR}", parsed)

    def test_a_unit_systemd_rejects_fails_before_publication(self) -> None:
        self.prepare()
        broken = convention.render_service(IDENTIFIER, convention.ROLE_WPCRON).replace(
            f"ExecStart=/var/www/{IDENTIFIER}/bin/wp", "ExecStart=/nonexistent/barectl-wp"
        )
        with self.shell() as shell:
            path = self.write(shell, "broken.service", broken)
        output = self.native(
            f"systemd-analyze verify {shlex.quote(path)} 2>&1; printf '\\nstatus=%s\\n' $?"
        )
        self.assertNotIn("status=0", output)
        self.assertIn("/nonexistent/barectl-wp", output)


__all__ = ["AutomationValidators"]
