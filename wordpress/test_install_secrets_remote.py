"""The initial administrator password and the salts never leave the server, and the terminal
step that sets a password works (docs/wordpress.md#administrator-password-setup).

Tagged ``ssh`` and skipped unless the disposable server is configured. A sampler running on
the server as root records every process command line and environment while Barectl applies
the installation; the journal, the unit's systemd metadata, the controller's records and the
rendered pages are searched too. Because the password is unknown to everyone, absence is
proven the other way round: every 32 character token found on any of those surfaces is tried
as the administrator's password with ``wp user check-password``, and none matches. A canary
command and environment the test itself injects prove the sampler would have seen a secret.
"""

import json
import re
import secrets
import shlex
import time

from bootstrap.models import Execution, Verification
from operations.models import RemoteOperation

from . import install, setup_native
from .install_apply_remote_testing import BASE, USER, InstallApplyTestCase
from .install_remote_testing import NAME, PRIVATE, PUBLIC

Status = RemoteOperation.Status
SAMPLE = "/tmp/barectl-sample.txt"  # noqa: S108 - a file in the disposable server
STOP = "/tmp/barectl-sample.stop"  # noqa: S108
SAMPLER = r"""
import json, os, sys, time
seen = {}
end = time.monotonic() + float(sys.argv[1])
stop = sys.argv[2]
while time.monotonic() < end and not os.path.exists(stop):
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            record = {}
            record["cgroup"] = None
            try:
                with open(f"/proc/{pid}/cgroup") as handle:
                    record["cgroup"] = handle.read(65536)
            except OSError:
                pass
            for name in ("cmdline", "environ", "comm"):
                with open(f"/proc/{pid}/{name}", "rb") as handle:
                    record[name] = handle.read(65536).decode("utf-8", "replace")
            with open(f"/proc/{pid}/status") as handle:
                record["uid"] = next(
                    int(line.split()[1]) for line in handle if line.startswith("Uid:")
                )
        except (OSError, StopIteration):
            continue
        if record["cmdline"] or record["environ"]:
            seen[json.dumps(record, sort_keys=True)] = None
    time.sleep(0.003)
with open(sys.argv[3], "w") as out:
    for item in seen:
        out.write(item + "\n")
"""
TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9]{32}(?![A-Za-z0-9+/=_-])")
PASSWORD = "Barectl-Known-Passw0rd-9fK2xQ7v"  # noqa: S105 - the test's own throwaway value


class InstallSecretTests(InstallApplyTestCase):
    def wp(self, *arguments: str) -> str:
        """WP-CLI as the site user, as the documented terminal step runs it."""
        quoted = " ".join(shlex.quote(item) for item in arguments)
        return (
            f"sudo -u {USER} /usr/bin/php{self.php} {setup_native.PHAR} --path={PUBLIC} "
            f"--url=https://{NAME} {quoted}"
        )

    def is_password(self, candidate: str) -> bool:
        result = self.administer(
            f"{self.wp('user', 'check-password', 'owner', candidate)} >/dev/null 2>&1; echo $?"
        )
        return result.strip() == "0"

    def test_no_secret_reaches_a_command_line_an_environment_the_journal_or_a_record(self) -> None:
        canary_argument = secrets.token_hex(16)
        canary_environment = secrets.token_hex(16)
        self.addCleanup(self.administer, f"rm -f {SAMPLE} {STOP}")
        self.administer(f"rm -f {SAMPLE} {STOP}")
        self.administer(f"python3 -I -c {shlex.quote(SAMPLER)} 240 {STOP} {SAMPLE}", detach=True)
        time.sleep(1)
        plan = self.eligible()
        canary = f"CANARY={canary_environment} sh -c 'sleep 3' {canary_argument}"
        with self.injected(plan, "stage", canary):
            run = self.apply_install(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.administer(f"touch {STOP}")
        for _ in range(30):
            if self.administer(f"test -s {SAMPLE} && echo ready; true").strip():
                break
            time.sleep(1)
        records = [json.loads(line) for line in self.administer(f"cat {SAMPLE}").splitlines()]
        sampled = "\n".join(
            (record["cmdline"] + "\0" + record["environ"]).replace("\0", "\n") for record in records
        )
        # The sampler would have seen a secret on a command line or in an environment.
        self.assertIn(canary_argument, sampled)
        self.assertIn(canary_environment, sampled)
        self.assert_application_processes_ran_as_the_site_user(records, run.unit_name)
        # Everything else the run exposed on the server.
        properties = self.administer(f"systemctl show {run.unit_name}")
        journal = self.administer(f"journalctl --no-pager -o cat -u {run.unit_name}")
        everything = self.administer("journalctl --no-pager -o cat --since '-15min'")
        controller = "\n".join(
            [
                run.failure,
                run.effects,
                run.reviewed_changes,
                *(self.client.get(f"/applies/{run.pk}/").content.decode() for _ in range(1)),
            ]
        )
        surfaces = {
            "processes": sampled,
            "unit": properties,
            "journal": journal,
            "system journal": everything,
            "controller": controller,
        }
        for name, text in surfaces.items():
            for word in ("AUTH_KEY'", "NONCE_SALT'", "--admin_password", "admin_password="):
                self.assertNotIn(word, text.replace("define(", ""), name)
        candidates = {
            token
            for text in surfaces.values()
            for token in TOKEN.findall(text)
            if token not in {canary_argument, canary_environment}
        }
        self.assertTrue(candidates, "the unit name and invocation are among the tokens")
        for candidate in sorted(candidates):
            self.assertFalse(self.is_password(candidate), "a token on a surface is the password")
        # Tokens do not hide in the salts either: no salt is on any surface.
        salts = re.findall(
            r"define\( '(?:\w+_(?:KEY|SALT))', '([A-Za-z0-9]{64})' \);",
            self.administer(f"cat {PRIVATE}/wp-config.php"),
        )
        self.assertEqual(len(salts), 8)
        for salt in salts:
            for name, text in surfaces.items():
                self.assertNotIn(salt, text, name)

    def owned_processes(
        self, records: list[dict[str, object]], uid: int, unit_name: str
    ) -> list[dict[str, object]]:
        unit = f"0::/system.slice/{unit_name}"
        owned = []
        for record in records:
            comm, cmdline = str(record["comm"]).strip(), str(record["cmdline"])
            cgroup = record.get("cgroup")
            if (
                re.fullmatch(r"php\d\.\d", comm)
                or comm in {"tar", "python3"}
                or setup_native.PHAR in cmdline
            ):
                self.assertIsInstance(cgroup, str, f"No process ownership evidence: {cmdline}")
                self.assertTrue(cgroup, f"Empty process ownership evidence: {cmdline}")
            membership = str(cgroup).splitlines()
            in_unit = any(path == unit or path.startswith(f"{unit}/") for path in membership)
            if in_unit or record["uid"] == uid:
                owned.append(record)
        return owned

    def assert_application_processes_ran_as_the_site_user(
        self, records: list[dict[str, object]], unit_name: str
    ) -> None:
        """Owned WP-CLI, PHP and archive tools retain the site's identity and private
        environment; unrelated native maintenance remains in the global secret scan."""
        uid = int(self.administer(f"id -u {USER}").strip())
        owned = self.owned_processes(records, uid, unit_name)
        unit = f"0::/system.slice/{unit_name}"
        allowed = {
            "PATH",
            "LC_ALL",
            "HOME",
            "TMPDIR",
            "WP_CLI_CACHE_DIR",
            "WP_CLI_PACKAGES_DIR",
            "WP_CLI_CONFIG_PATH",
            "WP_CLI_DISABLE_AUTO_CHECK_UPDATE",
            # Set by the shell that starts it, in the private home.
            "PWD",
        }
        wp_cli = [
            r
            for r in owned
            if str(r["cmdline"]).startswith(f"/usr/bin/php{self.php}\0")
            and setup_native.PHAR in str(r["cmdline"])
        ]
        self.assertTrue(wp_cli, "the sampler saw owned WP-CLI run")
        self.assertTrue(
            any(
                r["comm"] == f"php{self.php}\n"
                and r["uid"] == uid
                and any(
                    path == unit or path.startswith(f"{unit}/")
                    for path in str(r["cgroup"]).splitlines()
                )
                for r in wp_cli
            ),
            "the sampler saw the unit's WP-CLI executing as the site user",
        )
        for record in wp_cli:
            command = str(record["cmdline"]).split("\0")
            if record["comm"] == "runuser\n":
                continue
            self.assertEqual(record["uid"], uid, command)
            self.assertEqual(command[0], f"/usr/bin/php{self.php}", command)
            self.assertNotIn("--allow-root", command)
            environment = dict(
                item.split("=", 1) for item in str(record["environ"]).split("\0") if "=" in item
            )
            self.assertLessEqual(set(environment), allowed, environment)
            self.assertRegex(environment["HOME"], rf"^{BASE}/\.wp-[0-9a-f]{{32}}/home$")
            self.assertRegex(environment["TMPDIR"], rf"^{BASE}/\.wp-[0-9a-f]{{32}}/tmp$")
            self.assertEqual(environment["PATH"], "/usr/bin:/bin")
            self.assertEqual(environment.get("PWD", environment["HOME"]), environment["HOME"])
        # No owned application interpreter, archive tool or WP-CLI had root's identity.
        for record in owned:
            comm, cmdline = str(record["comm"]).strip(), str(record["cmdline"])
            if re.fullmatch(r"php\d\.\d", comm):
                self.assertIn(record["uid"], {0, uid}, cmdline)
            if re.fullmatch(r"php\d\.\d", comm) and record["uid"] == uid:
                self.assertEqual(comm, f"php{self.php}", cmdline)
                self.assertIn(setup_native.PHAR, cmdline, cmdline)
            if record["uid"] != 0:
                continue
            if re.fullmatch(r"php\d\.\d", comm):
                # The one root PHP is the fixed FastCGI client, which loads no application.
                self.assertIn("stream_socket_client", cmdline, cmdline)
                self.assertNotIn("wp-load", cmdline)
            if comm in {"tar", "python3", "php8.3", "php8.5"}:
                self.assertNotIn("wordpress.tar.gz", cmdline)
                self.assertNotIn(setup_native.PHAR, cmdline)

    def test_the_salts_are_generated_on_the_server_and_differ_between_installations(self) -> None:
        run = self.apply_install(self.eligible())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        configuration = self.administer(f"cat {PRIVATE}/wp-config.php")
        salts = re.findall(r"define\( '\w+_(?:KEY|SALT)', '([A-Za-z0-9]{64})' \);", configuration)
        self.assertEqual(len(salts), 8)
        self.assertEqual(len(set(salts)), 8)
        self.assertEqual(self.administer(f"stat -c %a {PRIVATE}/wp-config.php").strip(), "600")

    def test_the_documented_terminal_step_sets_a_password_that_works_over_https(self) -> None:
        run = self.apply_install(self.eligible())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        row = run.wordpress_install
        step = install.password_command(row.identifier, row.php_version, NAME, row.admin_login)
        login = (
            "curl -sk --max-time 30 --resolve {name}:443:127.0.0.1 -c /tmp/jar -b /tmp/jar "
            "-o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
            '-H "Cookie: wordpress_test_cookie=WP%20Cookie%20check" '
            "--data-urlencode log=owner --data-urlencode pwd={password} "
            "--data-urlencode wp-submit=Log+In --data-urlencode testcookie=1 "
            "https://{name}/wp-login.php; true"
        )
        self.addCleanup(self.administer, "rm -f /tmp/jar")
        # Before the step no password is usable: a guess is not accepted.
        guess = login.format(name=NAME, password="guess-guess-guess")  # noqa: S106 - a wrong guess
        refused = self.administer(guess).strip()
        self.assertEqual(refused.split()[:1], ["200"], refused)
        # The operator types the password at WP-CLI's prompt, which reads standard input.
        feed = f"printf '%s\\n' {shlex.quote(PASSWORD)} | {step}"
        output = self.administer(f"{feed} 2>&1; echo status=$?")
        self.assertIn("Success: Updated user", output)
        self.assertIn("status=0", output)
        accepted = self.administer(login.format(name=NAME, password=PASSWORD)).strip()
        self.assertEqual(accepted, f"302 https://{NAME}/wp-admin/")
        dashboard = self.administer(
            f"curl -sk --max-time 30 --resolve {NAME}:443:127.0.0.1 -b /tmp/jar "
            f"https://{NAME}/wp-admin/ | grep -c 'Dashboard'; true"
        )
        self.assertGreater(int(dashboard.strip() or "0"), 0)
        self.assertEqual(self.curl("/"), "200")
        self.assertEqual(self.administer(f"ls -A {BASE}").split(), ["private", "public"])
