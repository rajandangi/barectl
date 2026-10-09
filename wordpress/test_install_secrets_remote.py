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

import re
import secrets
import shlex
import time

from bootstrap.models import Execution, Verification
from operations.models import RemoteOperation

from . import install, setup_native
from .test_install_apply_remote import (
    BASE,
    IDENTIFIER,
    NAME,
    PRIVATE,
    PUBLIC,
    USER,
    InstallApplyTestCase,
)

Status = RemoteOperation.Status
SAMPLE = "/tmp/barectl-sample.txt"  # noqa: S108 - a file in the disposable server
STOP = "/tmp/barectl-sample.stop"  # noqa: S108
SAMPLER = r"""
import os, sys, time
seen = set()
end = time.monotonic() + float(sys.argv[1])
stop = sys.argv[2]
while time.monotonic() < end and not os.path.exists(stop):
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        for name in ("cmdline", "environ"):
            try:
                with open(f"/proc/{pid}/{name}", "rb") as handle:
                    data = handle.read(65536)
            except OSError:
                continue
            if data:
                seen.add(data.replace(b"\0", b"\n"))
    time.sleep(0.003)
with open(sys.argv[3], "wb") as out:
    for item in seen:
        out.write(item + b"\n")
"""
TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9]{32}(?![A-Za-z0-9+/=_-])")
PASSWORD = "Barectl-Known-Passw0rd-9fK2xQ7v"


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
        sampled = self.administer(f"cat {SAMPLE}")
        # The sampler would have seen a secret on a command line or in an environment.
        self.assertIn(canary_argument, sampled)
        self.assertIn(canary_environment, sampled)
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
        refused = self.administer(login.format(name=NAME, password="guess-guess-guess")).strip()
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
