"""Native HTTP denial, source confidentiality and administrative boundaries."""

import ipaddress
import json
import shlex

from django.test import tag

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteSecurityBehavior(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4sec"

    def _create(self, identifier: str = "s4secalpha") -> None:
        from operations.inputs import PreparationInputs
        from sites import change

        inputs = PreparationInputs("php84", identifier, (identifier + ".example.com",))
        with self.shell() as shell:
            draft = change.review(change.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            import time

            from operations import engine, native
            from operations.models import ChangeReview

            if draft.uptime_centiseconds is None:
                self.fail("No native clock.")
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
            )
            review = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=engine._sites_digest(shell, draft),
            )
            body = change.body(draft.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, change.BODY_SHA256)), stdin=body.source
                ).exit_status,
                0,
            )
            payload = engine.payload(change.CREATE_SITE, review, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
            deadline = time.monotonic() + 30
            outcome = engine.read_result(shell, context.unit)
            while outcome is None and time.monotonic() < deadline:
                time.sleep(0.1)
                outcome = engine.read_result(shell, context.unit)
            self.assertIsNotNone(outcome, self.native(f"journalctl -u {context.unit} -n 40"))
            if outcome is None:
                self.fail("No native result.")
            self.assertEqual(
                outcome.result_class,
                "succeeded",
                self.native(f"journalctl -u {context.unit} -n 40"),
            )

    def _request(self, path: str, host: str = "s4secalpha.example.com") -> tuple[int, str]:
        response = self.native(
            shlex.join(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--path-as-is",
                    "-H",
                    f"Host: {host}",
                    "-w",
                    "\\n%{http_code}",
                    "http://127.0.0.1" + path,
                ]
            )
        )
        body, status = response.rsplit("\n", 1)
        return int(status), body

    def test_http_denials_precede_php_and_keep_public_controls_available(self) -> None:
        """Actual decoded requests must not execute forbidden source through FastCGI."""
        self._create()
        self.native(
            "install -d -o ss4secalpha -g caddy -m 2750 "
            "/var/www/s4secalpha/current/public/.git "
            "/var/www/s4secalpha/current/public/.well-known "
            "/var/www/s4secalpha/current/public/wp-content/uploads"
        )
        source = (
            "<?php file_put_contents('/var/www/s4secalpha/private/executed', 'yes'); "
            "echo 'FORBIDDEN';"
        )
        for path in (
            ".env",
            ".git/config",
            "wp-config.php",
            "wp-content/uploads/a.php",
            "wp-content/uploads/a.PHP",
            "wp-content/uploads/a.phtml",
        ):
            self.native(
                "printf %s "
                + shlex.quote(source)
                + " >"
                + shlex.quote("/var/www/s4secalpha/current/public/" + path)
            )
        self.native(
            "printf PUBLIC >/var/www/s4secalpha/current/public/.well-known/x; "
            "find /var/www/s4secalpha/current/public -type f ! -name index.php "
            "-exec chown ss4secalpha:caddy {} + -exec chmod 640 {} +"
        )
        self.native(
            "printf %s "
            + shlex.quote(source)
            + " >/var/www/s4secalpha/current/public/control.php; "
            "chown ss4secalpha:ss4secalpha /var/www/s4secalpha/current/public/control.php; "
            "chmod 600 /var/www/s4secalpha/current/public/control.php"
        )
        self.assertEqual(self._request("/control.php"), (200, "FORBIDDEN"))
        self.native("test -f /var/www/s4secalpha/private/executed")
        self.native("rm /var/www/s4secalpha/private/executed")
        self.assertEqual(self._request("/.well-known/x"), (200, "PUBLIC"))
        self.assertEqual(self._request("/", "unknown.example.com")[0], 404)
        self.assertEqual(self._request("/")[0], 200)
        for path in (
            "/.env",
            "/.git/config",
            "/wp-config.php",
            "/wp-content/uploads/a.php",
            "/wp-content/uploads/a.PHP/x",
            "/wp-content/uploads/a.phtml",
            "/%2eenv",
            "/.git%2fconfig",
            "/wp-content/uploads/a%2ephp",
            "/wp-content/uploads/a.PHP%2fx",
            "//wp-content//uploads/a.php",
            "/wp-config.php/extra",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._request(path)[0], 404)
        self.native("test ! -e /var/www/s4secalpha/private/executed")

        self._create("s4secbeta")
        uid = int(self.native("id -u ss4secbeta").strip())
        root_status, root_body = self._request("/", "s4secbeta.example.com")
        status, body = self._request("/index.php", "s4secbeta.example.com")
        self.assertEqual(status, 200, repr(body))
        response = json.loads(body)
        self.assertEqual(response["uid"], uid)
        self.assertEqual(response["runtime"], "8.4")
        for account in ("caddy", "ss4secalpha"):
            self.native(
                f"runuser -u {account} -- test ! -r /var/www/s4secbeta/current/public/index.php"
            )
        self.native("runuser -u caddy -- test -r /var/www/s4secbeta/current/public/hello.txt")
        private_source = "<?php echo 'B_PRIVATE_EXECUTION'; // PRIVATE_SOURCE_CANARY"
        self.native(
            "printf %s "
            + shlex.quote(private_source)
            + " >/var/www/s4secbeta/current/public/private.php; "
            "chown ss4secbeta:ss4secbeta /var/www/s4secbeta/current/public/private.php; "
            "chmod 600 /var/www/s4secbeta/current/public/private.php"
        )
        self.assertEqual(
            self._request("/private.php", "s4secbeta.example.com"), (200, "B_PRIVATE_EXECUTION")
        )
        for suffix in ("txt", "php"):
            self.native(
                "ln -s /var/www/s4secbeta/current/public/private.php "
                f"/var/www/s4secalpha/current/public/alias.{suffix}"
            )
            alias_body = self._request(f"/alias.{suffix}")[1]
            self.assertNotIn("PRIVATE_SOURCE_CANARY", alias_body)
            self.assertNotIn("B_PRIVATE_EXECUTION", alias_body)
        self.assertEqual(self._request("/hello.txt", "s4secbeta.example.com")[0], 200)
        self.assertIn(
            "PHP 8.4.", self.native("runuser -u ss4secbeta -- /var/www/s4secbeta/bin/php -v")
        )
        listeners = self.native("ss -H -ltn").splitlines()
        public_ports = set()
        for line in listeners:
            address, port = line.split()[3].rsplit(":", 1)
            if address == "*" or not ipaddress.ip_address(address.strip("[]")).is_loopback:
                public_ports.add(port)
        self.assertEqual(public_ports, {"22", "80"})
        self.assertEqual(
            self._request(
                "/?token=TOKEN_CANARY&token=SECOND_CANARY&key=KEY_CANARY&signature=SIGNATURE_CANARY"
            )[0],
            200,
        )
        logs = self.native("cat /var/www/s4secalpha/logs/access.json")
        for secret in ("TOKEN_CANARY", "SECOND_CANARY", "KEY_CANARY", "SIGNATURE_CANARY"):
            self.assertNotIn(secret, logs)
        rows = [json.loads(line) for line in logs.splitlines()]
        self.assertTrue(any("REDACTED" in row["request"]["uri"] for row in rows))
        script = (
            "<?php ini_set('display_errors', '0'); "
            "trigger_error('native-log-proof', E_USER_WARNING); sleep(6); echo 'LOG_OK';"
        )
        self.native(
            "printf %s "
            + shlex.quote(script)
            + " >/var/www/s4secbeta/current/public/log.php; chown ss4secbeta:ss4secbeta "
            "/var/www/s4secbeta/current/public/log.php; "
            "chmod 600 /var/www/s4secbeta/current/public/log.php"
        )
        self.assertEqual(self._request("/log.php", "s4secbeta.example.com"), (200, "LOG_OK"))
        self.assertIn("native-log-proof", self.native("cat /var/www/s4secbeta/logs/php-error.log"))
        self.assertIn("log.php", self.native("cat /var/www/s4secbeta/logs/php-slow.log"))

        rotation = """
import http.client
connection = http.client.HTTPConnection('127.0.0.1', timeout=10)
for _ in range(2200):
    connection.request('GET', '/hello.txt?public=' + 'x' * 10000,
                       headers={'Host': 's4secbeta.example.com'})
    response = connection.getresponse()
    if response.status != 200 or response.read() != b'Welcome to your PHP site.\\n':
        raise RuntimeError('The static rotation control stopped serving.')
connection.close()
"""
        self.native(shlex.join(["python3", "-c", rotation]), timeout=120)
        self.native("test $(find /var/www/s4secbeta/logs -name 'access-*' | wc -l) -ge 1")
        self.native("test -S /run/caddy/admin.sock")
        command = """
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/caddy/admin.sock')
except PermissionError:
    pass
else:
    raise RuntimeError('The site account reached the private Caddy socket.')
"""
        self.native(shlex.join(["runuser", "-u", "ss4secbeta", "--", "python3", "-c", command]))
        from .docker import DockerError

        self.native(
            "/nix/var/nix/profiles/default/bin/nix "
            "--extra-experimental-features nix-command store info --store daemon"
        )
        with self.assertRaises(DockerError) as denial:
            self.native(
                "runuser -u ss4secbeta -- /nix/var/nix/profiles/default/bin/nix "
                "--extra-experimental-features nix-command store info --store daemon"
            )
        self.assertIn("cannot open connection", str(denial.exception))
        daemon_log = self.native("journalctl -u nix-daemon.service --no-pager")
        self.assertTrue(
            any("ss4secbeta" in line and "not allowed" in line for line in daemon_log.splitlines()),
            daemon_log,
        )
        self.assertEqual(root_status, 200, repr(root_body))
