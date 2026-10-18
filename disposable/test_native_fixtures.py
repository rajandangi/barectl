"""The offline Phase B fixtures, proven end to end on one real server (issue #375).

docs/quality.md#native-layer. One lane server reaches only its lane: the snapshot archive,
the Composer distribution mirror, the fixture Git host and the local ACME server all live
on the lane's internal network. Each method proves one fixture the later Phase B slices
build on.
"""

import os
import shlex
import time
from pathlib import Path

from django.test import tag

from discovery.ssh import RemoteShell

from . import mirror
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class NativeFixtures(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "sf"

    def write(self, shell: RemoteShell, path: str, content: str, mode: int = 0o644) -> None:
        result = shell.run(
            f"install -D -m {mode:o} /dev/stdin {shlex.quote(path)}", stdin=content.encode()
        )
        self.assertEqual(result.exit_status, 0, result.stdout)

    def test_1_apt_resolves_and_installs_git_from_the_lane_snapshot(self) -> None:
        with self.shell() as shell:
            self.write(
                shell,
                "/etc/apt/sources.list.d/barectl-fixture.sources",
                mirror.apt_sources(),
            )
            self.write(
                shell,
                "/etc/apt/apt.conf.d/99barectl-fixture",
                'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
            )
            self.assertEqual(
                shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0
            )
            update = shell.run("apt-get update 2>&1")
            self.assertEqual(update.exit_status, 0, update.stdout)
            resolved = shell.run(
                "apt-get install --simulate --no-install-recommends "
                "mariadb-server postgresql git 2>&1"
            )
            self.assertEqual(resolved.exit_status, 0, resolved.stdout)
            self.assertIn("Inst mariadb-server", resolved.stdout)
            self.assertIn("Inst postgresql-18", resolved.stdout)
            self.assertIn("Inst git", resolved.stdout)
            installed = shell.run(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git 2>&1"
            )
            self.assertEqual(installed.exit_status, 0, installed.stdout)
            self.assertIn("2.53", shell.run("git --version").stdout)

    def test_2_git_clones_over_https_and_ssh_from_the_lane(self) -> None:
        key = Path(os.environ["BARECTL_FIXTURE_GIT_KEY"]).read_text(encoding="utf-8")
        host = os.environ["BARECTL_FIXTURE_GIT_HOST"]
        with self.shell() as shell:
            self.write(shell, "/root/.ssh/fixture-git", key, mode=0o600)
            shell.run("rm -rf /root/fixture-https /root/fixture-ssh")
            https = shell.run(f"git clone -q https://{host}/fixture.git /root/fixture-https 2>&1")
            self.assertEqual(https.exit_status, 0, https.stdout)
            ssh = shell.run(
                "GIT_SSH_COMMAND='ssh -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null -i /root/.ssh/fixture-git' "
                f"git clone -q git@{host}:fixture.git /root/fixture-ssh 2>&1"
            )
            self.assertEqual(ssh.exit_status, 0, ssh.stdout)
            listing = shell.run("ls /root/fixture-https /root/fixture-ssh").stdout
            self.assertIn("composer.lock", listing)
            self.assertEqual(
                shell.run("git -C /root/fixture-https rev-parse HEAD").stdout,
                shell.run("git -C /root/fixture-ssh rev-parse HEAD").stdout,
            )

    def test_3_composer_installs_the_fixture_lock_from_the_mirror(self) -> None:
        with self.shell() as shell:
            self.write(
                shell,
                "/root/.composer/config.json",
                '{"config":{"notify-on-install":false}}\n',
            )
            result = shell.run(
                "PATH=/nix/var/nix/profiles/barectl/php84/bin:"
                "/nix/var/nix/profiles/barectl/composer/bin:$PATH "
                "COMPOSER_HOME=/root/.composer COMPOSER_CACHE_DIR=/root/.composer/cache "
                "composer install --working-dir=/root/fixture-https --no-dev "
                "--no-interaction --prefer-dist --optimize-autoloader --no-plugins "
                "--no-scripts --no-blocking 2>&1"
            )
            self.assertEqual(result.exit_status, 0, result.stdout)
            present = shell.run(
                "test -f /root/fixture-https/vendor/laravel/framework/composer.json && echo present"
            )
            self.assertEqual(present.stdout.strip(), "present")

    def test_4_caddy_obtains_a_certificate_from_the_lane_acme_server(self) -> None:
        root = Path(os.environ["BARECTL_FIXTURE_ACME_ROOT"]).read_text(encoding="utf-8")
        host = os.environ["BARECTL_FIXTURE_ACME_HOST"]
        domain = os.environ["BARECTL_FIXTURE_ACME_DOMAIN"]
        caddyfile = (
            "{\n"
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            f"\tacme_ca https://{host}:14000/dir\n"
            "\tacme_ca_root /etc/caddy/pebble.minica.pem\n"
            "\temail fixture@barectl.test\n"
            "\tservers {\n\t\tstrict_sni_host on\n\t}\n"
            "}\n"
            "import sites/*.caddy\n"
            ":80 {\n\trespond 404\n}\n"
        )
        site = f'{domain} {{\n\trespond "fixture-certificate"\n}}\n'
        with self.shell() as shell:
            self.write(shell, "/etc/caddy/pebble.minica.pem", root)
            self.write(shell, f"/etc/caddy/sites/{self.prefix}acme.caddy", site)
            self.write(shell, "/etc/caddy/Caddyfile", caddyfile)
            validate = shell.run(
                "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
                "--config /etc/caddy/Caddyfile --adapter caddyfile"
            )
            self.assertEqual(validate.exit_status, 0, validate.stdout)
            self.assertEqual(shell.run("systemctl reload caddy").exit_status, 0)
            probe = ""
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                result = shell.run(
                    f"curl --silent --show-error --insecure --resolve {domain}:443:127.0.0.1 "
                    f"https://{domain}/ 2>&1"
                )
                if result.exit_status == 0 and "fixture-certificate" in result.stdout:
                    probe = result.stdout
                    break
                time.sleep(1)
            if "fixture-certificate" not in probe:
                self.fail(
                    "No certificate from Pebble:\n"
                    + self.native("journalctl -u caddy --no-pager -n 40 2>&1")
                    + "\n"
                    + shell.run(
                        f"curl --verbose --insecure --resolve {domain}:443:127.0.0.1 "
                        f"https://{domain}/ 2>&1"
                    ).stdout
                )
            issuer = shell.run(
                f"echo | openssl s_client -connect 127.0.0.1:443 -servername {domain} "
                "2>/dev/null | openssl x509 -noout -issuer"
            )
            self.assertIn("Pebble", issuer.stdout)
