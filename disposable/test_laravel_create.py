"""A Laravel site created by the product's own reviewed change (Phase B #382).

docs/quality.md#native-layer. The scenario installs MariaDB (with Git), creates a Laravel
site from the lane's fixture Git repository over SSH, and proves the acceptance criteria on
a real Ubuntu 26.04 host: the site and its database, the private environment with a
generated ``APP_KEY``, an ed25519 deploy key whose private half never leaves the server, a
repository host key trusted only by an exact fingerprint match, and a fresh-controller
reconstruction.
"""

import json
import os
import shlex
from typing import cast

from django.test import tag

from discovery.ssh import RemoteShell
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "slcalpha"
# The lane's DNS resolves the fixture domain to the server itself, so Caddy's automatic
# HTTPS issues a real certificate from the lane's Pebble ACME server.
DOMAIN = "site.fixture.test"
MARIADB_SOCKET = "/run/mysqld/mysqld.sock"
WRONG_FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class LaravelCreateCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "slc"

    def router(self, shell: RemoteShell) -> None:
        write(self, shell, "/etc/apt/sources.list.d/barectl-fixture.sources", mirror.apt_sources())
        write(
            self,
            shell,
            "/etc/apt/apt.conf.d/99barectl-fixture",
            'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
        )
        self.assertEqual(shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0)
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)

    def caddyfile(self, acme_host: str) -> str:
        return (
            "{\n"
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            f"\tacme_ca https://{acme_host}:14000/dir\n"
            "\tacme_ca_root /etc/caddy/pebble.minica.pem\n"
            "\tservers {\n\t\tstrict_sni_host on\n\t}\n"
            "}\n"
            "import sites/*.caddy\n"
            ":80 {\n\trespond 404\n}\n"
        )

    def install_acme(self) -> None:
        root = os.environ["BARECTL_FIXTURE_ACME_ROOT"]
        host = os.environ["BARECTL_FIXTURE_ACME_HOST"]
        with open(root, encoding="utf-8") as handle:
            certificate = handle.read()
        original = self.native("cat /etc/caddy/Caddyfile")
        self.addCleanup(
            self.native,
            "printf %s " + shlex.quote(original) + " >/etc/caddy/Caddyfile; systemctl reload caddy",
        )
        self.native(
            "printf %s "
            + shlex.quote(certificate)
            + " >/etc/caddy/pebble.minica.pem; chmod 644 /etc/caddy/pebble.minica.pem"
        )
        self.native("printf %s " + shlex.quote(self.caddyfile(host)) + " >/etc/caddy/Caddyfile")
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /etc/caddy/Caddyfile --adapter caddyfile"
        )
        self.native("chown root:root /etc/caddy/Caddyfile; chmod 644 /etc/caddy/Caddyfile")
        self.native("systemctl reload caddy")

    def install_engine(self) -> None:
        from databases import engine as kinds

        with self.shell() as shell:
            self.router(shell)
            apply_change(self, kinds.INSTALL, PreparationInputs("mariadb", git=True), timeout=180)
        self.assertIn("active", self.native("systemctl is-active mariadb.service"))
        # A package transaction reloads systemd and clears the running foundation masters'
        # loaded-execution metadata; restart them, as ordinary administration, so the site
        # review's live protections are current again.
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")

    def repository(self) -> str:
        return f"git@{os.environ['BARECTL_FIXTURE_GIT_HOST']}:fixture.git"

    def fingerprint(self) -> str:
        host = os.environ["BARECTL_FIXTURE_GIT_HOST"]
        return self.native(
            f"ssh-keyscan -T 5 -t ed25519 {host} 2>/dev/null "
            "| ssh-keygen -lf - | head -1 | cut -d' ' -f2"
        ).strip()

    def inputs(self, *, fingerprint: str) -> PreparationInputs:
        return PreparationInputs(
            "php84",
            IDENTIFIER,
            (DOMAIN,),
            https=True,
            repository=self.repository(),
            branch="main",
            fingerprint=fingerprint,
        )

    def create(self, *, fingerprint: str) -> None:
        from laravel import create

        apply_change(self, create.CREATE_LARAVEL, self.inputs(fingerprint=fingerprint), timeout=180)


@tag(SCENARIO_TAG)
class LaravelCreateMariaDB(LaravelCreateCase):
    records: tuple[str, ...] = ("laravel-create-26.04",)

    def test_1_creates_the_site_database_environment_and_deploy_key(self) -> None:
        from databases import binding
        from laravel import create

        self.install_acme()
        self.install_engine()
        fingerprint = self.fingerprint()
        self.assertTrue(fingerprint.startswith("SHA256:"), fingerprint)
        self.create(fingerprint=fingerprint)
        base = f"/var/www/{IDENTIFIER}"
        # The site serves its placeholder as the site user over HTTPS.
        served = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )
        self.assertIn(IDENTIFIER, served)
        # The private environment holds Laravel's production defaults and the socket database.
        environment = self.native(f"cat {base}/private/laravel.env")
        for line in (
            "APP_ENV=production",
            "APP_DEBUG=false",
            f"APP_URL=https://{DOMAIN}",
            "LOG_CHANNEL=daily",
            "LOG_DAILY_DAYS=14",
            "DB_CONNECTION=mariadb",
            f"DB_DATABASE={binding.name_of(IDENTIFIER)}",
            f"DB_USERNAME={binding.name_of(IDENTIFIER)}",
            "DB_PASSWORD=",
            f"DB_SOCKET={MARIADB_SOCKET}",
        ):
            self.assertIn(line, environment, environment)
        app_key = next(
            (value for value in environment.splitlines() if value.startswith("APP_KEY=")), ""
        )
        self.assertRegex(app_key, r"^APP_KEY=base64:[A-Za-z0-9+/]{43}=$")
        # The deploy key lives in the site's private area; only its public half is readable.
        metadata = self.native(
            f"stat -c '%U %G %a' {base}/private/deploy_key {base}/private/deploy_key.pub "
            f"{base}/private/known_hosts {base}/current/artisan"
        ).splitlines()
        self.assertEqual(
            metadata,
            [
                f"{binding.name_of(IDENTIFIER)} {binding.name_of(IDENTIFIER)} 600",
                f"{binding.name_of(IDENTIFIER)} {binding.name_of(IDENTIFIER)} 644",
                f"{binding.name_of(IDENTIFIER)} {binding.name_of(IDENTIFIER)} 600",
                f"{binding.name_of(IDENTIFIER)} {binding.name_of(IDENTIFIER)} 600",
            ],
        )
        public_key = self.native(f"cat {base}/private/deploy_key.pub").strip()
        self.assertTrue(public_key.startswith("ssh-ed25519 "), public_key)
        # The trusted host key is exactly the one whose fingerprint the review matched.
        known = self.native(f"cat {base}/private/known_hosts").strip()
        self.assertTrue(known, "no repository host key was trusted")
        self.assertEqual(
            self.native(
                f"printf '%s\\n' {shlex.quote(known)} | ssh-keygen -lf - | cut -d' ' -f2"
            ).strip(),
            self.fingerprint(),
        )
        # The first release carries the reviewed repository and branch as native Git metadata.
        config = self.native(f"cat {base}/current/.git/config")
        self.assertIn(self.repository(), config)
        self.assertTrue(self.native(f"readlink {base}/current").startswith("releases/bootstrap-"))
        # The site's database binding is satisfied and reaches the site user over the socket.
        self.assertEqual(
            self.native(
                f"runuser -u {binding.name_of(IDENTIFIER)} -- mariadb --no-defaults "
                f"--protocol=socket --socket={MARIADB_SOCKET} {binding.name_of(IDENTIFIER)} "
                "-N -B -e 'SELECT 1'"
            ).strip(),
            "1",
        )
        # A fresh review over the same site proposes no changes.
        with self.shell() as shell:
            inputs = self.inputs(fingerprint=fingerprint)
            draft = create.review(create.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertTrue(draft.no_changes, draft.refusals)

    def test_2_a_wrong_repository_fingerprint_is_refused(self) -> None:
        from laravel import create

        with self.shell() as shell:
            inputs = self.inputs(fingerprint=WRONG_FINGERPRINT)
            draft = create.review(create.inspect(shell, inputs), inputs)
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("does not match the fingerprint" in refusal for refusal in draft.refusals),
            draft.refusals,
        )

    def test_3_a_fresh_controller_reconstructs_the_site_and_its_key(self) -> None:
        from databases import binding
        from discovery.observations import collect
        from laravel import observation

        with self.shell() as fresh:
            laravel = observation.read(fresh)
            row = observation.site(laravel or {}, IDENTIFIER)
            if row is None:
                self.fail(f"The site's release layout was not read: {laravel}")
            self.assertEqual(row["application"], "laravel")
            self.assertEqual(row["repository"], self.repository())
            self.assertEqual(row["branch"], "main")
            self.assertTrue(all(cast(dict[str, bool], row["shared"]).values()))
            # The `.env` key names, never a value, and the deploy key's public half.
            environment = cast(list[str], row["environment"])
            self.assertIn("APP_ENV", environment)
            self.assertIn("APP_KEY", environment)
            self.assertIn("DB_CONNECTION", environment)
            self.assertNotIn("APP_KEY=base64", " ".join(environment))
            self.assertEqual(
                row["deploy_key"],
                self.native(f"cat /var/www/{IDENTIFIER}/private/deploy_key.pub").strip(),
            )
            self.assertTrue(row["host_keys"])
            # A full discovery read on the same shell, so the recorded transcript also
            # carries the host-standing judgment.
            loaded = collect(fresh, releases=True)
            releases = [
                release for release in loaded.releases.value if release.identifier == IDENTIFIER
            ]
            self.assertEqual(len(releases), 1)
            self.assertTrue(releases[0].name.startswith("bootstrap-"), releases[0].name)
            self.assertTrue(releases[0].current)
            self.checkpoint("laravel-create-26.04", fresh)
        self.assertEqual(
            self.native(f"stat -c '%a' /var/www/{IDENTIFIER}/private/deploy_key").strip(),
            "600",
        )
        self.assertEqual(binding.name_of(IDENTIFIER), f"s{IDENTIFIER}")

    def test_4_edits_the_environment_and_keeps_the_secret_private(self) -> None:
        from databases import binding
        from laravel import settings

        if self.record_state:
            self.skipTest("Recording stops after the transcript checkpoint.")

        canary = "Barectl-Canary-6d2f4a91"
        path = f"/var/www/{IDENTIFIER}/private/laravel.env"
        apply_change(
            self,
            settings.EDIT_ENVIRONMENT,
            PreparationInputs(
                "",
                IDENTIFIER,
                settings_changes=(("MAIL_PASSWORD", "set"), ("MAIL_FROM_ADDRESS", "set")),
            ),
            timeout=60,
            secret=json.dumps(
                {"values": {"MAIL_PASSWORD": canary, "MAIL_FROM_ADDRESS": "bot@example.com"}}
            ).encode(),
        )
        private = self.native(f"cat {path}")
        self.assertIn("MAIL_PASSWORD=", private)
        self.assertIn("MAIL_FROM_ADDRESS=bot@example.com", private)
        self.assertIn(canary, private)
        self.assertEqual(
            self.native(f"stat -c '%U %a' {path}").strip(),
            f"{binding.name_of(IDENTIFIER)} 600",
        )
        leaked = self.native(
            f"find /var/www/{IDENTIFIER}/current /var/www/{IDENTIFIER}/releases "
            f"/var/www/{IDENTIFIER}/logs /etc/caddy -type f -print0 2>/dev/null "
            f"| xargs -0 -r grep --binary-files=without-match -l -F {shlex.quote(canary)} "
            "2>/dev/null || true"
        )
        self.assertEqual(leaked.strip(), "")
        journal = self.native(
            "journalctl --since '-10 min' --no-pager -o cat | grep -F "
            f"{shlex.quote(canary)} || true"
        )
        self.assertEqual(journal.strip(), "")

        # A second edit leaves every untouched line byte-identical.
        self.native(f"cp {path} /tmp/laravel.env.before")
        apply_change(
            self,
            settings.EDIT_ENVIRONMENT,
            PreparationInputs("", IDENTIFIER, settings_changes=(("MAIL_FROM_ADDRESS", "set"),)),
            timeout=60,
            secret=json.dumps({"values": {"MAIL_FROM_ADDRESS": "other@example.com"}}).encode(),
        )
        difference = self.native(f"diff -u /tmp/laravel.env.before {path} || true")
        removed = [
            line
            for line in difference.splitlines()
            if line.startswith("-") and not line.startswith(("---", "-MAIL_FROM_ADDRESS="))
        ]
        added = [
            line
            for line in difference.splitlines()
            if line.startswith("+") and not line.startswith(("+++", "+MAIL_FROM_ADDRESS="))
        ]
        self.assertEqual((removed, added), ([], []))
        self.assertIn("MAIL_FROM_ADDRESS=other@example.com", self.native(f"cat {path}"))
