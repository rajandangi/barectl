"""A WordPress site created by the product's own reviewed change (Phase B #380).

docs/quality.md#native-layer. The scenario installs MariaDB, creates a WordPress site from
the pinned offline archive, and proves the acceptance criteria on a real Ubuntu 26.04 host:
the site and its database, the pinned core, server-generated salts in a private file, a
first sign-in over HTTPS with the operator's password, pretty permalinks, denied files, and
a fresh-controller reconstruction.
"""

import os
import shlex

from django.test import tag

from discovery.ssh import RemoteShell
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "swpalpha"
DOMAIN = "site.fixture.test"
ADMIN = "barectladmin"
EMAIL = "admin@example.com"
TITLE = "Barectl fixture"
CANARY = "Barectl-Canary-7f3c9a2e"
NEW_CANARY = "Barectl-Canary-2b8d5f10"


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class WordPressCreateCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "swp"

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
            apply_change(self, kinds.INSTALL, PreparationInputs("mariadb"), timeout=180)
        self.assertIn("active", self.native("systemctl is-active mariadb.service"))
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")

    def inputs(self) -> PreparationInputs:
        return PreparationInputs(
            "php84",
            IDENTIFIER,
            (DOMAIN,),
            https=True,
            title=TITLE,
            admin_username=ADMIN,
            admin_email=EMAIL,
        )

    def login_status(self, password: str = CANARY) -> str:
        return self.native(
            "rm -f /tmp/wp.cookies; "
            "curl --silent --show-error --insecure --max-time 20 "
            f"--resolve {DOMAIN}:443:127.0.0.1 "
            "-c /tmp/wp.cookies -b /tmp/wp.cookies "
            f"--data-urlencode log={ADMIN} --data-urlencode pwd={password} "
            "--data-urlencode wp-submit=Log+In "
            f"--data-urlencode redirect_to=https://{DOMAIN}/wp-admin/ "
            "--data-urlencode testcookie=1 "
            f"-o /dev/null -w '%{{http_code}}' https://{DOMAIN}/wp-login.php; "
            "printf ' '; grep -c wordpress_logged_in /tmp/wp.cookies || true"
        ).strip()


@tag(SCENARIO_TAG)
class WordPressCreateMariaDB(WordPressCreateCase):
    def test_1_creates_the_pinned_site_and_signs_in(self) -> None:
        from databases import binding
        from discovery.observations import collect
        from wordpress import create

        self.install_acme()
        self.install_engine()
        inputs = self.inputs()
        apply_change(self, create.CREATE_WORDPRESS, inputs, timeout=120, secret=CANARY.encode())

        base = f"/var/www/{IDENTIFIER}"
        home = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )
        self.assertIn("WordPress", home)
        login = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/wp-login.php"
        )
        self.assertIn("wp-login.php", login)
        signed_in = self.login_status()
        self.assertIn(signed_in.split()[0], ("200", "302"), signed_in)
        self.assertTrue(signed_in.endswith(" 1"), signed_in)
        # Pretty permalinks reach the front controller and the fixed denials still apply.
        for path, expected in (
            ("/wp-json/", "200"),
            ("/wp-config.php", "404"),
            ("/.env", "404"),
            ("/wp-content/uploads/barectl.php", "404"),
        ):
            with self.subTest(path=path):
                status = self.native(
                    "curl --silent --output /dev/null --write-out '%{http_code}' "
                    "--insecure --max-time 20 "
                    f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}{path}"
                )
                self.assertEqual(status.strip(), expected)
        metadata = self.native(
            f"stat -c '%U %G %a' {base}/private/wp-config.php {base}/current/public/wp-config.php"
        ).splitlines()
        self.assertEqual(
            metadata,
            [f"{binding.name_of(IDENTIFIER)} {binding.name_of(IDENTIFIER)} 600"] * 2,
        )
        private = self.native(f"cat {base}/private/wp-config.php")
        for key in ("AUTH_KEY", "SECURE_AUTH_KEY", "NONCE_SALT"):
            self.assertIn(f"define( '{key}', '", private)
        self.assertNotIn(CANARY, private)
        # The password canary appears nowhere outside WordPress's own hash.
        leaked = self.native(
            f"grep -R --binary-files=without-match -l {shlex.quote(CANARY)} "
            f"/var/www {base}/logs /etc/caddy 2>/dev/null || true"
        )
        self.assertEqual(leaked.strip(), "")
        journal = self.native(
            "journalctl --since '-10 min' --no-pager -o cat | grep -F "
            f"{shlex.quote(CANARY)} || true"
        )
        self.assertEqual(journal.strip(), "")
        # Discovery reports the core version without running PHP, and a fresh review is quiet.
        with self.shell() as shell:
            observed = collect(shell)
            site = next(row for row in observed.sites.value if row.identifier == IDENTIFIER)
            self.assertEqual(site.application, "wordpress")
            self.assertEqual(site.application_version, "7.1.3")
            draft = create.review(create.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(
            self.native(
                f"runuser -u {binding.name_of(IDENTIFIER)} -- mariadb --no-defaults "
                f"--protocol=socket --socket={binding.MARIADB_SOCKET} "
                f"{binding.name_of(IDENTIFIER)} -N -B -e 'SELECT 1'"
            ).strip(),
            "1",
        )

    def test_2_resets_the_password_and_verifies_core(self) -> None:
        from operations.inputs import PreparationInputs
        from wordpress import actions

        base = f"/var/www/{IDENTIFIER}"
        # Reset the administrator password over the confidential channel, and prove the
        # new value signs in while the old one does not.
        apply_change(
            self,
            actions.RESET_PASSWORD,
            PreparationInputs("", IDENTIFIER, admin_username=ADMIN),
            timeout=60,
            secret=NEW_CANARY.encode(),
        )
        signed_in = self.login_status(NEW_CANARY)
        self.assertIn(signed_in.split()[0], ("200", "302"), signed_in)
        self.assertTrue(signed_in.endswith(" 1"), signed_in)
        self.assertTrue(self.login_status(CANARY).endswith(" 0"))
        leaked = self.native(
            f"grep -R --binary-files=without-match -l {shlex.quote(NEW_CANARY)} "
            f"/var/www {base}/logs /etc/caddy 2>/dev/null || true"
        )
        self.assertEqual(leaked.strip(), "")
        journal = self.native(
            "journalctl --since '-10 min' --no-pager -o cat | grep -F "
            f"{shlex.quote(NEW_CANARY)} || true"
        )
        self.assertEqual(journal.strip(), "")

        # The installed core matches WordPress.org's official checksums.
        apply_change(
            self,
            actions.VERIFY_CORE,
            PreparationInputs("", IDENTIFIER),
            timeout=60,
        )

        # A modified core file is a mismatch, and the run changes nothing.
        core = f"{base}/current/public/wp-admin/admin.php"
        self.native(f"cp -p {core} /tmp/wp-admin.php.orig")
        self.addCleanup(self.native, f"cp -p /tmp/wp-admin.php.orig {core}")
        self.native(f"printf '\n<?php // tampered\n' >> {core}")
        apply_change(
            self,
            actions.VERIFY_CORE,
            PreparationInputs("", IDENTIFIER),
            timeout=60,
            expected="refused",
            reason="wordpress_checksums",
        )
        self.native(f"cp -p /tmp/wp-admin.php.orig {core}")

        # An unreachable checksum service is a separate outcome, not a mismatch.
        hosts = self.native("cat /etc/hosts")
        self.addCleanup(self.native, "printf %s " + shlex.quote(hosts) + " >/etc/hosts")
        self.native("printf '\n127.0.0.1 api.wordpress.org\n' >>/etc/hosts")
        apply_change(
            self,
            actions.VERIFY_CORE,
            PreparationInputs("", IDENTIFIER),
            timeout=60,
            expected="refused",
            reason="wordpress_checksums_unavailable",
        )
        self.native("printf %s " + shlex.quote(hosts) + " >/etc/hosts")

        # The core still verifies after the file is restored.
        apply_change(
            self,
            actions.VERIFY_CORE,
            PreparationInputs("", IDENTIFIER),
            timeout=60,
        )

    def test_3_edits_extra_constants_and_keeps_the_value_private(self) -> None:
        import json

        from databases import binding
        from wordpress import convention
        from wordpress import settings as wordpress_settings

        canary = "Barectl-Canary-9b4e2c17"
        base = f"/var/www/{IDENTIFIER}"
        private = f"{base}/private/wp-config.php"
        fixed_count = len(
            convention.render_private_configuration(
                IDENTIFIER, ("x" * 64,) * len(convention.SALTS)
            ).splitlines()
        )
        apply_change(
            self,
            wordpress_settings.EDIT_SETTINGS,
            PreparationInputs("", IDENTIFIER, settings_changes=(("MAIL_HOST", "set"),)),
            timeout=60,
            secret=json.dumps({"values": {"MAIL_HOST": canary}}).encode(),
        )
        configured = self.native(f"cat {private}")
        self.assertIn(f"define( 'MAIL_HOST', '{canary}' );", configured)
        self.assertEqual(
            self.native(f"stat -c '%U %a' {private}").strip(),
            f"{binding.name_of(IDENTIFIER)} 600",
        )
        leaked = self.native(
            f"grep -R --binary-files=without-match -l {shlex.quote(canary)} "
            f"{base}/current {base}/releases {base}/logs /etc/caddy 2>/dev/null || true"
        )
        self.assertEqual(leaked.strip(), "")
        journal = self.native(
            "journalctl --since '-10 min' --no-pager -o cat | grep -F "
            f"{shlex.quote(canary)} || true"
        )
        self.assertEqual(journal.strip(), "")

        # The fixed Barectl block stays byte-identical when one constant changes.
        fixed = configured.splitlines()[:fixed_count]
        apply_change(
            self,
            wordpress_settings.EDIT_SETTINGS,
            PreparationInputs("", IDENTIFIER, settings_changes=(("MAIL_HOST", "set"),)),
            timeout=60,
            secret=json.dumps({"values": {"MAIL_HOST": "mail.example.com"}}).encode(),
        )
        changed = self.native(f"cat {private}")
        self.assertEqual(changed.splitlines()[:fixed_count], fixed)
        self.assertIn("define( 'MAIL_HOST', 'mail.example.com' );", changed)
        self.assertNotIn(canary, changed)

        # A removal needs no confidential value and leaves the fixed block alone.
        apply_change(
            self,
            wordpress_settings.EDIT_SETTINGS,
            PreparationInputs("", IDENTIFIER, settings_changes=(("MAIL_HOST", "remove"),)),
            timeout=60,
        )
        removed = self.native(f"cat {private}")
        self.assertNotIn("MAIL_HOST", removed)
        self.assertEqual(removed.splitlines()[:fixed_count], fixed)

    def test_4_removes_the_wordpress_site_and_its_resources(self) -> None:
        from databases import binding
        from sites import remove as remove_kind

        base = f"/var/www/{IDENTIFIER}"
        self.assertEqual(
            self.native(f"test -f {base}/current/public/wp-includes/version.php; echo $?").strip(),
            "0",
        )
        review = apply_change(
            self, remove_kind.REMOVE, PreparationInputs("", IDENTIFIER), timeout=120
        )
        self.assertEqual(review.document["confirmation"], DOMAIN)
        self.assertNotIn(
            "WordPress",
            self.native(
                f"curl --fail --silent --max-time 10 -H 'Host: {DOMAIN}' http://127.0.0.1/ || true"
            ),
        )
        self.assertEqual(
            self.native(
                f"test ! -e /etc/caddy/sites/{IDENTIFIER}.caddy && test ! -e {base} "
                f"&& test ! -e /etc/haproxy/sites/{IDENTIFIER}.cfg "
                f"&& test ! -e /etc/php-fpm/sites/{IDENTIFIER} && echo gone || echo remains"
            ).strip(),
            "gone",
        )
        self.assertEqual(
            self.native(f"getent passwd s{IDENTIFIER} || echo absent").strip(), "absent"
        )
        self.assertEqual(
            self.native(f"getent passwd p{IDENTIFIER} || echo absent").strip(), "absent"
        )
        principal = binding.name_of(IDENTIFIER)
        query = (
            "SELECT COUNT(*) FROM information_schema.SCHEMATA "  # noqa: S608 - fixed names
            f"WHERE SCHEMA_NAME='{principal}';"
            "SELECT COUNT(*) FROM mysql.global_priv "
            f"WHERE User='{principal}'"
        )
        self.assertEqual(
            self.native(
                "mariadb --no-defaults --protocol=socket --socket="
                + binding.MARIADB_SOCKET
                + " -N -B -e "
                + shlex.quote(query)
            ).split(),
            ["0", "0"],
        )
        self.assertEqual(
            self.native(f"find /var/lib/caddy -name {shlex.quote(DOMAIN + '*')} | wc -l").strip(),
            "0",
        )

        # A Barectl-owned name is refused before anything changes.
        from wordpress import settings as reviewed

        with self.shell() as shell:
            draft = reviewed.review(
                reviewed.inspect(
                    shell,
                    PreparationInputs("", IDENTIFIER, settings_changes=(("AUTH_KEY", "set"),)),
                ),
                PreparationInputs("", IDENTIFIER, settings_changes=(("AUTH_KEY", "set"),)),
            )
            self.assertFalse(draft.eligible)
            self.assertIn("AUTH_KEY is owned by Barectl and cannot be edited.", draft.refusals)
