"""ADR 0015 states reconstructed by independent controllers on disposable servers."""

import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import override
from unittest import skipUnless

from django.test import SimpleTestCase, tag

from dashboard.testing import TEST_MANIFEST

from .fakes import pool_config, site_config
from .native_testing import reconstruct
from .observations.databases import postgresql_command
from .releases import SUPPORTED

_REQUIRED = (
    "CONTAINER",
    "HOST",
    "PORT",
    "KEY",
    "SECOND_KEY",
    "KNOWN_HOSTS",
    "UNPRIVILEGED_USER",
)
_CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in _REQUIRED)


def setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


def docker(script: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed scripts in a disposable test container
        ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout


def write(path: str, content: str) -> str:
    return f"printf %s {shlex.quote(content)} > {path} && chmod 644 {path}"


def hand_made_site(php: str, identifier: str) -> str:
    user = f"s{identifier}"
    boundary = f"/var/www/{identifier}"
    source = f"/etc/nginx/sites-available/{identifier}.conf"
    return " && ".join(
        (
            (
                f"useradd --home-dir {boundary} --no-create-home "
                f"--shell /usr/sbin/nologin --user-group {user}"
            ),
            f"install -d -o root -g root -m 755 {boundary}",
            f"install -d -o {user} -g www-data -m 750 {boundary}/public",
            f"install -d -o {user} -g {user} -m 700 {boundary}/private",
            write(source, site_config(identifier, (f"{identifier}.test",))),
            f"ln -s {source} /etc/nginx/sites-enabled/{identifier}.conf",
            write(f"/etc/php/{php}/fpm/pool.d/{identifier}.conf", pool_config(identifier)),
        )
    )


@tag("ssh")
@skipUnless(_CONFIGURED, "Set the disposable server and both controller keys")
class ConventionReconstructionTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        release = docker(". /etc/os-release; echo $VERSION_ID").strip()
        self.php = SUPPORTED[release].php
        self.major = SUPPORTED[release].postgresql
        self.addCleanup(self.remove_fixtures)
        docker(hand_made_site(self.php, "alpha"))
        docker(hand_made_site(self.php, "gamma"))
        source = "/etc/nginx/sites-available/beta.conf"
        docker(write(source, site_config("beta", ("beta.test",))))
        docker(f"ln -s {source} /etc/nginx/sites-enabled/beta.conf")
        docker(
            "nginx -t -q && "
            f"php-fpm{self.php} -t && systemctl reload php{self.php}-fpm && "
            "systemctl reload nginx"
        )
        docker(
            "sed -i 's|root /var/www/gamma/public;|root /var/www/elsewhere/public;|' "
            "/etc/nginx/sites-available/gamma.conf"
        )
        docker(
            write(
                "/etc/nginx/sites-enabled/foreign-site",
                "server { listen 80; server_name foreign.test; }\n",
            )
        )
        docker(
            write(
                f"/etc/php/{self.php}/fpm/pool.d/foreign-pool.conf",
                "[foreign-pool]\nuser = www-data\ngroup = www-data\n"
                "listen = /run/php/foreign.sock\npm = ondemand\npm.max_children = 1\n",
            )
        )
        docker("runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -c 'CREATE ROLE salpha LOGIN'")

    def remove_fixtures(self) -> None:
        docker("runuser -u postgres -- psql -X -c 'DROP DATABASE IF EXISTS salpha'")
        docker("runuser -u postgres -- psql -X -c 'DROP ROLE IF EXISTS salpha'")
        for identifier in ("alpha", "beta", "gamma"):
            docker(
                f"rm -f /etc/nginx/sites-enabled/{identifier}.conf "
                f"/etc/nginx/sites-available/{identifier}.conf "
                f"/etc/php/{self.php}/fpm/pool.d/{identifier}.conf; "
                f"rm -rf /var/www/{identifier}; "
                f"id s{identifier} >/dev/null 2>&1 && userdel s{identifier}; true"
            )
        docker(
            "rm -f /etc/nginx/sites-enabled/foreign-site "
            f"/etc/php/{self.php}/fpm/pool.d/foreign-pool.conf; "
            f"systemctl reload php{self.php}-fpm; systemctl reload nginx"
        )

    def controller(self, name: str, key: str, user: str = "root") -> dict[str, object]:
        config = self.directory / f"{name}.config"
        config.write_text(
            f"Host disposable\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {user}\n  IdentityFile {setting(key)}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )
        report = reconstruct(self.directory / name, config, TEST_MANIFEST)
        self.assertEqual(report["status"], "succeeded", report["failure"])
        self.assertEqual(report["page_status"], 200)
        self.assertEqual((report["runs"], report["preparations"]), (0, 0))
        return report

    def native_evidence(self) -> str:
        scripts = (
            "find /etc /var/www -xdev -type f -exec sha256sum {} + | sort | sha256sum",
            "find /etc /var/www -xdev -printf '%p %y %m %U %G %n %T@ %l\\n' | sort | sha256sum",
            (
                f"systemctl show nginx.service php{self.php}-fpm.service "
                f"postgresql@{self.major}-main.service -p Id -p MainPID -p ActiveState "
                "-p SubState -p ActiveEnterTimestamp -p StateChangeTimestamp | sha256sum"
            ),
            f"{postgresql_command(('salpha', 'sbeta', 'sgamma'))} | sha256sum",
        )
        return docker("bash -o pipefail -c " + shlex.quote("set -e; " + "; ".join(scripts)))

    def test_every_convention_state_agrees_on_a_fresh_controller(self) -> None:
        before = self.native_evidence()
        first = self.controller("first", "KEY")
        second = self.controller("second", "SECOND_KEY")
        self.assertEqual(second["sites"], first["sites"])
        self.assertEqual(second["components"], first["components"])
        self.assertEqual(self.native_evidence(), before)
        sites = first["sites"]
        assert isinstance(sites, list)  # noqa: S101 - the report boundary was validated
        named = {site["identifier"]: site for site in sites if site["identifier"]}
        self.assertEqual(named["alpha"]["state"], "managed")
        self.assertTrue(named["alpha"]["database"]["partial"])
        self.assertEqual(named["gamma"]["state"], "changed")
        self.assertEqual(named["gamma"]["file"], "/etc/nginx/sites-available/gamma.conf")
        self.assertIn("root /var/www/gamma/public;", named["gamma"]["expected"])
        self.assertEqual(named["beta"]["state"], "partly_applied")
        blocked = {site["file"] for site in sites if site["state"] == "not_following"}
        self.assertIn("/etc/nginx/sites-enabled/foreign-site", blocked)
        self.assertIn(f"/etc/php/{self.php}/fpm/pool.d/foreign-pool.conf", blocked)
        components = first["components"]
        assert isinstance(components, list)  # noqa: S101 - the report boundary was validated
        postgres = next(item for item in components if item["component"] == "postgresql")
        self.assertFalse(postgres["managed"])
        self.assertTrue(any("archive" in item for item in postgres["deviations"]))
        units = {item[0] for item in postgres["service"]["value"]}
        self.assertEqual(units, {"postgresql.service", f"postgresql@{self.major}-main.service"})
        self.assertIn("Changed outside Barectl", str(second["page"]))
        self.assertIn("Partly applied", str(second["page"]))
        self.assertIn("Not following the convention", str(second["page"]))
        observer = self.controller("observer", "SECOND_KEY", setting("UNPRIVILEGED_USER"))
        observed_sites = observer["sites"]
        assert isinstance(observed_sites, list)  # noqa: S101 - report boundary was validated
        alpha = next(site for site in observed_sites if site["identifier"] == "alpha")
        self.assertEqual(alpha["outcome"], "inaccessible")
        self.assertNotEqual(alpha["state"], "changed")
        self.assertEqual(self.native_evidence(), before)
        statements = (
            (
                'CREATE DATABASE "salpha" WITH OWNER "salpha" TEMPLATE template0 '
                "ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'"
            ),
            'REVOKE CONNECT, TEMPORARY ON DATABASE "salpha" FROM PUBLIC',
        )
        for statement in statements:
            docker(f"runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -c {shlex.quote(statement)}")
        docker(
            "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d salpha "
            "-c 'REVOKE ALL ON SCHEMA public FROM PUBLIC'"
        )
        before = self.native_evidence()
        satisfied = self.controller("satisfied-first", "KEY")
        rebuilt = self.controller("satisfied-second", "SECOND_KEY")
        self.assertEqual(rebuilt["sites"], satisfied["sites"])
        self.assertEqual(rebuilt["components"], first["components"])
        satisfied_sites = rebuilt["sites"]
        assert isinstance(satisfied_sites, list)  # noqa: S101 - report boundary was validated
        alpha = next(site for site in satisfied_sites if site["identifier"] == "alpha")
        self.assertTrue(alpha["database"]["conforms"])
        self.assertFalse(alpha["database"]["partial"])
        for site in satisfied_sites:
            if site["identifier"] != "alpha":
                self.assertIn(site, sites)
        self.assertEqual(self.native_evidence(), before)
