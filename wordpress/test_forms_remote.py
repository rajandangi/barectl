"""The WordPress Nginx forms under the server's real Nginx and PHP-FPM
(docs/site-conventions.md#wordpress-forms).

The administrator installs each exact form through ``docker exec``; Nginx must accept it,
and requests to it must be routed, gated and denied as the convention says.
"""

import shlex
from typing import ClassVar, override
from unittest import skipUnless

from django.test import SimpleTestCase, tag

from discovery.releases import SUPPORTED
from discovery.test_databases_remote import docker
from discovery.test_remote import CONFIGURED
from discovery.test_sites_remote import FIXTURES, create_site, remove_site
from sites.convention import Application, Stage, render_site

IDENTIFIER = "shop"
NAMES = ("shop.test", "www.shop.test")
PUBLIC = f"/var/www/{IDENTIFIER}/public"
SOURCE = f"/etc/nginx/sites-available/{IDENTIFIER}.conf"
LINEAGE = f"/etc/letsencrypt/live/{IDENTIFIER}"
CHALLENGES = f"/var/lib/letsencrypt/{IDENTIFIER}/.well-known/acme-challenge"
# One request to the local Nginx without following redirects: status, Location and body.
FETCH = """
import http.client, ssl, sys
name, secure, path = sys.argv[1:4]
if secure == "1":
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", 443, context=context, timeout=10)
else:
    connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
connection.request("GET", path, headers={"Host": name})
response = connection.getresponse()
print(response.status, response.getheader("Location") or "-", response.read(200).decode().strip())
"""


def write(path: str, text: str, mode: str = "644", owner: str = "root:root") -> str:
    return f"printf %s {shlex.quote(text)} >{path} && chown {owner} {path} && chmod {mode} {path}"


@tag("ssh")
@skipUnless(FIXTURES and CONFIGURED, "Set BARECTL_SSH_TEST_* and the server's container")
class WordPressFormServingTests(SimpleTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        release = docker(". /etc/os-release; echo $VERSION_ID").strip()
        cls.php = SUPPORTED[release].php

    @override
    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(self.reload)
        self.addCleanup(docker, f"rm -rf {LINEAGE} /var/lib/letsencrypt/{IDENTIFIER}")
        self.addCleanup(docker, remove_site(self.php, IDENTIFIER))
        owner = f"s{IDENTIFIER}:www-data"
        docker(create_site(self.php, IDENTIFIER))
        docker(
            " && ".join(
                (
                    "command -v openssl >/dev/null",
                    f"install -d -m 755 {LINEAGE} {CHALLENGES}",
                    (
                        f"openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN={NAMES[0]} "
                        f"-keyout {LINEAGE}/privkey.pem -out {LINEAGE}/fullchain.pem 2>/dev/null"
                    ),
                    write(f"{CHALLENGES}/token", "challenge-answer"),
                    f"chmod -R a+rX /var/lib/letsencrypt/{IDENTIFIER}",
                    write(f"{PUBLIC}/index.php", '<?php echo "front";', "640", owner),
                    write(f"{PUBLIC}/wp-config.php", "<?php // loader", "640", owner),
                    (
                        f"install -d -o s{IDENTIFIER} -g www-data -m 750 {PUBLIC}/wp-content "
                        f"{PUBLIC}/wp-content/uploads"
                    ),
                    write(
                        f"{PUBLIC}/wp-content/uploads/evil.php", '<?php echo "ran";', "640", owner
                    ),
                    write(
                        f"{PUBLIC}/wp-content/uploads/evil.PHP", '<?php echo "ran";', "640", owner
                    ),
                    "systemctl is-active nginx >/dev/null || systemctl start nginx",
                )
            )
        )

    def reload(self) -> None:
        docker("nginx -t -q && systemctl reload nginx || true")

    def install(
        self,
        application: Application,
        stage: Stage = Stage.REDIRECT,
        canonical: str = "",
        php_version: str = "",
    ) -> None:
        text = render_site(
            IDENTIFIER,
            NAMES,
            ipv6=False,
            stage=stage,
            php_version=php_version,
            application=application,
            canonical=canonical,
        )
        docker(write(SOURCE, text))
        docker("nginx -t -q && systemctl reload nginx")

    def fetch(self, name: str, path: str, *, secure: bool = True) -> tuple[str, ...]:
        script = shlex.quote(FETCH)
        output = docker(
            f"python3 -I -c {script} {name} {'1' if secure else '0'} {shlex.quote(path)}"
        )
        status, location, body = (*output.strip().split(" ", 2), "", "")[:3]
        return status, location, body

    def test_the_ready_form_routes_wordpress_and_denies_what_it_must(self) -> None:
        self.install(Application.WORDPRESS)
        name = NAMES[0]
        self.assertEqual(self.fetch(name, "/"), ("200", "-", "front"))
        self.assertEqual(self.fetch(name, "/a/pretty/permalink?x=1")[0], "200")
        self.assertEqual(self.fetch(name, "/index.php?x=1"), ("200", "-", "front"))
        for denied in (
            "/wp-config.php",
            "/wp-content/uploads/evil.php",
            "/wp-content/uploads/evil.PHP",
            "/wp-content/uploads/evil.php/a.jpg",
            "/wp-content/uploads/evil.phtml",
            "/.git/config",
        ):
            with self.subTest(denied=denied):
                self.assertEqual(self.fetch(name, denied)[0], "403")
        # HTTP redirects to the canonical name and keeps the challenge route.
        self.assertEqual(
            self.fetch(name, "/anything?q=1", secure=False)[:2],
            ("301", f"https://{name}/anything?q=1"),
        )
        self.assertEqual(
            self.fetch(name, "/.well-known/acme-challenge/token", secure=False),
            ("200", "-", "challenge-answer"),
        )
        # An alias never serves the application; it redirects to the canonical name.
        self.assertEqual(self.fetch(NAMES[1], "/x")[:2], ("301", f"https://{name}/x"))

    def test_a_non_first_canonical_name_redirects_http_and_the_first_name(self) -> None:
        self.install(Application.WORDPRESS, canonical=NAMES[1])
        self.assertEqual(self.fetch(NAMES[1], "/")[0], "200")
        self.assertEqual(self.fetch(NAMES[0], "/x")[:2], ("301", f"https://{NAMES[1]}/x"))
        self.assertEqual(
            self.fetch(NAMES[0], "/y", secure=False)[:2], ("301", f"https://{NAMES[1]}/y")
        )

    def test_the_gate_serves_503_for_every_application_path_and_keeps_challenges(self) -> None:
        for stage in (Stage.REDIRECT, Stage.HTTPS):
            with self.subTest(stage=stage):
                self.install(Application.WORDPRESS_GATE, stage)
                name = NAMES[0]
                for path in (
                    "/",
                    "/wp-admin/install.php",
                    "/wp-admin/install.php?step=1",
                    "/index.php",
                    "/anything.php",
                    "/wp-content/uploads/evil.php",
                    "/wp-login.php",
                    "/some/page",
                ):
                    self.assertEqual(self.fetch(name, path)[0], "503", path)
                self.assertEqual(
                    self.fetch(name, "/.well-known/acme-challenge/token", secure=False),
                    ("200", "-", "challenge-answer"),
                )
                if stage == Stage.HTTPS:
                    self.assertEqual(self.fetch(name, "/", secure=False)[0], "503")
                    self.assertEqual(self.fetch(name, "/install.php", secure=False)[0], "503")

    def test_every_form_is_accepted_for_legacy_and_selected_branch_sites(self) -> None:
        for application in (Application.WORDPRESS, Application.WORDPRESS_GATE):
            for stage in (Stage.HTTPS, Stage.REDIRECT):
                for version in ("", self.php):
                    with self.subTest(application=application, stage=stage, version=version):
                        self.install(application, stage, php_version=version)
