import re
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.observation import COMMON_SOURCE, PHP_TRANSITION_INCOMPLETE
from sites.recognition import CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT
from sites.ui_testing import record_shaped_sites


def rows(html: str, table_id: str) -> list[str]:
    """Each table row's visible text, whitespace collapsed; empty when the table is absent."""
    table = re.search(rf'<table[^>]*id="{table_id}".*?</table>', html, re.DOTALL)
    return [
        " ".join(re.sub(r"<[^>]+>", " ", row).split())
        for row in re.findall(r"<tr>(.*?)</tr>", table.group(0) if table else "", re.DOTALL)[1:]
    ]


def pool(identifier: str, runtime: str = "php84") -> str:
    return f"/etc/php-fpm/sites/{identifier}/{runtime}/pools/{identifier}.conf {identifier}"


class ReaderFindingTests(SimpleTestCase):
    def test_recognition_follows_the_native_readers_own_findings(self) -> None:
        # Joins implicitly concatenated string literals split across lines.
        source = re.sub(r'"\s*\n\s*"', "", COMMON_SOURCE)
        for finding in (CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT):
            with self.subTest(finding=finding):
                self.assertIn(f'"{finding}"', source)


class StackRecognitionTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_shaped_sites(self.server)

    def page(self, url: str) -> str:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_web_lists_each_site_file_as_recognized_or_unsupported(self) -> None:
        html = self.page(f"/servers/{self.server.pk}/stack/?tab=web")
        self.assertEqual(
            rows(html, "site-files"),
            [
                "/etc/caddy/sites/alpha.caddy alpha Recognized",
                "/etc/caddy/sites/beta.caddy beta Recognized",
                f"/etc/caddy/sites/gamma.caddy gamma Outside supported settings {CADDY_OUTSIDE}",
                "/etc/caddy/sites/delta.caddy delta Recognized",
                f"/etc/caddy/sites/omega.caddy omega Absent {ROUTE_ABSENT}",
            ],
        )

    def test_php_runtimes_lists_each_site_pool_as_recognized_or_unsupported(self) -> None:
        html = self.page(f"/servers/{self.server.pk}/stack/?tab=php")
        self.assertEqual(
            rows(html, "site-pools"),
            [
                f"{pool('alpha')} Recognized",
                f"{pool('beta')} Outside supported settings {POOL_OUTSIDE}",
                f"{pool('gamma')} Not confirmed {CADDY_OUTSIDE}",
                f"{pool('delta', 'php85')} Not confirmed {PHP_TRANSITION_INCOMPLETE}",
                f"{pool('omega')} Not confirmed {ROUTE_ABSENT}",
            ],
        )
