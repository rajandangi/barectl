"""The prepared-WordPress snapshot layer: L1 plus MariaDB and one WordPress site.

docs/quality.md#native-layer. Phase C's WordPress scenarios need a real, product-created
WordPress site. Creating it (with its database engine) costs more than one item and more
than a shard can carry, so it is committed once into the keyed L3 image and every later
scenario starts from it, exactly as L2 does for a plain site.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

from django.test import tag

from discovery.ssh import RemoteShell
from operations.inputs import PreparationInputs

from . import images
from .change_testing import apply_change
from .docker import docker
from .scenario_testing import SCENARIO_TAG
from .test_wordpress_create import CANARY, WordPressCreateCase
from .wordpress_testing import (
    WORDPRESS_ADMIN,
    WORDPRESS_DOMAIN,
    WORDPRESS_EMAIL,
    WORDPRESS_SITE,
    WORDPRESS_TITLE,
)

OTHER_SITE = "l4other"
OTHER_DOMAIN = "l4other.example.com"


class PreparedWordPressCase(WordPressCreateCase):
    """A preparation uses a plain connection: a recording shell refuses secret staging."""

    exclusive = True
    prefix = ""
    preparation = True

    @override
    @contextmanager
    def shell(self) -> Iterator[RemoteShell]:
        from discovery import ssh

        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection


@tag(SCENARIO_TAG)
class PrepareWordPress(PreparedWordPressCase):
    layer = "L1"

    @override
    def inputs(self) -> PreparationInputs:
        return PreparationInputs(
            "php84",
            WORDPRESS_SITE,
            (WORDPRESS_DOMAIN,),
            https=False,
            title=WORDPRESS_TITLE,
            admin_username=WORDPRESS_ADMIN,
            admin_email=WORDPRESS_EMAIL,
        )

    def test_commits_a_wordpress_site_into_the_prepared_wordpress_layer(self) -> None:
        from wordpress import create

        self.install_engine()
        apply_change(
            self,
            create.CREATE_WORDPRESS,
            self.inputs(),
            timeout=180,
            secret=CANARY.encode(),
        )
        served = self.native(
            f"curl --fail --silent --show-error --max-time 20 -H 'Host: {WORDPRESS_DOMAIN}' "
            "http://127.0.0.1/"
        )
        self.assertIn("WordPress", served)
        image = images.tag("L3")
        if not images.exists(image):
            docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
        self.assertEqual(images.ensure("L3"), image)


@tag(SCENARIO_TAG)
class PrepareWordPressCache(PreparedWordPressCase):
    """L3 plus Valkey and the site's PHP client, so a cache scenario stays a small item."""

    layer = "L3"

    def test_commits_the_cache_prerequisites_into_the_prepared_cache_layer(self) -> None:
        from cache import engine as cache_engine
        from sites import change as site_change
        from sites.client_change import SET_SITE_PHP_CLIENT

        apply_change(
            self,
            site_change.CREATE_SITE,
            PreparationInputs("php84", OTHER_SITE, (OTHER_DOMAIN,)),
            timeout=120,
        )
        apply_change(self, cache_engine.INSTALL, PreparationInputs(), timeout=180)
        apply_change(
            self,
            SET_SITE_PHP_CLIENT,
            PreparationInputs(identifier=WORDPRESS_SITE, php_client=True),
            timeout=180,
        )
        image = images.tag("L4")
        if not images.exists(image):
            docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
        self.assertEqual(images.ensure("L4"), image)


__all__ = ["PrepareWordPress", "PrepareWordPressCache"]
