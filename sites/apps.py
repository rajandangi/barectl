from typing import override

from django.apps import AppConfig


class SitesConfig(AppConfig):
    name = "sites"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import HANDLER

        register_handler(HANDLER)

        from operations.engine import register_kind

        from .change import CREATE_SITE
        from .node_change import SET_SITE_NODE
        from .php_change import SET_SITE_PHP

        register_kind(CREATE_SITE)
        register_kind(SET_SITE_NODE)
        register_kind(SET_SITE_PHP)
