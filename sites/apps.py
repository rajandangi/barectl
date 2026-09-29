from typing import override

from django.apps import AppConfig


class SitesConfig(AppConfig):
    name = "sites"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import HANDLER

        register_handler(HANDLER)
