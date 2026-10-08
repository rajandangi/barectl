from typing import override

from django.apps import AppConfig


class WordpressConfig(AppConfig):
    name = "wordpress"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import SETUP_HANDLER

        register_handler(SETUP_HANDLER)
