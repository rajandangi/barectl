from typing import override

from django.apps import AppConfig


class WordpressConfig(AppConfig):
    name = "wordpress"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import (
            FINISH_HANDLER,
            INSPECTION_HANDLER,
            INSTALL_HANDLER,
            RUNTIME_HANDLER,
            SETUP_HANDLER,
        )

        register_handler(SETUP_HANDLER)
        register_handler(RUNTIME_HANDLER)
        register_handler(INSTALL_HANDLER)
        register_handler(FINISH_HANDLER)
        register_handler(INSPECTION_HANDLER)
