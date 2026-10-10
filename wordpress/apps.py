from typing import override

from django.apps import AppConfig


class WordpressConfig(AppConfig):
    name = "wordpress"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler
        from operations.lifecycle import register_completion

        from .access_reset_handler import ACCESS_HANDLER
        from .access_reset_services import completed
        from .handler import (
            FINISH_HANDLER,
            INSPECTION_HANDLER,
            INSTALL_HANDLER,
            MAINTENANCE_HANDLER,
            RUNTIME_HANDLER,
            SETUP_HANDLER,
        )

        register_handler(SETUP_HANDLER)
        register_handler(RUNTIME_HANDLER)
        register_handler(INSTALL_HANDLER)
        register_handler(FINISH_HANDLER)
        register_handler(INSPECTION_HANDLER)
        register_handler(MAINTENANCE_HANDLER)
        register_handler(ACCESS_HANDLER)
        register_completion(completed)
