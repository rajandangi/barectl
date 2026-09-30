from typing import override

from django.apps import AppConfig


class TlsConfig(AppConfig):
    name = "tls"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import HANDLER, SETUP_HANDLER

        register_handler(HANDLER)
        register_handler(SETUP_HANDLER)
