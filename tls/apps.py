from typing import override

from django.apps import AppConfig


class TlsConfig(AppConfig):
    name = "tls"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import (
            ACTIVATION_HANDLER,
            HANDLER,
            ISSUANCE_HANDLER,
            READINESS_HANDLER,
            SETUP_HANDLER,
            STAGING_HANDLER,
        )

        register_handler(HANDLER)
        register_handler(SETUP_HANDLER)
        register_handler(READINESS_HANDLER)
        register_handler(STAGING_HANDLER)
        register_handler(ISSUANCE_HANDLER)
        register_handler(ACTIVATION_HANDLER)
