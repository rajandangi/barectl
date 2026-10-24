from typing import override

from django.apps import AppConfig


class BootstrapConfig(AppConfig):
    name = "bootstrap"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .certificate_email import SET_CERTIFICATE_EMAIL
        from .foundation import HOST_FOUNDATION

        register_kind(HOST_FOUNDATION)
        register_kind(SET_CERTIFICATE_EMAIL)
