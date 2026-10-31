from typing import override

from django.apps import AppConfig


class SecurityConfig(AppConfig):
    name = "security"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import SET_AUTOMATIC_SECURITY_UPDATES

        register_kind(SET_AUTOMATIC_SECURITY_UPDATES)
