from typing import override

from django.apps import AppConfig


class RuntimesConfig(AppConfig):
    name = "runtimes"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import ADD_RUNTIME

        register_kind(ADD_RUNTIME)
