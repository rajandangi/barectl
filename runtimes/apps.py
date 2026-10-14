from typing import override

from django.apps import AppConfig


class RuntimesConfig(AppConfig):
    name = "runtimes"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import ADD_RUNTIME
        from .defaults import SET_DEFAULT_NODE, SET_DEFAULT_PHP

        register_kind(ADD_RUNTIME)
        register_kind(SET_DEFAULT_PHP)
        register_kind(SET_DEFAULT_NODE)
