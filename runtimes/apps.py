from typing import override

from django.apps import AppConfig


class RuntimesConfig(AppConfig):
    name = "runtimes"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import ADD_RUNTIME
        from .defaults import SET_DEFAULT_NODE, SET_DEFAULT_PHP
        from .remove import REMOVE_RUNTIME
        from .revert import REVERT_RUNTIME
        from .update import UPDATE_CATALOG

        register_kind(ADD_RUNTIME)
        register_kind(SET_DEFAULT_PHP)
        register_kind(SET_DEFAULT_NODE)
        register_kind(REMOVE_RUNTIME)
        register_kind(UPDATE_CATALOG)
        register_kind(REVERT_RUNTIME)
