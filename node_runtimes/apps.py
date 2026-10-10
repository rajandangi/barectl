from typing import override

from django.apps import AppConfig


class NodeRuntimesConfig(AppConfig):
    name = "node_runtimes"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import HANDLER

        register_handler(HANDLER)
        from operations.lifecycle import register_completion

        from .changes import completed

        register_completion(completed)
