from typing import override

from django.apps import AppConfig


class DiscoveryConfig(AppConfig):
    name = "discovery"

    @override
    def ready(self) -> None:
        from . import services  # noqa: F401 - registers the discovery step
