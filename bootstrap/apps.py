from typing import override

from django.apps import AppConfig


class BootstrapConfig(AppConfig):
    name = "bootstrap"

    @override
    def ready(self) -> None:
        from . import services  # noqa: F401 - registers the plan preparation step
