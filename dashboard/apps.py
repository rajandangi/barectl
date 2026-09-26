from typing import override

from django.apps import AppConfig


class DashboardConfig(AppConfig):
    name = "dashboard"

    @override
    def ready(self) -> None:
        from . import checks  # noqa: F401 - registers system checks
