from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar, override

from django.contrib import admin
from django.http import HttpRequest

from .models import Server

if TYPE_CHECKING:
    ServerAdminBase = admin.ModelAdmin[Server]
else:
    ServerAdminBase = admin.ModelAdmin


@admin.register(Server)
class ServerAdmin(ServerAdminBase):
    """Removal only. Registration and editing use the Barectl dashboard's alias forms.

    Admin forms would accept any alias text instead of a configured alias. The remaining
    removal workflow moves to the dashboard when Django admin is retired.
    """

    list_display: (
        list[str | Callable[[Server], str | bool]]
        | tuple[str | Callable[[Server], str | bool], ...]
    ) = ("name", "ssh_alias", "legacy_connection")
    search_fields: ClassVar[list[str] | tuple[str, ...]] = ("name", "ssh_alias")

    @override
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @override
    def has_change_permission(self, request: HttpRequest, _obj: Server | None = None) -> bool:
        return False
