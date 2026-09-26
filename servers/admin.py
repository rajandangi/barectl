from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar

from django.contrib import admin

from .models import Server

if TYPE_CHECKING:
    ServerAdminBase = admin.ModelAdmin[Server]
else:
    ServerAdminBase = admin.ModelAdmin


@admin.register(Server)
class ServerAdmin(ServerAdminBase):
    list_display: (
        list[str | Callable[[Server], str | bool]]
        | tuple[str | Callable[[Server], str | bool], ...]
    ) = ("name", "hostname", "ssh_user", "ssh_port")
    search_fields: ClassVar[list[str] | tuple[str, ...]] = ("name", "hostname")
