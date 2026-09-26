from django.contrib import admin

from .models import Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ["name", "hostname", "ssh_user", "ssh_port"]
    search_fields = ["name", "hostname"]
