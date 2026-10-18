"""Barectl's own per-site settings, kept on the controller.

A change stays the server's source of truth: no Barectl marker, configuration file or
database row is written to a managed host. These rows shape what a reviewed change does
and are reconstructed as their default on a fresh controller. See
``docs/adr/0039-keep-per-site-deploy-switches-on-the-controller.md``.
"""

from typing import ClassVar, override

from django.db import models


class SiteDeploySetting(models.Model):
    """The per-site Deploy switches saved for this server and site."""

    server = models.ForeignKey(
        "servers.Server", on_delete=models.CASCADE, related_name="deploy_settings"
    )
    identifier = models.CharField(max_length=24)
    run_migrations = models.BooleanField(default=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=("server", "identifier"), name="unique_site_deploy_setting"
            )
        ]

    @override
    def __str__(self) -> str:
        return f"{self.identifier} on {self.server}"
