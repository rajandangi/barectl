from collections.abc import Sequence
from typing import ClassVar, override

from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from .aliases import ALIAS, ALIAS_MAX_LENGTH


class Server(models.Model):
    """A managed server, registered by an SSH alias configured on the controller host.

    Connection settings, credentials and host trust stay in the controller's SSH
    configuration. A registration is not a verified connection.
    """

    name = models.CharField(max_length=100, unique=True)
    ssh_alias = models.CharField(
        "SSH alias",
        max_length=ALIAS_MAX_LENGTH,
        blank=True,
        validators=[RegexValidator(ALIAS, "Enter an SSH alias, not a pattern or command.")],
    )
    # Explicit connection details recorded before alias registration, kept only so the
    # operator can choose the matching alias. They are never used to connect.
    legacy_connection = models.CharField(max_length=400, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["ssh_alias"],
                condition=~Q(ssh_alias=""),
                name="servers_server_unique_ssh_alias",
                violation_error_message="Another server is already registered with this alias.",
                # A "unique" code attaches the error to the ssh_alias form field.
                violation_error_code="unique",
            ),
            # Only migrated records may lack an alias, and only until they are reconciled.
            models.CheckConstraint(
                condition=~Q(ssh_alias="") | ~Q(legacy_connection=""),
                name="servers_server_alias_or_legacy_connection",
            ),
        ]

    @override
    def __str__(self) -> str:
        return self.name

    @property
    def needs_alias(self) -> bool:
        """Migrated records cannot connect until the operator chooses their alias."""
        return not self.ssh_alias
