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
        validators=[RegexValidator(ALIAS, "Enter an SSH alias, not a pattern or command.")],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["ssh_alias"],
                name="servers_server_unique_ssh_alias",
                violation_error_message="Another server is already registered with this alias.",
                # A "unique" code attaches the error to the ssh_alias form field.
                violation_error_code="unique",
            ),
            # Every server connects through its alias.
            models.CheckConstraint(
                condition=~Q(ssh_alias=""), name="servers_server_ssh_alias_required"
            ),
        ]

    @override
    def __str__(self) -> str:
        return self.name
