from collections.abc import Sequence
from typing import ClassVar, override

from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from .aliases import ALIAS, ALIAS_MAX_LENGTH


class Server(models.Model):
    """docs/ssh-aliases.md"""

    name = models.CharField(max_length=100, unique=True)
    ssh_alias = models.CharField(
        "SSH alias",
        max_length=ALIAS_MAX_LENGTH,
        unique=True,
        validators=[RegexValidator(ALIAS, "Enter an SSH alias, not a pattern or command.")],
        error_messages={"unique": "Another server is already registered with this alias."},
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=~Q(ssh_alias=""), name="servers_server_ssh_alias_required"
            ),
        ]

    @override
    def __str__(self) -> str:
        return self.name
