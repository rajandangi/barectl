from collections.abc import Iterable, Sequence
from typing import ClassVar, override

from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.db.models import Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Combinable

from .aliases import ALIAS, ALIAS_MAX_LENGTH
from .connections import validate_address, validate_username


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
    connection_mode = models.CharField(
        max_length=8, default="alias", choices=(("alias", "SSH alias"), ("agent", "SSH agent"))
    )
    address = models.CharField(max_length=253, blank=True, validators=[validate_address])
    username = models.CharField(max_length=64, default="root", validators=[validate_username])
    port = models.PositiveIntegerField(
        default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    connection_revision = models.PositiveIntegerField(default=0)
    registration_revision = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["name"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=~Q(ssh_alias=""), name="servers_server_ssh_alias_required"
            ),
            models.CheckConstraint(
                condition=Q(connection_mode__in=["alias", "agent"]),
                name="server_connection_mode_known",
            ),
            models.CheckConstraint(
                condition=Q(port__gte=1, port__lte=65535), name="server_port_valid"
            ),
            models.CheckConstraint(
                condition=Q(connection_mode="alias") | ~Q(address=""),
                name="saved_server_address_required",
            ),
        ]

    @override
    def __str__(self) -> str:
        return self.name


class ConnectionDefinition(models.Model):
    """docs/saved-server-connections.md#immutable-revisions"""

    server = models.ForeignKey(Server, on_delete=models.SET_NULL, null=True, related_name="+")
    revision = models.PositiveIntegerField()
    mode = models.CharField(max_length=8, choices=(("alias", "SSH alias"), ("agent", "SSH agent")))
    alias = models.CharField(max_length=ALIAS_MAX_LENGTH)
    address = models.CharField(max_length=253, validators=[validate_address])
    username = models.CharField(max_length=64, validators=[validate_username])
    port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    alias_config_digest = models.CharField(max_length=64, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server", "revision"], name="unique_connection_revision"
            ),
            models.CheckConstraint(
                condition=Q(mode__in=["alias", "agent"]), name="connection_mode_known"
            ),
            models.CheckConstraint(
                condition=Q(port__gte=1, port__lte=65535, revision__gte=1),
                name="connection_port_revision_valid",
            ),
            models.CheckConstraint(
                condition=~Q(address="") & ~Q(username=""), name="connection_target_required"
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Connection {self.alias} revision {self.revision}"

    @override
    def save(
        self,
        *,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        if not self._state.adding or force_update or update_fields is not None:
            raise ValueError("Connection definitions are immutable; save a new revision.")
        self.full_clean(validate_unique=False, validate_constraints=False)
        super().save(force_insert=True, using=using)

    @property
    def target_label(self) -> str:
        address = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.username}@{address}:{self.port}"
