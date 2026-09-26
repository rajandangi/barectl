from collections.abc import Sequence
from typing import ClassVar, override

from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.db.models.expressions import Combinable


class Server(models.Model):
    """Connection metadata only. Remote discovery is a later milestone."""

    name = models.CharField(max_length=100, unique=True)
    hostname = models.CharField(
        max_length=253,
        validators=[
            RegexValidator(
                r"\A[A-Za-z0-9][A-Za-z0-9.:-]*\Z",
                "Enter a hostname, IP address, or SSH alias without spaces or shell characters.",
            )
        ],
    )
    ssh_port = models.PositiveIntegerField(
        default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    ssh_user = models.CharField(
        max_length=64,
        validators=[RegexValidator(r"\A[a-z_][a-z0-9_-]*\Z", "Enter a Linux username.")],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["name"]

    @override
    def __str__(self) -> str:
        return self.name
