"""A site plan's typed review records (docs/sites.md#what-a-site-plan-reviews).

Each is immutable and deleted with its plan; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from bootstrap.models import ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class SiteRequest(ImmutableRecord):
    """What the operator asked to prepare, stored with the queued preparation."""

    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="site_request"
    )
    identifier = models.CharField(max_length=24)
    # The canonical names, one per line, in the order the operator gave them.
    names = models.TextField()

    class Meta:
        # docs/sites.md#permissions: site plans have their own viewers, preparers and appliers.
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_siteplan", "Can view site plans"),
            ("prepare_siteplan", "Can prepare site plans"),
            ("apply_siteplan", "Can apply site plans"),
        ]

    @override
    def __str__(self) -> str:
        return f"Site {self.identifier}"


class PlanSite(ImmutableRecord):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="site"
    )
    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    user = models.CharField(max_length=32)
    document_root = models.CharField(max_length=100)
    socket = models.CharField(max_length=100)
    pool_name = models.CharField(max_length=24)
    # Whether the site also listens on [::]:80, as nginx did when the plan was prepared.
    ipv6 = models.BooleanField()
    # The temporary serving probe's name part, 32 hexadecimal digits; not a secret.
    probe_token = models.CharField(max_length=32)
    # The size of the payload built at preparation, which must fit one submission.
    payload_bytes = models.PositiveIntegerField(null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Site {self.identifier}"


class PlanSiteName(ImmutableRecord):
    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="site_names")
    position = models.PositiveSmallIntegerField()
    name = models.CharField(max_length=253)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.name


class PlanFileChange(ImmutableRecord):
    """One file or link the plan publishes, with its complete bytes."""

    class Role(models.TextChoices):
        NGINX_SOURCE = "nginx_source", "Nginx site file"
        NGINX_LINK = "nginx_link", "Nginx enablement link"
        POOL = "pool", "PHP-FPM pool"
        PLACEHOLDER = "placeholder", "Placeholder page"
        PROBE = "probe", "Temporary serving probe"

    class Type(models.TextChoices):
        FILE = "file", "Regular file"
        SYMLINK = "symlink", "Symbolic link"

    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="site_files")
    position = models.PositiveSmallIntegerField()
    role = models.CharField(max_length=20, choices=Role)
    path = models.CharField(max_length=200)
    file_type = models.CharField(max_length=10, choices=Type)
    owner = models.CharField(max_length=32)
    group = models.CharField(max_length=32)
    # Octal permission bits, such as "0644"; empty for a link.
    mode = models.CharField(max_length=4, blank=True)
    link_target = models.CharField(max_length=200, blank=True)
    content = models.TextField(blank=True)
    content_sha256 = models.CharField(max_length=64, blank=True)
    # A creation plan requires every destination to be absent.
    preimage_absent = models.BooleanField(default=True)
    # Removed again before the run succeeds.
    temporary = models.BooleanField(default=False)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.path


class PlanDirectoryChange(ImmutableRecord):
    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="site_directories"
    )
    position = models.PositiveSmallIntegerField()
    path = models.CharField(max_length=200)
    owner = models.CharField(max_length=32)
    group = models.CharField(max_length=32)
    mode = models.CharField(max_length=4)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.path


class PlanAccountChange(ImmutableRecord):
    """The native account creation, whose records the account tool itself writes."""

    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="site_account"
    )
    user = models.CharField(max_length=32)
    group = models.CharField(max_length=32)
    home = models.CharField(max_length=100)
    login_shell = models.CharField(max_length=100)
    command = models.TextField()
    uid_min = models.PositiveIntegerField()
    uid_max = models.PositiveIntegerField()
    gid_min = models.PositiveIntegerField()
    gid_max = models.PositiveIntegerField()
    free_uids = models.PositiveIntegerField()
    free_gids = models.PositiveIntegerField()
    # The allocator's likely choice when prepared; another account may take it first.
    predicted_uid = models.PositiveIntegerField(null=True)
    predicted_gid = models.PositiveIntegerField(null=True)
    subordinate_ids = models.BooleanField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return self.user
