"""A WP-CLI setup plan's typed review records (docs/wordpress.md).

Each is immutable and deleted with its plan or run; nothing here is written to the
server. The controller never records key material: the pins are the public review's own
facts, and the payload rechecks them on the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class WpcliTool(ImmutableRecord):
    """The reviewed authenticated artifact and where the run installs it."""

    version = models.CharField(max_length=20)
    # The pinned official artifacts and the signing identity the run authenticates with.
    phar_url = models.URLField(max_length=300)
    signature_url = models.URLField(max_length=300)
    key_url = models.URLField(max_length=300)
    fingerprint = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64)
    path = models.CharField(max_length=200)
    # Whether the installation directory exists as reviewed; a run creates it otherwise.
    creates_directory = models.BooleanField()
    # Whether the artifact existed with its reviewed bytes when the plan was prepared.
    exists = models.BooleanField()
    payload_bytes = models.PositiveIntegerField(null=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WP-CLI {self.version} at {self.path}"


class PlanWpcliTool(WpcliTool):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_tool"
    )


class RunWpcliTool(WpcliTool):
    """An apply run's copy of its plan's tool review, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_tool"
    )


class WpcliRunResult(ImmutableRecord):
    """What verification read after a successful setup run."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_result"
    )
    # Each difference from the reviewed setup, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"


class WordpressRequest(ImmutableRecord):
    """The site an operator asked to prepare a WordPress plan for, with its queued
    preparation (docs/wordpress.md#php-runtime)."""

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_request",
    )
    identifier = models.CharField(max_length=24)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress request of {self.preparation}"


class RuntimeReview(ImmutableRecord):
    """What a PHP runtime plan reviews of the selected site, as its run's audit keeps it.

    The pool probe is the temporary file the apply run publishes in the root-owned site
    directory to ask the site's own pool which capabilities it loads.
    """

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=3)
    php_supply = models.CharField(max_length=10, default="ubuntu")
    site_revision = models.PositiveSmallIntegerField()
    site_user = models.CharField(max_length=32)
    uid = models.PositiveIntegerField()
    gid = models.PositiveIntegerField()
    socket = models.CharField(max_length=100)
    probe_token = models.CharField(max_length=32)
    probe_path = models.CharField(max_length=100)
    probe_content = models.TextField()
    probe_sha256 = models.CharField(max_length=64)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress PHP {self.php_version} runtime of {self.identifier}"


class PlanWordpressRuntime(RuntimeReview):
    plan = models.OneToOneField(
        ConfigurationPlan,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_runtime",
    )


class RunWordpressRuntime(RuntimeReview):
    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wordpress_runtime"
    )


class RuntimeCapability(ImmutableRecord):
    """One baseline capability as preparation observed it in the selected CLI and PHP-FPM."""

    class State(models.TextChoices):
        ENABLED = "enabled", "Enabled in the CLI and PHP-FPM"
        PLANNED = "planned", "Installed by this plan"
        UNAVAILABLE = "unavailable", "Not available"

    position = models.PositiveSmallIntegerField()
    name = models.CharField(max_length=20)
    label = models.CharField(max_length=60)
    # The Ubuntu package that enables it; empty for the PHP build's own capabilities.
    package = models.CharField(max_length=60, blank=True)
    cli = models.BooleanField()
    fpm = models.BooleanField()
    state = models.CharField(max_length=12, choices=State)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return f"{self.name}: {self.get_state_display()}"


class PlanRuntimeCapability(RuntimeCapability):
    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="runtime_capabilities"
    )


class RunRuntimeCapability(RuntimeCapability):
    run = models.ForeignKey(ApplyRun, on_delete=models.CASCADE, related_name="runtime_capabilities")


class RuntimeRunResult(ImmutableRecord):
    """What verification read after a successful runtime run: the selected CLI's and
    PHP-FPM's capabilities, fresh from the server."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="runtime_result"
    )
    # Each difference from the reviewed baseline, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"


class InstallationRequest(ImmutableRecord):
    """What the operator asked an installation review for, stored with the queued
    preparation (docs/wordpress.md#installation-review).

    The row holds only the bounded application metadata; the administrator password is
    generated on the server and never exists here. Its Meta defines the permissions of
    WordPress plans (docs/wordpress.md#review-permissions).
    """

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="installation_request",
    )
    identifier = models.CharField(max_length=24)
    canonical_name = models.CharField(max_length=46)
    title = models.CharField(max_length=100)
    admin_login = models.CharField(max_length=60)
    admin_email = models.CharField(max_length=100)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_wordpressplan", "Can view WordPress plans"),
            ("prepare_wordpressplan", "Can prepare WordPress plans"),
            ("install_wordpress", "Can install WordPress from a reviewed plan"),
        ]

    @override
    def __str__(self) -> str:
        return f"WordPress installation request for {self.identifier}"


class InstallationReview(ImmutableRecord):
    """The immutable installation intent a review binds, as an apply run consumes it.

    Every field is a public pin, an observed non-secret fact or the operator's bounded
    metadata. The administrator password and the salts are generated on the server when the
    review is applied and are never a column here. The abstract base lets the apply run keep
    its own copy beside the plan's, like the other WordPress reviews.
    """

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=3)
    php_supply = models.CharField(max_length=10, default="ubuntu")
    site_revision = models.PositiveSmallIntegerField()
    site_user = models.CharField(max_length=32)
    uid = models.PositiveIntegerField()
    gid = models.PositiveIntegerField()
    socket = models.CharField(max_length=100)
    ipv6 = models.BooleanField()
    # The site's covered names, space separated, and the one canonical HTTPS name.
    names = models.CharField(max_length=520)
    canonical_name = models.CharField(max_length=46)
    url = models.CharField(max_length=60)
    title = models.CharField(max_length=100)
    admin_login = models.CharField(max_length=60)
    admin_email = models.CharField(max_length=100)
    # The certificate the HTTPS name is served with, public identity only.
    certificate_sha256 = models.CharField(max_length=64)
    certificate_not_after = models.CharField(max_length=40)
    # The authenticated WP-CLI the run executes, as setup installs it.
    tool_version = models.CharField(max_length=20)
    tool_path = models.CharField(max_length=200)
    tool_sha256 = models.CharField(max_length=64)
    # The pinned official archive and the limits its acquisition runs under.
    core_version = models.CharField(max_length=20)
    core_locale = models.CharField(max_length=10)
    archive_url = models.CharField(max_length=200)
    archive_bytes = models.PositiveBigIntegerField()
    archive_sha256 = models.CharField(max_length=64)
    max_archive_bytes = models.PositiveBigIntegerField()
    max_tree_bytes = models.PositiveBigIntegerField()
    max_entries = models.PositiveIntegerField()
    max_file_bytes = models.PositiveBigIntegerField()
    memory_max_bytes = models.PositiveBigIntegerField()
    runtime_limit_seconds = models.PositiveIntegerField()
    # The routing: the site file's exact bytes now, and the two exact candidates.
    preimage_sha256 = models.CharField(max_length=64)
    gate_sha256 = models.CharField(max_length=64)
    gate_content = models.TextField()
    ready_sha256 = models.CharField(max_length=64)
    ready_content = models.TextField()
    # The files the run may publish: the placeholder it replaces and the fixed loader.
    placeholder_sha256 = models.CharField(max_length=64)
    # Whether the exact placeholder exists to be replaced; otherwise the public tree is empty.
    placeholder_present = models.BooleanField()
    loader_sha256 = models.CharField(max_length=64)
    public_root = models.CharField(max_length=100)
    private_configuration = models.CharField(max_length=100)
    # The database the run creates the schema in, observed wholly empty.
    database_name = models.CharField(max_length=25)
    # Whether the other database engine was installed when the binding's catalog was read,
    # which the catalog digest the run rechecks covers.
    engine_other = models.BooleanField(default=False)
    # The reviewed native body the run executes: the SHA-256 of its exact text and the size of
    # the payload that carries it (docs/adr/0006-use-native-bootstrap-execution.md).
    body_sha256 = models.CharField(max_length=64, blank=True)
    payload_bytes = models.PositiveIntegerField(null=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress {self.core_version} installation of {self.identifier}"


class PlanWordpressInstall(InstallationReview):
    plan = models.OneToOneField(
        ConfigurationPlan,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_install",
    )


class RunWordpressInstall(InstallationReview):
    """An apply run's copy of its plan's installation review, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wordpress_install"
    )


class InstallRunResult(ImmutableRecord):
    """What verification read after a successful installation run."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="install_result"
    )
    # Each difference from the reviewed installation, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"


# The inspection records live in their own module and are registered here for Django.
from .inspection_models import (  # noqa: E402,F401 - model registration
    InspectionItem,
    InspectionRequest,
    InspectionResult,
    PlanWordpressInspection,
    RunWordpressInspection,
)
