import itertools
import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.db import models
from django.test import TestCase, override_settings
from django.utils import timezone

from bootstrap.actions import BUILT_IN
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Privilege,
    Verification,
)
from dashboard.testing import TEST_MANIFEST
from databases.models import DatabaseRequest, RunDatabaseBinding
from operations.models import RemoteOperation
from sites.models import RunSite, SiteRequest
from tls.models import (
    ActivationRequest,
    IssuanceRequest,
    RunChallenge,
    RunStaging,
    RunTlsActivation,
    RunTlsIssuance,
    StagingRequest,
    TlsRequest,
)

from .models import Server

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

HTMX_FRAGMENT = {"HX-Request": "true", "HX-Request-Type": "partial"}
SSH_CONFIG = """\
Host web.example.com
  HostName 203.0.113.10
  User deploy
Host stage.example.net db-1
  User deploy
Host *.internal
  User ops
"""


class ControllerConfigTestCase(TestCase):
    """Runs against a temporary controller SSH configuration, never the real one."""

    user: ClassVar[User]
    ssh_config: ClassVar[Path]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.ssh_config = directory / "config"
        cls.enterClassContext(
            override_settings(
                SSH_CONFIG_PATH=str(cls.ssh_config),
                VITE_MANIFEST_PATH=TEST_MANIFEST,
                VITE_DEV_SERVER_URL="",
            )
        )
        super().setUpClass()

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")

    @override
    def setUp(self) -> None:
        self.write_config(SSH_CONFIG)

    def write_config(self, text: str) -> None:
        self.ssh_config.write_text(text, encoding="utf-8")

    def grant(self, *codenames: str) -> None:
        for codename in codenames:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def grant_view(self) -> None:
        self.grant("view_server")

    def history_of(self, page: _MonkeyPatchedWSGIResponse) -> str:
        content = page.content.decode()
        return content[content.index('id="discovery-history"') :]


_PLAN_NUMBERS = itertools.count(1_000_000)
_SITE_ACTIONS = {Action.SITE_HTTP}
_RUN_COPIES: dict[str, type[models.Model]] = {
    Action.SITE_HTTP: RunSite,
    Action.DATABASE_MARIADB: RunDatabaseBinding,
    Action.DATABASE_POSTGRESQL: RunDatabaseBinding,
    Action.TLS_CHALLENGE: RunChallenge,
    Action.TLS_STAGING: RunStaging,
    Action.TLS_ISSUANCE: RunTlsIssuance,
    Action.TLS_ACTIVATION: RunTlsActivation,
}
_DATABASE_ACTIONS = {
    Action.PHP_MYSQL,
    Action.PHP_PGSQL,
    Action.DATABASE_MARIADB,
    Action.DATABASE_POSTGRESQL,
    Action.DATABASE_INSPECTION,
}
_TLS_ACTIONS = {Action.TLS_CHALLENGE, Action.CERTBOT, Action.TLS_READINESS}


def record_preparation(
    server: Server,
    action: Action,
    identifier: str = "",
    status: RemoteOperation.Status = RemoteOperation.Status.SUCCEEDED,
) -> PlanPreparation:
    """A preparation stored with the typed request its action's service records."""
    finished = status not in RemoteOperation.ACTIVE
    preparation = PlanPreparation.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        action=action,
        status=status,
        finished_at=timezone.now() if finished else None,
    )
    if action in _SITE_ACTIONS:
        SiteRequest.objects.create(
            preparation=preparation, identifier=identifier, names=f"{identifier}.test"
        )
    elif action in _DATABASE_ACTIONS:
        DatabaseRequest.objects.create(preparation=preparation, identifier=identifier)
    elif action in _TLS_ACTIONS:
        TlsRequest.objects.create(preparation=preparation, identifier=identifier)
    elif action == Action.TLS_STAGING:
        StagingRequest.objects.create(
            preparation=preparation,
            identifier=identifier,
            email="admin@example.com",
            authority="https://acme-staging.example.com/directory",
            terms_accepted=True,
        )
    elif action == Action.TLS_ISSUANCE:
        IssuanceRequest.objects.create(
            preparation=preparation,
            identifier=identifier,
            email="admin@example.com",
            terms_accepted=True,
        )
    elif action == Action.TLS_ACTIVATION:
        ActivationRequest.objects.create(preparation=preparation, identifier=identifier)
    elif action not in BUILT_IN:
        raise ValueError(f"No typed request is recorded for {action}.")
    return preparation


def record_run(
    server: Server,
    action: Action,
    *,
    preparation: PlanPreparation | None = None,
    site: str = "",
    intent: str = "",
    status: RemoteOperation.Status = RemoteOperation.Status.SUCCEEDED,
    execution: Execution = Execution.SUCCEEDED,
    verification: Verification = Verification.PASSED,
    failure: str = "",
) -> ApplyRun:
    """An apply run of ``preparation``'s plan, or with its action's retained copy of
    ``site``."""
    now = timezone.now()
    plan = None
    if preparation is not None:
        plan = ConfigurationPlan.objects.create(
            preparation=preparation,
            action=action,
            profile_revision=1,
            intent=intent,
            eligible=False,
            ssh_alias=server.ssh_alias,
            host_key="",
            collected_at=now,
            admission_expires_at=now,
            privilege=Privilege.ROOT,
        )
    run = ApplyRun.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        status=status,
        finished_at=None if status in RemoteOperation.ACTIVE else now,
        failure=failure,
        plan=plan,
        plan_number=next(_PLAN_NUMBERS),
        requested_by_name="operator",
        server_name=server.name,
        action=action,
        intent=intent,
        profile_revision=1,
        release="24.04",
        reviewed_host_key="",
        boot_id="",
        admission_deadline_centiseconds=0,
        admission_expires_at=now,
        effects="",
        unit_name=f"barectl-apply-{uuid.uuid4().hex}.service",
        execution=execution,
        verification=verification,
    )
    if site:
        model = _RUN_COPIES[action]
        model._default_manager.create(run=run, identifier=site, **_placeholders(model, site))
    return run


def _placeholders(model: type[models.Model], site: str) -> dict[str, object]:
    """Values for a copy's other required fields, which only its audit reads."""
    values: dict[str, object] = {}
    for field in model._meta.concrete_fields:
        if field.name == "names":
            values[field.name] = f"{site}.test"
        elif isinstance(field, models.BooleanField):
            values[field.name] = False
        elif isinstance(field, models.IntegerField) and not field.null and not field.primary_key:
            values[field.name] = 0
    return values
