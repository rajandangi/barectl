"""One authorized native PHP site recipe (docs/site-creation.md)."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.tasks import task
from django.utils import timezone

from bootstrap import actions, php_supply, releases
from bootstrap.apply import request_apply
from bootstrap.models import Action, ConfigurationPlan, PlanPreparation, Verification
from bootstrap.runtime_services import request_php_installation
from bootstrap.services import request_preparation
from bootstrap.source_tools_models import SourceToolsSelection
from databases.services import request_binding_preparation, request_driver_preparation
from discovery.models import DatabaseEngine
from discovery.services import queue_discovery, read_discovery
from node_runtimes import catalog as node_catalog
from node_runtimes.services import request_runtime_preparation as request_node_preparation
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server
from sites import names as site_names
from sites.services import request_site_preparation
from tls import readiness
from tls.models import PlanChallenge, PlanTlsActivation, PlanTlsIssuance
from tls.services import (
    request_activation_preparation,
    request_challenge_preparation,
    request_issuance_preparation,
    request_setup_preparation,
)
from wordpress import first_access, inputs, qualification
from wordpress.services import (
    request_install_preparation,
    request_runtime_preparation,
)
from wordpress.services import (
    request_setup_preparation as request_wpcli_preparation,
)

from .models import HostingCreation, HostingCreationStep

DISCOVERY = "discover"
SOURCE_TOOLS = Action.PHP_SOURCE_PREREQUISITES


@dataclass(frozen=True)
class CreationInput:
    names: tuple[str, ...]
    php_version: str = ""
    discovery_revision: int = 0
    database_engine: str = ""
    https: bool = False
    email: str = ""
    application: str = "php"
    title: str = ""
    admin_login: str = ""
    admin_email: str = ""
    first_access_spki: str = ""
    node_version: str = ""


@dataclass(frozen=True)
class CreationStepView:
    position: int
    stage: str
    status: str
    operation_id: int | None
    failure: str


@dataclass(frozen=True)
class CreationView:
    id: int
    identifier: str
    names: tuple[str, ...]
    php_version: str
    application: str
    status: str
    failure: str
    steps: tuple[CreationStepView, ...]


def identifier_for(domain: str) -> str:
    return "site" + hashlib.sha256(domain.encode("ascii")).hexdigest()[:20]


def _stages(
    database_engine: str, https: bool, application: str = "php", node_version: str = ""
) -> tuple[str, ...]:
    stages: list[str] = [
        DISCOVERY,
        Action.METADATA_REFRESH,
        SOURCE_TOOLS,
        Action.PHP_SOURCE,
        Action.METADATA_REFRESH,
        Action.NGINX,
    ]
    stages.extend(
        (
            Action.WORDPRESS_LIBRARIES if application == "wordpress" else Action.PHP_LIBRARIES,
            Action.PHP,
        )
    )
    if database_engine:
        stages.extend(
            (Action.MARIADB, Action.PHP_MYSQL)
            if database_engine == DatabaseEngine.MARIADB
            else (Action.POSTGRESQL, Action.PHP_PGSQL)
        )
    stages.extend((DISCOVERY, Action.SITE_HTTP))
    if node_version:
        stages.append(Action.NODE_RUNTIME)
    if application == "wordpress":
        stages.append(Action.PHP_WORDPRESS)
    if database_engine:
        stages.append(
            Action.DATABASE_MARIADB
            if database_engine == DatabaseEngine.MARIADB
            else Action.DATABASE_POSTGRESQL
        )
    if https:
        stages.extend(
            (Action.TLS_CHALLENGE, Action.CERTBOT, Action.TLS_ISSUANCE, Action.TLS_ACTIVATION)
        )
    if application == "wordpress":
        stages.extend((Action.WPCLI, Action.WORDPRESS_INSTALL))
    stages.append(DISCOVERY)
    return tuple(stages)


def permissions(wanted: CreationInput) -> tuple[str, ...]:
    required = {"servers.view_server", "discovery.view_siteobservation"}
    for stage in _stages(
        _engine(wanted),
        wanted.https or wanted.application == "wordpress",
        wanted.application,
        wanted.node_version,
    ):
        if stage == DISCOVERY:
            continue
        authority = actions.authority(stage)
        required.update((*authority.prepare, *authority.apply))
    return tuple(sorted(required))


def _validate(wanted: CreationInput) -> None:
    if site_names.names("\n".join(wanted.names)) != wanted.names:
        raise ValueError("Site names must be canonical and unique.")
    if wanted.php_version and wanted.php_version not in php_supply.ELIGIBLE_BRANCHES:
        raise ValueError("Select a supported PHP branch.")
    if wanted.database_engine not in {"", DatabaseEngine.MARIADB, DatabaseEngine.POSTGRESQL}:
        raise ValueError("Select a supported site database engine.")
    if wanted.application not in {"php", "wordpress"}:
        raise ValueError("Select a supported application.")
    _validate_application(wanted)
    if wanted.node_version and wanted.node_version not in node_catalog.VERSIONS:
        raise ValueError("Select a supported Node runtime.")
    if wanted.https or wanted.application == "wordpress":
        validate_email(wanted.email or wanted.admin_email)
    elif wanted.email:
        raise ValueError("Certificate contact applies only when HTTPS is requested.")
    if wanted.discovery_revision <= 0:
        raise ValueError("A current server observation is required.")


def _validate_application(wanted: CreationInput) -> None:
    if wanted.application != "wordpress":
        if wanted.title or wanted.admin_login or wanted.admin_email or wanted.first_access_spki:
            raise ValueError("Administrator metadata applies only to explicit WordPress creation.")
        return
    if wanted.database_engine not in {"", DatabaseEngine.MARIADB}:
        raise ValueError("WordPress requires MariaDB.")
    problems = inputs.problems(
        inputs.Metadata(wanted.names[0], wanted.title, wanted.admin_login, wanted.admin_email)
    )
    if problems:
        raise ValueError(" ".join(problems))
    if wanted.first_access_spki:
        first_access.validate_key(wanted.first_access_spki)


@lifecycle.recovers_first
def request_creation(server: Server, user_id: int, wanted: CreationInput) -> HostingCreation | None:
    _validate(wanted)
    user = User.objects.filter(pk=user_id, is_active=True).first()
    if user is None or not user.has_perms(permissions(wanted)):
        return None
    key = hashlib.sha256(json.dumps(asdict(wanted), sort_keys=True).encode()).hexdigest()
    try:
        with transaction.atomic():
            Server.objects.select_for_update().get(pk=server.pk)
            existing = HostingCreation.objects.filter(server=server, request_key=key).first()
            if existing is not None:
                return existing if existing.requested_by_id == user_id else None
            if (
                HostingCreation.objects.filter(
                    server=server, status=HostingCreation.Status.ACTIVE
                ).exists()
                or lifecycle.active_operation(server) is not None
            ):
                return None
            discovered = read_discovery(server)
            if (
                discovered.snapshot is None
                or discovered.snapshot.revision != wanted.discovery_revision
                or discovered.attempt is None
                or discovered.attempt.status != RemoteOperation.Status.SUCCEEDED
                or not discovered.attempt.host_key
                or discovered.attempt.ssh_alias != server.ssh_alias
            ):
                return None
            authority = readiness.production_authority() if wanted.https else None
            if wanted.application == "wordpress":
                authority = readiness.production_authority()
            if (wanted.https or wanted.application == "wordpress") and authority is None:
                return None
            creation = HostingCreation.objects.create(
                server=server,
                requested_by=user,
                request_key=key,
                identifier=identifier_for(wanted.names[0]),
                names="\n".join(wanted.names),
                php_version=wanted.php_version,
                database_engine=_engine(wanted),
                https=wanted.https or wanted.application == "wordpress",
                email=wanted.email or wanted.admin_email,
                application=wanted.application,
                title=wanted.title,
                admin_login=wanted.admin_login,
                admin_email=wanted.admin_email,
                first_access_spki=wanted.first_access_spki,
                node_version=wanted.node_version,
                authority="" if authority is None else authority["directory"],
                discovery_revision=wanted.discovery_revision,
                ssh_alias=server.ssh_alias,
                host_key=discovered.attempt.host_key,
            )
            advance_creation.enqueue(creation.pk)
            return creation
    except IntegrityError:
        return HostingCreation.objects.filter(
            server=server, request_key=key, requested_by=user
        ).first()


def completed(operation_ids: list[int]) -> None:
    creations = (
        HostingCreationStep.objects.filter(
            Q(discovery_id__in=operation_ids)
            | Q(preparation_id__in=operation_ids)
            | Q(run_id__in=operation_ids),
            creation__status=HostingCreation.Status.ACTIVE,
        )
        .values_list("creation_id", flat=True)
        .distinct()
    )
    discovered_servers = RemoteOperation.objects.filter(
        pk__in=operation_ids, kind=RemoteOperation.Kind.DISCOVERY
    ).values_list("server_id", flat=True)
    refreshed = HostingCreation.objects.filter(
        server_id__in=discovered_servers, status=HostingCreation.Status.ACTIVE
    ).values_list("pk", flat=True)
    for creation_id in set(creations) | set(refreshed):
        advance_creation.enqueue(creation_id)


def _wanted(creation: HostingCreation) -> CreationInput:
    return CreationInput(
        tuple(creation.names.splitlines()),
        creation.php_version,
        creation.discovery_revision,
        creation.database_engine,
        creation.https,
        creation.email,
        creation.application,
        creation.title,
        creation.admin_login,
        creation.admin_email,
        creation.first_access_spki,
        creation.node_version,
    )


def _engine(wanted: CreationInput) -> str:
    return DatabaseEngine.MARIADB if wanted.application == "wordpress" else wanted.database_engine


def _stop(creation: HostingCreation, failure: str) -> None:
    creation.status = HostingCreation.Status.FAILED
    creation.failure = failure
    creation.finished_at = timezone.now()
    creation.save(update_fields=["status", "failure", "finished_at"])


def _authorized(creation: HostingCreation) -> bool:
    user, server = creation.requested_by, creation.server
    if user is None or not user.is_active or not user.has_perms(permissions(_wanted(creation))):
        _stop(creation, "The requesting account can no longer prepare this site.")
        return False
    if server is None or server.ssh_alias != creation.ssh_alias:
        _stop(creation, "The server connection changed. No later stage was started.")
        return False
    authority = readiness.production_authority() if creation.https else None
    if creation.https and (authority is None or authority["directory"] != creation.authority):
        _stop(creation, "The certificate authority changed. No later stage was started.")
        return False
    return True


@task
def advance_creation(creation_id: int) -> None:
    with transaction.atomic():
        creation = (
            HostingCreation.objects.select_for_update()
            .select_related("server", "requested_by")
            .filter(pk=creation_id, status=HostingCreation.Status.ACTIVE)
            .first()
        )
        if creation is None or not _authorized(creation):
            return
        step = creation.steps.select_related("discovery", "preparation", "run").last()
        if step is not None and not _complete(creation, step):
            return
        position = 0 if step is None else step.position + 1
        stages = _stages(
            creation.database_engine, creation.https, creation.application, creation.node_version
        )
        if position == len(stages):
            creation.status = HostingCreation.Status.SUCCEEDED
            creation.finished_at = timezone.now()
            creation.save(update_fields=["status", "finished_at"])
        else:
            _queue(creation, position, stages[position])


def _complete(creation: HostingCreation, step: HostingCreationStep) -> bool:
    if step.satisfied:
        return True
    operation: RemoteOperation | None = step.run or step.preparation or step.discovery
    if operation is None:
        _stop(creation, "A stage record is missing. Inspect the server before starting again.")
        return False
    if operation.status in RemoteOperation.ACTIVE:
        return False
    if operation.status != RemoteOperation.Status.SUCCEEDED or (
        step.run is not None and step.run.verification != Verification.PASSED
    ):
        _stop(creation, operation.failure or "The stage did not verify successfully.")
        return False
    if operation.host_key != creation.host_key:
        _stop(creation, "The server identity changed. No later stage was started.")
        return False
    if step.run is not None or step.discovery is not None:
        return True
    return _apply_prepared(creation, step)


def _source_selection(creation: HostingCreation, plan: ConfigurationPlan) -> bool:
    selection = SourceToolsSelection.objects.filter(plan=plan).first()
    if selection is None or selection.supply not in {"ubuntu", "sury"}:
        _stop(creation, "The server's native PHP supply could not be established.")
        return False
    release = releases.RELEASES.get(plan.release)
    branch = (
        creation.php_version or selection.default_branch or ("" if release is None else release.php)
    )
    if branch not in php_supply.ELIGIBLE_BRANCHES:
        _stop(creation, "The server's native default PHP branch could not be established.")
        return False
    creation.php_version = branch
    creation.php_supply = selection.supply
    creation.source_setup_needed = not selection.installed and selection.supply == "sury"
    creation.save(update_fields=["php_version", "php_supply", "source_setup_needed"])
    if creation.application == "wordpress" and not qualification.qualified(
        plan.release, plan.architecture, creation.php_version, creation.php_supply
    ):
        _stop(
            creation,
            qualification.reason(
                plan.release, plan.architecture, creation.php_version, creation.php_supply
            ),
        )
        return False
    return True


def _admit_plan(creation: HostingCreation, step: HostingCreationStep) -> ConfigurationPlan | None:
    plan = ConfigurationPlan.objects.filter(preparation=step.preparation).first()
    if plan is None or not plan.eligible:
        reasons = [] if plan is None else list(plan.refusals.values_list("text", flat=True))
        _stop(creation, " ".join(reasons) or "The server refused this stage.")
        return None
    if plan.host_key != creation.host_key:
        _stop(creation, "The reviewed server identity changed.")
        return None
    if step.stage == SOURCE_TOOLS and not _source_selection(creation, plan):
        return None
    for model in (PlanChallenge, PlanTlsIssuance, PlanTlsActivation):
        detail = model.objects.filter(plan=plan).first()
        if detail is not None and set(detail.names.splitlines()) != set(
            creation.names.splitlines()
        ):
            _stop(creation, "The site's domains changed. No later stage was started.")
            return None
    return plan


def _apply_prepared(creation: HostingCreation, step: HostingCreationStep) -> bool:
    plan = _admit_plan(creation, step)
    if plan is None:
        return False
    if plan.no_changes:
        return True
    user = creation.requested_by
    if user is None:
        return False
    if creation.server is not None and _discovering(creation.server):
        return False
    applied = request_apply(plan, user)
    if applied.run is None:
        _stop(creation, applied.problem)
        return False
    step.run = applied.run
    step.save(update_fields=["run"])
    return False


def _discovering(server: Server) -> bool:
    active = lifecycle.active_operation(server)
    return active is not None and active.kind == RemoteOperation.Kind.DISCOVERY


def _queue(creation: HostingCreation, position: int, stage: str) -> None:
    server, user = creation.server, creation.requested_by
    if server is None or user is None:
        return
    if _discovering(server):
        return
    if lifecycle.active_operation(server) is not None:
        _stop(creation, "Another operation is active. No later stage was started.")
        return
    latest = read_discovery(server).attempt
    if latest is None or latest.status != RemoteOperation.Status.SUCCEEDED:
        _stop(creation, "Discovery did not succeed. Inspect the server before starting again.")
        return
    if latest.host_key != creation.host_key:
        _stop(creation, "The server identity changed. No later stage was started.")
        return
    if stage == DISCOVERY:
        discovery = queue_discovery(server)
        HostingCreationStep.objects.create(
            creation=creation, position=position, stage=stage, discovery=discovery
        )
        return
    if (
        stage == Action.PHP_SOURCE
        and (creation.php_supply == "ubuntu" or not creation.source_setup_needed)
    ) or (stage == Action.PHP_LIBRARIES and creation.php_supply != "sury"):
        HostingCreationStep.objects.create(
            creation=creation, position=position, stage=stage, satisfied=True
        )
        advance_creation.enqueue(creation.pk)
        return
    try:
        preparation = _prepare(creation, stage, server, user)
    except ValueError:
        _stop(creation, "The request expired or is no longer valid. No later stage was started.")
        return
    if preparation is None:
        _stop(creation, "Another operation is active. No later stage was started.")
        return
    HostingCreationStep.objects.create(
        creation=creation, position=position, stage=stage, preparation=preparation
    )


def _prepare(
    creation: HostingCreation, stage: str, server: Server, user: User
) -> PlanPreparation | None:
    if stage == Action.SITE_HTTP:
        return request_site_preparation(
            server,
            user,
            creation.identifier,
            tuple(creation.names.splitlines()),
            php_version=creation.php_version,
            convention_revision=4,
        )
    if stage in {Action.PHP_MYSQL, Action.PHP_PGSQL}:
        return request_driver_preparation(
            server,
            user,
            Action(stage),
            php_version=creation.php_version,
            php_supply=creation.php_supply,
        )
    if stage in {Action.DATABASE_MARIADB, Action.DATABASE_POSTGRESQL}:
        return request_binding_preparation(
            server, user, creation.identifier, DatabaseEngine(creation.database_engine)
        )
    if stage in {Action.TLS_CHALLENGE, Action.CERTBOT, Action.TLS_ISSUANCE, Action.TLS_ACTIVATION}:
        return _prepare_tls(creation, stage, server, user)
    return _prepare_application(creation, stage, server, user)


def _prepare_tls(
    creation: HostingCreation, stage: str, server: Server, user: User
) -> PlanPreparation | None:
    if stage == Action.TLS_CHALLENGE:
        return request_challenge_preparation(server, user, creation.identifier)
    if stage == Action.CERTBOT:
        return request_setup_preparation(server, user)
    if stage == Action.TLS_ISSUANCE:
        return request_issuance_preparation(server, user, creation.identifier, creation.email)
    return request_activation_preparation(server, user, creation.identifier)


def _prepare_application(
    creation: HostingCreation, stage: str, server: Server, user: User
) -> PlanPreparation | None:
    if stage == Action.NODE_RUNTIME:
        return request_node_preparation(
            server, user, creation.node_version, identifier=creation.identifier
        )
    if stage == Action.PHP_WORDPRESS:
        return request_runtime_preparation(server, user, creation.identifier)
    if stage == Action.WPCLI:
        return request_wpcli_preparation(server, user)
    if stage == Action.WORDPRESS_INSTALL:
        return request_install_preparation(
            server,
            user,
            creation.identifier,
            inputs.Metadata(
                creation.names.splitlines()[0],
                creation.title,
                creation.admin_login,
                creation.admin_email,
            ),
            first_access_spki=creation.first_access_spki,
            first_access_expires_at=(
                creation.created_at + timedelta(hours=1) if creation.first_access_spki else None
            ),
        )
    if stage == Action.PHP:
        return request_php_installation(server, user, creation.php_version, creation.php_supply)
    return request_preparation(server, user, Action(stage))


@lifecycle.recovers_first
def read_creation(server: Server, creation_id: int | None = None) -> CreationView | None:
    query = HostingCreation.objects.filter(server=server)
    creation = query.filter(pk=creation_id).first() if creation_id is not None else query.first()
    if creation is None:
        return None
    steps = []
    for step in creation.steps.select_related("discovery", "preparation", "run"):
        operation: RemoteOperation | None = step.run or step.preparation or step.discovery
        steps.append(
            CreationStepView(
                step.position,
                step.stage,
                "succeeded"
                if step.satisfied
                else "unknown"
                if operation is None
                else operation.status,
                None if operation is None else operation.pk,
                "" if operation is None else operation.failure,
            )
        )
    return CreationView(
        creation.pk,
        creation.identifier,
        tuple(creation.names.splitlines()),
        creation.php_version,
        creation.application,
        creation.status,
        creation.failure,
        tuple(steps),
    )


def detach_creations(server: Server) -> None:
    if HostingCreation.objects.filter(server=server, status=HostingCreation.Status.ACTIVE).exists():
        raise IntegrityError("A site creation is active.")
    HostingCreation.objects.filter(server=server).update(server=None)
