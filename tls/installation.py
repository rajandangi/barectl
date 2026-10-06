"""docs/tls.md#create-and-install"""

from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.tasks import task
from django.utils import timezone

from bootstrap.apply import request_apply
from bootstrap.models import Action, ConfigurationPlan, Verification
from discovery.models import SiteState
from discovery.services import read_discovery
from discovery.snapshot import ObservedSite
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server

from . import readiness
from .handler import ISSUANCE_AUTHORITY
from .models import (
    CertificateInstallation,
    CertificateInstallationStep,
    PlanChallenge,
    PlanTlsActivation,
    PlanTlsIssuance,
)
from .services import (
    request_activation_preparation,
    request_challenge_preparation,
    request_issuance_preparation,
    request_setup_preparation,
)

PERMISSIONS = tuple(
    dict.fromkeys(
        (*ISSUANCE_AUTHORITY.prepare, *ISSUANCE_AUTHORITY.apply, "discovery.view_siteobservation")
    )
)
STAGES = (Action.TLS_CHALLENGE, Action.CERTBOT, Action.TLS_ISSUANCE, Action.TLS_ACTIVATION)


@dataclass(frozen=True)
class InstallationSites:
    revision: int
    sites: tuple[ObservedSite, ...]


def available_sites(server: Server) -> InstallationSites:
    """Only managed sites: a partly applied, changed or blocked item cannot take a certificate
    (docs/adr/0015-recognize-only-the-convention.md)."""
    snapshot = read_discovery(server).snapshot
    if snapshot is None:
        return InstallationSites(0, ())
    sites = snapshot.collected.sites.value or ()
    return InstallationSites(
        snapshot.revision,
        tuple(site for site in sites if site.identifier and site.state == SiteState.MANAGED),
    )


@lifecycle.recovers_first
def request_installation(
    server: Server, user_id: int, identifier: str, email: str, snapshot_id: int
) -> CertificateInstallation | None:
    from django.contrib.auth.models import User

    user = User.objects.get(pk=user_id)
    if not user.is_active or not user.has_perms(PERMISSIONS):
        return None
    authority = readiness.production_authority()
    available = available_sites(server)
    site = next((site for site in available.sites if site.identifier == identifier), None)
    if authority is None or site is None or available.revision != snapshot_id:
        return None
    try:
        with transaction.atomic():
            existing = CertificateInstallation.objects.filter(
                server=server, status=CertificateInstallation.Status.ACTIVE
            ).first()
            if existing is not None:
                return (
                    existing
                    if existing.identifier == identifier
                    and existing.email == email
                    and existing.requested_by_id == user_id
                    else None
                )
            if lifecycle.active_operation(server) is not None:
                return None
            installation = CertificateInstallation.objects.create(
                server=server,
                requested_by=user,
                identifier=identifier,
                names="\n".join(site.server_names),
                discovery_revision=snapshot_id,
                email=email,
                authority=authority["directory"],
                ssh_alias=server.ssh_alias,
            )
            advance_installation.enqueue(installation.pk)
            return installation
    except IntegrityError:
        return CertificateInstallation.objects.filter(
            server=server, status=CertificateInstallation.Status.ACTIVE
        ).first()


def completed(operation_ids: list[int]) -> None:
    installations = (
        CertificateInstallationStep.objects.filter(
            Q(preparation_id__in=operation_ids) | Q(run_id__in=operation_ids),
            installation__status=CertificateInstallation.Status.ACTIVE,
        )
        .values_list("installation_id", flat=True)
        .distinct()
    )
    for installation_id in installations:
        advance_installation.enqueue(installation_id)
    discovered = RemoteOperation.objects.filter(
        pk__in=operation_ids, kind=RemoteOperation.Kind.DISCOVERY
    ).values_list("server_id", flat=True)
    for installation_id in CertificateInstallation.objects.filter(
        server_id__in=discovered, status=CertificateInstallation.Status.ACTIVE
    ).values_list("pk", flat=True):
        advance_installation.enqueue(installation_id)


def _stop(installation: CertificateInstallation, failure: str) -> None:
    installation.status = CertificateInstallation.Status.FAILED
    installation.failure = failure
    installation.finished_at = timezone.now()
    installation.save(update_fields=["status", "failure", "finished_at"])


@task
def advance_installation(installation_id: int) -> None:
    with transaction.atomic():
        installation = (
            CertificateInstallation.objects.select_for_update()
            .select_related("server", "requested_by")
            .filter(pk=installation_id, status=CertificateInstallation.Status.ACTIVE)
            .first()
        )
        if installation is None or not _authorized(installation):
            return
        step = installation.steps.select_related("preparation", "run").last()
        if step is not None and not _step_complete(installation, step):
            return
        position = 0 if step is None else step.position + 1
        if position == len(STAGES):
            installation.status = CertificateInstallation.Status.SUCCEEDED
            installation.finished_at = timezone.now()
            installation.save(update_fields=["status", "finished_at"])
        else:
            _queue_step(installation, position)


def _authorized(installation: CertificateInstallation) -> bool:
    user = installation.requested_by
    server = installation.server
    authority = readiness.production_authority()
    if user is None or not user.is_active or not user.has_perms(PERMISSIONS):
        _stop(installation, "The requesting account can no longer install certificates.")
        return False
    if (
        server is None
        or server.ssh_alias != installation.ssh_alias
        or authority is None
        or authority["directory"] != installation.authority
    ):
        _stop(installation, "The server connection or certificate authority changed.")
        return False
    return True


def _step_complete(
    installation: CertificateInstallation, step: CertificateInstallationStep
) -> bool:
    operation: RemoteOperation | None = step.run or step.preparation
    if operation is None:
        _stop(installation, "The step record is missing. Inspect the server before starting again.")
        return False
    if operation.status in RemoteOperation.ACTIVE:
        return False
    if operation.status != RemoteOperation.Status.SUCCEEDED or (
        step.run is not None and step.run.verification != Verification.PASSED
    ):
        _stop(installation, operation.failure or "The step did not verify successfully.")
        return False
    if step.run is not None:
        return True
    return _apply_prepared(installation, step)


def _apply_prepared(
    installation: CertificateInstallation, step: CertificateInstallationStep
) -> bool:
    plan = ConfigurationPlan.objects.filter(preparation=step.preparation).first()
    if plan is None or not plan.eligible:
        reasons = [] if plan is None else list(plan.refusals.values_list("text", flat=True))
        _stop(installation, " ".join(reasons) or "The server refused this installation step.")
        return False
    if installation.host_key and installation.host_key != plan.host_key:
        _stop(installation, "The server identity changed between installation steps.")
        return False
    names = _plan_names(plan)
    if names is not None and set(names.splitlines()) != set(installation.names.splitlines()):
        _stop(installation, "The site's domains changed. Refresh discovery before starting again.")
        return False
    if not installation.host_key:
        installation.host_key = plan.host_key
        installation.save(update_fields=["host_key"])
    if plan.no_changes:
        return True
    server = installation.server
    user = installation.requested_by
    if server is None or user is None:
        return False
    if _discovering(server):
        return False
    applied = request_apply(plan, user)
    if applied.run is None:
        _stop(installation, applied.problem)
        return False
    step.run = applied.run
    step.save(update_fields=["run"])
    return False


def _discovering(server: Server) -> bool:
    active = lifecycle.active_operation(server)
    return active is not None and active.kind == RemoteOperation.Kind.DISCOVERY


def _queue_step(installation: CertificateInstallation, position: int) -> None:
    server = installation.server
    user = installation.requested_by
    if server is None or user is None or _discovering(server):
        return
    if position == 0:
        queued = request_challenge_preparation(server, user, installation.identifier)
    elif position == 1:
        queued = request_setup_preparation(server, user)
    elif position == 2:
        queued = request_issuance_preparation(
            server, user, installation.identifier, installation.email
        )
    else:
        queued = request_activation_preparation(server, user, installation.identifier)
    if queued is None:
        _stop(installation, "Another operation is active. No later step was started.")
        return
    CertificateInstallationStep.objects.create(
        installation=installation, position=position, preparation=queued
    )


def _plan_names(plan: ConfigurationPlan) -> str | None:
    if plan.action == Action.TLS_CHALLENGE:
        detail = PlanChallenge.objects.filter(plan=plan).first()
        return None if detail is None else detail.names
    if plan.action == Action.TLS_ISSUANCE:
        issued = PlanTlsIssuance.objects.filter(plan=plan).first()
        return None if issued is None else issued.names
    if plan.action == Action.TLS_ACTIVATION:
        activated = PlanTlsActivation.objects.filter(plan=plan).first()
        return None if activated is None else activated.names
    return None


def detach_installations(server: Server) -> None:
    if CertificateInstallation.objects.filter(
        server=server, status=CertificateInstallation.Status.ACTIVE
    ).exists():
        raise IntegrityError("A certificate installation is active.")
    CertificateInstallation.objects.filter(server=server).update(server=None)
