"""docs/tls.md#create-and-install: one site's installation as its HTTPS section shows it."""

from dataclasses import dataclass

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation, Verification
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server

from .installation import available_sites
from .models import CertificateInstallation, CertificateInstallationStep

# In installation.STAGES order.
LABELS = ("Route preparation", "Renewal setup", "Certificate order", "HTTPS activation")
ORDER, ACTIVATION = 2, 3


class StageState(models.TextChoices):
    COMPLETED = "completed", "Completed"
    CURRENT = "current", "Current"
    NOT_STARTED = "not_started", "Not started"
    FAILED = "failed", "Failed"


@dataclass(frozen=True)
class StageView:
    label: str
    state: StageState
    preparation: PlanPreparation | None = None
    run: ApplyRun | None = None

    @property
    def uncertain(self) -> bool:
        return self.run is not None and self.run.status == RemoteOperation.Status.RECONCILING


@dataclass(frozen=True)
class SiteInstallation:
    identifier: str
    # The names an installation submitted now would cover: the current observation's.
    domains: tuple[str, ...]
    installation: CertificateInstallation | None
    stages: tuple[StageView, ...]
    # Another site's installation is active on the server and blocks a new one.
    blocked_by_other: bool

    @property
    def active(self) -> bool:
        return (
            self.installation is not None
            and self.installation.status == CertificateInstallation.Status.ACTIVE
        )

    @property
    def failed(self) -> bool:
        return (
            self.installation is not None
            and self.installation.status == CertificateInstallation.Status.FAILED
        )

    @property
    def polling(self) -> bool:
        return self.active or self.blocked_by_other

    @property
    def names(self) -> list[str]:
        return [] if self.installation is None else self.installation.names.splitlines()

    @property
    def current(self) -> StageView | None:
        return next((stage for stage in self.stages if stage.state is StageState.CURRENT), None)

    @property
    def uncertain(self) -> StageView | None:
        current = self.current
        return current if current is not None and current.uncertain else None

    @property
    def failed_stage(self) -> StageView | None:
        return next((stage for stage in self.stages if stage.state is StageState.FAILED), None)

    @property
    def stopped_before(self) -> StageView | None:
        """The stage that never started when the installation stopped between stages."""
        if not self.failed or self.failed_stage is not None:
            return None
        return next((stage for stage in self.stages if stage.state is StageState.NOT_STARTED), None)

    @property
    def issued_not_activated(self) -> bool:
        return (
            self.failed
            and self.stages[ORDER].state is StageState.COMPLETED
            and self.stages[ACTIVATION].state is not StageState.COMPLETED
        )

    @property
    def token(self) -> str:
        if self.installation is None:
            return f"none:{int(self.blocked_by_other)}"
        states = ",".join(
            f"{stage.state}:{'' if stage.run is None else stage.run.status}"
            for stage in self.stages
        )
        return f"{self.installation.pk}:{self.installation.status}:{states}"

    @property
    def announcement(self) -> str:
        if self.installation is None:
            return ""
        if self.uncertain is not None:
            return (
                f"Installation paused: the {self.uncertain.label.lower()} outcome is not "
                "established."
            )
        current = self.current
        if current is not None:
            return f"Installing HTTPS: {current.label.lower()} is the current stage."
        if self.issued_not_activated:
            return "Installation stopped: the certificate was issued; HTTPS was not activated."
        if self.failed:
            stage = self.failed_stage or self.stopped_before
            return (
                "Installation stopped."
                if stage is None
                else f"Installation stopped at {stage.label.lower()}."
            )
        return "HTTPS installation verified."


def _completed(step: CertificateInstallationStep) -> bool:
    run = step.run
    if run is not None:
        return (
            run.status == RemoteOperation.Status.SUCCEEDED
            and run.verification == Verification.PASSED
        )
    preparation = step.preparation
    if preparation is None or preparation.status != RemoteOperation.Status.SUCCEEDED:
        return False
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    return plan is not None and plan.eligible and plan.no_changes


def _stages(installation: CertificateInstallation | None) -> tuple[StageView, ...]:
    steps = (
        {}
        if installation is None
        else {
            step.position: step for step in installation.steps.select_related("preparation", "run")
        }
    )
    last = max(steps, default=None)
    stages = []
    for position, label in enumerate(LABELS):
        step = steps.get(position)
        if installation is None:
            state = StageState.NOT_STARTED
        elif step is None:
            # The worker queues the first stage after the request.
            waiting = last is None and position == 0
            state = (
                StageState.CURRENT
                if waiting and installation.status == CertificateInstallation.Status.ACTIVE
                else StageState.NOT_STARTED
            )
        elif position != last or installation.status == CertificateInstallation.Status.SUCCEEDED:
            state = StageState.COMPLETED
        elif installation.status == CertificateInstallation.Status.ACTIVE:
            state = StageState.CURRENT
        else:
            state = StageState.COMPLETED if _completed(step) else StageState.FAILED
        stages.append(
            StageView(
                label,
                state,
                None if step is None else step.preparation,
                None if step is None else step.run,
            )
        )
    return tuple(stages)


@lifecycle.recovers_first
def site_installation(server: Server, identifier: str) -> SiteInstallation:
    installation = CertificateInstallation.objects.filter(
        server=server, identifier=identifier
    ).first()
    site = next(
        (site for site in available_sites(server).sites if site.identifier == identifier), None
    )
    blocked = (
        CertificateInstallation.objects.filter(
            server=server, status=CertificateInstallation.Status.ACTIVE
        )
        .exclude(identifier=identifier)
        .exists()
    )
    return SiteInstallation(
        identifier,
        () if site is None else tuple(site.server_names),
        installation,
        _stages(installation),
        blocked,
    )
