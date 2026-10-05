"""docs/tls.md#create-and-install: one site's installation as its HTTPS section shows it."""

from dataclasses import dataclass

from django.db import models

from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server

from .installation import STAGES, available_sites
from .models import CertificateInstallation, CertificateInstallationStep

_LABELS = {
    Action.TLS_CHALLENGE: "Route preparation",
    Action.CERTBOT: "Renewal setup",
    Action.TLS_ISSUANCE: "Certificate order",
    Action.TLS_ACTIVATION: "HTTPS activation",
}
LABELS = tuple(_LABELS[action] for action in STAGES)
ORDER = STAGES.index(Action.TLS_ISSUANCE)
ACTIVATION = STAGES.index(Action.TLS_ACTIVATION)

# docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes
_UNESTABLISHED = frozenset(
    {Execution.SUBMITTED, Execution.NOT_FOUND, Execution.RUNNING, Execution.OUTCOME_UNKNOWN}
)
_NOT_APPLIED = Execution.refused_before_changes() | {
    Execution.NOT_SUBMITTED,
    Execution.INSTALL_NOT_STARTED,
}


class StageState(models.TextChoices):
    COMPLETED = "completed", "Completed"
    CURRENT = "current", "Current"
    NOT_STARTED = "not_started", "Not started"
    UNCONFIRMED = "unconfirmed", "Outcome not established"
    FAILED = "failed", "Failed"


@dataclass(frozen=True)
class StageView:
    label: str
    state: StageState
    preparation: PlanPreparation | None = None
    run: ApplyRun | None = None

    @property
    def uncertain(self) -> bool:
        return self.run is not None and (
            self.run.status == RemoteOperation.Status.RECONCILING
            or self.state is StageState.UNCONFIRMED
        )

    @property
    def not_applied(self) -> bool:
        """A failed stage whose run is established to have changed nothing it verifies."""
        run = self.run
        return self.state is StageState.FAILED and (
            run is None or run.execution in _NOT_APPLIED or run.verification == Verification.FAILED
        )


@dataclass(frozen=True)
class SiteInstallation:
    identifier: str
    # The current observation's names, which a new installation would cover.
    domains: tuple[str, ...]
    installation: CertificateInstallation | None
    stages: tuple[StageView, ...]
    blocked_by_other: bool

    @property
    def active(self) -> bool:
        return (
            self.installation is not None
            and self.installation.status == CertificateInstallation.Status.ACTIVE
        )

    @property
    def stopped(self) -> bool:
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
    def earlier(self) -> bool:
        """The record names other domains than the site the page now shows."""
        return self.installation is not None and set(self.names) != set(self.domains)

    @property
    def current(self) -> StageView | None:
        return next((stage for stage in self.stages if stage.state is StageState.CURRENT), None)

    @property
    def uncertain(self) -> StageView | None:
        return next((stage for stage in self.stages if stage.uncertain), None)

    @property
    def failed_stage(self) -> StageView | None:
        return next((stage for stage in self.stages if stage.state is StageState.FAILED), None)

    @property
    def stopped_before(self) -> StageView | None:
        """The stage that never started when the installation stopped between stages."""
        if not self.stopped or self.failed_stage is not None or self.uncertain is not None:
            return None
        return next((stage for stage in self.stages if stage.state is StageState.NOT_STARTED), None)

    @property
    def issued(self) -> bool:
        return self.stages[ORDER].state is StageState.COMPLETED

    @property
    def order_unconfirmed(self) -> bool:
        return self.stages[ORDER].uncertain

    @property
    def activation_unconfirmed(self) -> bool:
        return self.stages[ACTIVATION].uncertain

    @property
    def activation_failed(self) -> bool:
        return self.stages[ACTIVATION].state is StageState.FAILED

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
        uncertain = self.uncertain
        if uncertain is not None:
            paused = "paused" if self.active else "stopped"
            return (
                f"Installation {paused}: the {uncertain.label.lower()} outcome is not established."
            )
        current = self.current
        if current is not None:
            return f"Installing HTTPS: {current.label.lower()} is the current stage."
        if self.stopped:
            stage = self.failed_stage or self.stopped_before
            return (
                "Installation stopped."
                if stage is None
                else f"Installation stopped at {stage.label.lower()}."
            )
        return "Installation recorded as verified."


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


def _unestablished(run: ApplyRun | None) -> bool:
    return run is not None and (
        run.status in RemoteOperation.ACTIVE
        or run.verification == Verification.UNAVAILABLE
        or run.execution in _UNESTABLISHED
    )


def _stopped_state(step: CertificateInstallationStep) -> StageState:
    if _completed(step):
        return StageState.COMPLETED
    if _unestablished(step.run):
        return StageState.UNCONFIRMED
    return StageState.FAILED


def _stages(installation: CertificateInstallation | None) -> tuple[StageView, ...]:
    steps = (
        {}
        if installation is None
        else {
            step.position: step for step in installation.steps.select_related("preparation", "run")
        }
    )
    last = max(steps, default=None)
    status = None if installation is None else installation.status
    stages = []
    for position, label in enumerate(LABELS):
        step = steps.get(position)
        if step is None:
            # The worker queues the first stage after the request.
            waiting = last is None and position == 0
            state = (
                StageState.CURRENT
                if waiting and status == CertificateInstallation.Status.ACTIVE
                else StageState.NOT_STARTED
            )
        elif position != last or status == CertificateInstallation.Status.SUCCEEDED:
            state = StageState.COMPLETED
        elif status == CertificateInstallation.Status.ACTIVE:
            state = StageState.CURRENT
        else:
            state = _stopped_state(step)
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
