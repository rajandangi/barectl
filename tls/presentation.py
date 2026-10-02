"""What a challenge route plan's review shows beside the common plan facts."""

from dataclasses import dataclass

from bootstrap.models import ConfigurationPlan
from sites.convention import BACKUP_DIRECTORY, CHALLENGE_ROOT, WEB_USER, SitePaths

from . import activation_native, issuance_native, renewal, staging_native
from .models import (
    PlanChallenge,
    PlanRenewalFile,
    PlanRenewalObservation,
    PlanTlsActivation,
    PlanTlsIssuance,
    PlanTlsReadiness,
    PlanTlsStaging,
    ReadinessName,
)


@dataclass(frozen=True)
class ChallengeReview:
    challenge: PlanChallenge
    paths: SitePaths

    @property
    def names(self) -> tuple[str, ...]:
        return self.challenge.name_list

    @property
    def directories(self) -> list[tuple[str, str, str]]:
        """Each directory the run creates, with its owner and mode."""
        created = []
        if self.challenge.creates_letsencrypt:
            created.append((CHALLENGE_ROOT, "root:root", "0755"))
        created.append((self.paths.webroot, f"root:{WEB_USER}", "0750"))
        if self.challenge.creates_backups:
            created.append((BACKUP_DIRECTORY, "root:root", "0700"))
        return created

    @property
    def backup(self) -> str:
        return f"{BACKUP_DIRECTORY}/{self.paths.identifier}.conf.<unit>"

    @property
    def authority(self) -> str:
        """docs/tls.md#permissions"""
        return (
            "Viewing needs Barectl's permission to view TLS plans, preparing its permission to "
            "prepare them, and applying its permission to apply them; site and bootstrap "
            "permissions grant none of these. On the server, preparation read as root or "
            "through noninteractive sudo; applying needs the same for systemd-run and for the "
            "read that verifies the route afterwards."
        )


# docs/tls.md#renewal-outcomes: what each certbot.service exit status means.
_OUTCOMES = {
    "0": "completed: nothing was due, or every due certificate renewed and is served",
    str(renewal.Outcome.LOCK_HELD): "skipped: another change held the mutation lock",
    str(renewal.Outcome.APPLY_ACTIVE): "skipped: a Barectl run still had processes",
    str(renewal.Outcome.UNSAFE_LOCK): "failed: the lock directory or file was not safe",
    str(renewal.Outcome.NOT_DEPLOYED): (
        "failed: a certificate renewed on disk, but Nginx does not serve it"
    ),
}


@dataclass(frozen=True)
class SetupReview:
    files: list[PlanRenewalFile]
    observation: PlanRenewalObservation | None

    @property
    def last_run(self) -> str:
        """The last renewal's outcome, as the service's result and exit status tell it."""
        seen = self.observation
        if seen is None or not seen.last_exit:
            return "No renewal has run since the server started."
        if seen.last_result == "timeout":
            outcome = "stopped at its 30 minute start limit"
        else:
            outcome = _OUTCOMES.get(seen.last_status, f"failed: Certbot exited {seen.last_status}")
        return f"{seen.last_exit}: {outcome} (result {seen.last_result or 'unknown'})."

    @property
    def timer(self) -> str:
        seen = self.observation
        if seen is None or not seen.timer_enablement:
            return "certbot.timer is not installed."
        last = f", last triggered {seen.last_trigger}" if seen.last_trigger else ""
        following = f", next {seen.next_elapse}" if seen.next_elapse else ""
        state = f"{seen.timer_enablement} and {seen.timer_state}"
        return f"certbot.timer is {state}{last}{following}."

    @property
    def schedule(self) -> str:
        return (
            f"certbot.timer's packaged schedule: {renewal.TIMER_CALENDAR}, delayed at random "
            "by up to 12 hours, and caught up after downtime."
        )

    @property
    def authority(self) -> str:
        """docs/tls.md#permissions"""
        return (
            "Viewing needs Barectl's permission to view TLS plans, preparing its permission to "
            "prepare them, and applying its permission to apply them. On the server, "
            "preparation read as root or through noninteractive sudo; applying needs the same "
            "for systemd-run and for the read that verifies the setup afterwards."
        )


def setup_review(plan: ConfigurationPlan) -> SetupReview | None:
    files = list(PlanRenewalFile.objects.filter(plan=plan))
    observation = PlanRenewalObservation.objects.filter(plan=plan).first()
    if not files and observation is None:
        return None
    return SetupReview(files, observation)


def challenge_review(plan: ConfigurationPlan) -> ChallengeReview | None:
    challenge = PlanChallenge.objects.filter(plan=plan).first()
    if challenge is None:
        return None
    return ChallengeReview(challenge, SitePaths(challenge.identifier, challenge.php_version))


@dataclass(frozen=True)
class ReadinessReview:
    readiness: PlanTlsReadiness
    names: list[ReadinessName]

    @property
    def authority(self) -> str:
        """docs/tls.md#permissions"""
        return (
            "Reading this review needs Barectl's permission to view TLS plans; preparing it "
            "its permission to prepare them. On the server, the site is read as root or "
            "through noninteractive sudo, and DNS, the addresses, the clock and the "
            "authority directory are read without privilege."
        )


@dataclass(frozen=True)
class StagingReview:
    staging: PlanTlsStaging

    @property
    def names(self) -> tuple[str, ...]:
        return self.staging.name_list

    @property
    def directories(self) -> list[tuple[str, str, str]]:
        return [
            (staging_native.config_dir(self.staging.identifier), "root:root", "0700"),
            (staging_native.work_dir(self.staging.identifier), "root:root", "0700"),
            (staging_native.logs_dir(self.staging.identifier), "root:root", "0700"),
        ]

    @property
    def authority(self) -> str:
        return (
            "The order is authorized by the TLS permissions: preparing it needs Barectl's "
            "permission to prepare TLS plans, and applying needs its permission to apply "
            "them. On the server, the order runs as root in one transient unit under the "
            "shared mutation lock, and the verification reads the staged certificate as root."
        )


@dataclass(frozen=True)
class IssuanceReview:
    issuance: PlanTlsIssuance

    @property
    def names(self) -> tuple[str, ...]:
        return self.issuance.name_list

    @property
    def lineage(self) -> str:
        return issuance_native.lineage_dir(self.issuance.identifier)

    @property
    def authority(self) -> str:
        return (
            "The order is authorized by the TLS permissions: preparing it needs Barectl's "
            "permission to prepare TLS plans, and applying needs its permission to order "
            "production certificates. On the server, the order runs as root in one transient "
            "unit under the shared mutation lock, and the verification reads the issued "
            "lineage as root."
        )


@dataclass(frozen=True)
class ActivationReview:
    activation: PlanTlsActivation

    @property
    def names(self) -> tuple[str, ...]:
        return self.activation.name_list

    @property
    def lineage(self) -> str:
        return issuance_native.lineage_dir(self.activation.identifier)

    @property
    def redirect_target(self) -> str:
        return f"https://{self.activation.name_list[0]}"

    @property
    def default_path(self) -> str:
        return activation_native.DEFAULT_PATH

    @property
    def authority(self) -> str:
        return (
            "The activation is authorized by the TLS permissions: preparing it needs "
            "Barectl's permission to prepare TLS plans, and applying needs its permission to "
            "apply them. On the server, the run acts as root in one transient unit under the "
            "shared mutation lock, and the verification reads the site file and the served "
            "certificates as root."
        )


def readiness_review(plan: ConfigurationPlan) -> ReadinessReview | None:
    readiness = PlanTlsReadiness.objects.filter(plan=plan).first()
    if readiness is None:
        return None
    names = list(ReadinessName.objects.filter(plan=plan))
    return ReadinessReview(readiness, names)


def staging_review(plan: ConfigurationPlan) -> StagingReview | None:
    staging = PlanTlsStaging.objects.filter(plan=plan).first()
    if staging is None:
        return None
    return StagingReview(staging)


def activation_review(plan: ConfigurationPlan) -> ActivationReview | None:
    activation = PlanTlsActivation.objects.filter(plan=plan).first()
    if activation is None:
        return None
    return ActivationReview(activation)


def issuance_review(plan: ConfigurationPlan) -> IssuanceReview | None:
    issuance = PlanTlsIssuance.objects.filter(plan=plan).first()
    if issuance is None:
        return None
    return IssuanceReview(issuance)
