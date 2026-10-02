"""Applying a reviewed HTTPS activation: its payload, outcome and verification.

docs/tls.md#activation. Every boundary leaves the site's HTTP serving and certificates in
place; a failed redirect stage leaves the verified HTTPS state, and verification re-reads the
site file, the recovery preimage, the shared rejection server and the served certificates.
"""

import re

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.convention import SitePaths

from . import activation_native, issuance_native
from .models import ActivationRunResult, PlanTlsActivation, RunTlsActivation

EVIDENCE_FAILURE = (
    "The reviewed activation plan is incomplete or its evidence differs from the review, so "
    "Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the activation afterwards, so Barectl submitted nothing. Barectl never "
    "installs a sudo policy or asks for a password."
)
FAILED = (
    "The activation did not succeed. The certificate and the site's HTTP serving are unchanged."
)
DRIFT = (
    "The site's, the lineage's or the Nginx configuration's evidence changed after the "
    "review, so the activation stopped before changing anything. Prepare a new activation "
    "plan to review the current state."
)
VERIFICATION_FAILED = (
    "The activation ran, but the server does not match the review: {problems} Barectl does "
    "not repair or remove anything; inspect the server through ordinary administration "
    "(docs/tls.md#recovering-a-partial-activation)."
)

_PARTIAL = frozenset(
    {
        activation_native.Exit.DIRECTORIES,
        activation_native.Exit.DEFAULT,
        activation_native.Exit.REPLACEMENT,
        activation_native.Exit.RESTORED,
        activation_native.Exit.NOT_RESTORED,
        activation_native.Exit.NGINX_RELOAD,
        activation_native.Exit.NOT_SERVING,
        activation_native.Exit.REDIRECT,
        activation_native.Exit.NOT_REDIRECTING,
        activation_native.Exit.RESTORE_FAILED,
    }
)
_AFTER = (
    " Barectl never removes the preimage, the rejection server or the HTTPS server block "
    "automatically; a new plan shows what exists (docs/tls.md#recovering-a-partial-activation)."
)
_FAILURES = {
    activation_native.Exit.DIRECTORIES: (
        "The recovery preimage's directory could not be created, so nothing was replaced." + _AFTER
    ),
    activation_native.Exit.DEFAULT: (
        "The shared default TLS rejection server could not be published exactly, so the site "
        "file was not changed." + _AFTER
    ),
    activation_native.Exit.REPLACEMENT: (
        "The HTTPS candidate could not be written or replaced the site file, so nothing was "
        "reloaded." + _AFTER
    ),
    activation_native.Exit.RESTORED: (
        "nginx -t refused the HTTPS candidate, so the site file was restored from the preimage "
        "and nginx -t accepts the configuration again. Nothing was reloaded; the rejection "
        "server and the preimage remain." + _AFTER
    ),
    activation_native.Exit.NOT_RESTORED: (
        "nginx -t refused the HTTPS candidate and the site file could not be restored, or the "
        "configuration is still refused after restoring it. Nothing was reloaded, but a later "
        "reload would fail. Restore the preimage through ordinary administration, then run "
        "nginx -t." + _AFTER
    ),
    activation_native.Exit.NGINX_RELOAD: (
        "The HTTPS candidate is on disk and nginx -t accepted it, but reloading nginx.service "
        "failed, so Nginx may still serve the earlier configuration. Inspect it with systemctl "
        "status nginx.service." + _AFTER
    ),
    activation_native.Exit.NOT_SERVING: (
        "Nginx reloaded, but the certificate served for a reviewed name is not the reviewed "
        "lineage's, or an unknown name still received a certificate. Inspect it with openssl "
        "s_client and nginx -T." + _AFTER
    ),
    activation_native.Exit.REDIRECT: (
        "The verified HTTPS state is in place, but the reviewed HTTP redirect candidate could "
        "not be published, accepted or reloaded. HTTPS keeps serving; publish the redirect "
        "again with a fresh activation plan." + _AFTER
    ),
    activation_native.Exit.NOT_REDIRECTING: (
        "The redirect candidate is on disk and Nginx reloaded, but HTTP does not redirect the "
        "canonical name, the challenge route no longer answers, the served certificate changed "
        "or a mismatched Host was served. HTTPS may be serving; inspect it through ordinary "
        "administration." + _AFTER
    ),
    activation_native.Exit.RESTORE_FAILED: (
        "The redirect candidate was refused and the HTTPS candidate could not be restored, so "
        "the configuration is refused and a later reload would fail. Restore the HTTPS "
        "candidate through ordinary administration, then run nginx -t." + _AFTER
    ),
}

_SERVED = re.compile(r"^served (\S+) ([0-9a-f]{64})$", re.MULTILINE)
_SHA = re.compile(r"^sha ([0-9a-f]{64}) (\S+)$", re.MULTILINE)
_REDIRECT = re.compile(r"^redirect (\d{3}) challenge (\d{3})$", re.MULTILINE)


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _PARTIAL:
        return Execution.PARTIAL
    return evidence.execution


def failure(run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
    if exit_status in _FAILURES:
        return _FAILURES[exit_status]
    if execution == Execution.DRIFT:
        return DRIFT
    return FAILED


def reviewed_changes(plan: ConfigurationPlan) -> str:
    activation = plan.activation
    if activation.redirect_only:
        return (
            f"Publish the reviewed HTTP redirect for {', '.join(activation.name_list)} while "
            "preserving the HTTP-01 challenge route; HTTPS keeps serving "
            f"{issuance_native.lineage_dir(activation.identifier)}"
        )
    return (
        f"Publish the reviewed HTTPS server block for {', '.join(activation.name_list)} from "
        f"{issuance_native.lineage_dir(activation.identifier)}, then the reviewed HTTP redirect"
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    activation = PlanTlsActivation.objects.get(plan=plan)
    paths = SitePaths(activation.identifier, activation.php_version)
    suffix = run.unit_name.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    RunTlsActivation.objects.create(
        run=run,
        identifier=activation.identifier,
        php_version=activation.php_version,
        names=activation.names,
        ipv6=activation.ipv6,
        preimage=activation.preimage,
        preimage_sha256=activation.preimage_sha256,
        https_content=activation.https_content,
        https_sha256=activation.https_sha256,
        redirect_content=activation.redirect_content,
        redirect_sha256=activation.redirect_sha256,
        redirect_only=activation.redirect_only,
        fingerprint=activation.fingerprint,
        not_after=activation.not_after,
        default_content=activation.default_content,
        default_sha256=activation.default_sha256,
        creates_default=activation.creates_default,
        backup_path=paths.backup(suffix),
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        activation = plan.activation
        paths = SitePaths(activation.identifier, activation.php_version)
        return activation_native.activation_payload(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            activation_native.ActivationChange(
                paths=paths,
                names=activation.name_list,
                ipv6=activation.ipv6,
                digest=_fingerprint(plan, PlanEvidence.Kind.SITE_REVALIDATION),
                preimage=activation.preimage,
                https_content=activation.https_content,
                redirect_content=activation.redirect_content,
                fingerprint=activation.fingerprint,
                lineage_digest=_fingerprint(plan, PlanEvidence.Kind.LINEAGE_REVALIDATION),
                default_content=activation.default_content,
                default_exists=not activation.creates_default,
            ),
        )
    except ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _fingerprint(plan: ConfigurationPlan, kind: str) -> str:
    return plan.evidence.filter(kind=kind).values_list("fingerprint", flat=True).first() or ""


def _state_argv(activation: RunTlsActivation) -> list[str]:
    paths = SitePaths(activation.identifier, activation.php_version)
    return activation_native.activation_state(
        paths, activation.name_list, activation.fingerprint, activation.backup_path
    )


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    activation = RunTlsActivation.objects.filter(run=run).first()
    if activation is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    if shell.run(bootstrap_native.authorization(_state_argv(activation))).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/tls.md#activation: fresh reads of the site file, the preimage, the rejection
    server and the actually served certificates."""
    activation = RunTlsActivation.objects.filter(run=run).first()
    if activation is None:
        return Verification.UNAVAILABLE
    root = bootstrap_native.is_root(shell)
    argv = _state_argv(activation)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return Verification.UNAVAILABLE
    stdout = result.stdout
    shas = {path: value for value, path in _SHA.findall(stdout)}
    served = _SERVED.findall(stdout)
    redirect = _REDIRECT.search(stdout)
    problems = _problems(activation, shas, redirect, stdout)
    ActivationRunResult.objects.update_or_create(
        run=run,
        defaults={
            "served": "\n".join(f"{name} {value}" for name, value in served),
            "redirect": (
                f"HTTP {redirect[1]} to https://{activation.name_list[0]}"
                if redirect is not None
                else ""
            ),
            "rejects_unknown": "unknown rejected" in stdout,
            "host_checked": "host not served" in stdout,
            "problems": " ".join(problems),
            "verified_at": timezone.now(),
        },
    )
    return Verification.FAILED if problems else Verification.PASSED


def _problems(
    activation: RunTlsActivation,
    shas: dict[str, str],
    redirect: re.Match[str] | None,
    stdout: str,
) -> list[str]:
    paths = SitePaths(activation.identifier, activation.php_version)
    problems = []
    if shas.get(paths.source) != activation.redirect_sha256:
        problems.append("the site file does not hold the reviewed redirect candidate.")
    if shas.get(activation.backup_path) != activation.preimage_sha256:
        problems.append("the recovery preimage does not hold the reviewed bytes.")
    if shas.get(activation_native.DEFAULT_PATH) != activation.default_sha256:
        problems.append("the shared default TLS rejection server does not hold the reviewed bytes.")
    if "nginx valid" not in stdout:
        problems.append("nginx -t rejects the configuration.")
    if "served verified" not in stdout:
        problems.append("the server does not serve the reviewed certificate for every name.")
    if "unknown rejected" not in stdout:
        problems.append("an unknown name still received a certificate.")
    if "host not served" not in stdout:
        problems.append("a Host different from valid SNI served the site.")
    if redirect is None or redirect[1] != "301":
        problems.append("HTTP does not answer a 301 redirect for the canonical name.")
    if redirect is None or redirect[2] != "404":
        problems.append("the HTTP-01 challenge route no longer answers.")
    return problems


def verification_failure(run: ApplyRun) -> str:
    result = ActivationRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")


def audit(run: ApplyRun) -> list[str]:
    activation = RunTlsActivation.objects.filter(run=run).first()
    if activation is None:
        return []
    result = ActivationRunResult.objects.filter(run=run).first()
    lines = [
        (
            f"Activated HTTPS for {', '.join(activation.name_list)} from "
            f"{issuance_native.lineage_dir(activation.identifier)}, "
            f"certificate valid to {activation.not_after}, and redirected HTTP to "
            f"https://{activation.name_list[0]} while preserving the challenge route"
        )
    ]
    if result is not None and result.served:
        lines.append("Served certificates:")
        lines += result.served.splitlines()
    return lines
