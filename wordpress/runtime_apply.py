"""Applying a reviewed WordPress PHP runtime plan: its payload, outcome and verification.

docs/wordpress.md#php-runtime. The package transaction is bootstrap's; this module binds the
run to the reviewed site, appends the pool probe and separates the transaction's outcome from
the capabilities verification reads afterwards.
"""

import re

from django.utils import timezone

from bootstrap import apply as bootstrap_apply
from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap.evidence import Unreadable, parse_socket_listeners
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.native import UnitEvidence
from databases import drivers
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.convention import SitePaths

from . import runtime, runtime_native
from .models import (
    PlanRuntimeCapability,
    PlanWordpressRuntime,
    RunRuntimeCapability,
    RuntimeRunResult,
    RunWordpressRuntime,
    WordpressRequest,
)

Exit = runtime_native.Exit
EVIDENCE_FAILURE = (
    "The reviewed WordPress runtime plan is incomplete or its site differs from this "
    "version's convention, so Barectl submitted nothing. Prepare a new plan."
)
_PROBE_EXITS = (Exit.PROBE_FAILED, Exit.CAPABILITIES_DIFFER, Exit.PROBE_LEFT)
_PROBE_FAILURES = {
    Exit.PROBE_FAILED: (
        "The packages were installed and the pools reloaded, but the temporary probe could "
        "not be published in the site directory, or its preconditions no longer held."
    ),
    Exit.CAPABILITIES_DIFFER: (
        "The packages were installed and the pools reloaded, but the site's own pool or the "
        "selected CLI did not report every baseline capability."
    ),
    Exit.PROBE_LEFT: (
        "The packages were installed and the capabilities checked, but the temporary probe "
        "could not be removed from the site directory."
    ),
}
_AFTER = (
    " Barectl does not roll back or retry. Inspect the unit with systemctl status and "
    "journalctl, check the site directory for a leftover wpprobe-*.php file and the pool's "
    "configuration through ordinary administration, then prepare a new plan "
    "(docs/wordpress.md#php-runtime)."
)
VERIFICATION_FAILED = (
    "The run completed, but the baseline does not hold: {problems} Barectl does not repair "
    "or roll back; inspect the server through ordinary administration "
    "(docs/wordpress.md#php-runtime)."
)
_SOCKET = re.compile(r"/run/php/[A-Za-z0-9._-]{1,60}\.sock")


def _request(plan: ConfigurationPlan) -> str:
    request = WordpressRequest.objects.filter(preparation=plan.preparation).first()
    return request.identifier if request is not None else ""


def execution(evidence: UnitEvidence) -> Execution:
    """The probe's own exit statuses; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    if (
        evidence.found
        and evidence.terminal
        and exited
        and evidence.exec_main_status in _PROBE_EXITS
    ):
        return Execution.CAPABILITY_FAILED
    return evidence.execution


def failure(run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
    if outcome == Execution.CAPABILITY_FAILED:
        reason = _PROBE_FAILURES.get(exit_status or 0, _PROBE_FAILURES[Exit.CAPABILITIES_DIFFER])
        return f"{reason}{_AFTER}"
    return bootstrap_apply.package_failure(run, outcome)


def reviewed_changes(plan: ConfigurationPlan) -> str:
    packages = bootstrap_apply.reviewed_changes(plan)
    review = PlanWordpressRuntime.objects.filter(plan=plan).first()
    if review is None:
        return packages
    return (
        f"{packages}\nVerify with a temporary probe {review.probe_path} that the selected CLI "
        f"and site {review.identifier}'s pool report every baseline capability"
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    review = PlanWordpressRuntime.objects.filter(plan=plan).first()
    if review is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    RunWordpressRuntime.objects.create(
        run=run,
        identifier=review.identifier,
        php_version=review.php_version,
        php_supply=review.php_supply,
        site_revision=review.site_revision,
        site_user=review.site_user,
        uid=review.uid,
        gid=review.gid,
        socket=review.socket,
        probe_token=review.probe_token,
        probe_path=review.probe_path,
        probe_content=review.probe_content,
        probe_sha256=review.probe_sha256,
    )
    RunRuntimeCapability.objects.bulk_create(
        RunRuntimeCapability(
            run=run,
            position=item.position,
            name=item.name,
            label=item.label,
            package=item.package,
            cli=item.cli,
            fpm=item.fpm,
            state=item.state,
        )
        for item in PlanRuntimeCapability.objects.filter(plan=plan)
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    review = PlanWordpressRuntime.objects.filter(plan=plan).first()
    identifier = _request(plan)
    if (
        review is None
        or not identifier
        or review.identifier != identifier
        or review.php_version != plan.php_version
        or review.php_supply != plan.php_supply
        or not _SOCKET.fullmatch(review.socket)
    ):
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        paths = SitePaths(identifier, review.php_version, revision=review.site_revision)
        if paths.socket != review.socket:
            raise ValueError("The reviewed site socket differs.")
        steps = runtime_native.probe_steps(
            run.unit_name,
            paths=paths,
            token=review.probe_token,
            uid=review.uid,
            content=review.probe_content,
        )
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None
    sockets = tuple(plan.driver_pools.filter(default=False).values_list("socket", flat=True))
    return bootstrap_apply.package_payload(
        run,
        plan,
        sockets=sockets,
        preconditions=drivers.site_preconditions(plan, identifier),
        after=steps,
    )


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    """Verification reads nothing that needs privilege."""


def _problems(shell: RemoteShell, run: ApplyRun, plan: ConfigurationPlan) -> list[str]:
    """Each baseline capability the selected CLI or PHP-FPM does not list now."""
    profile = bootstrap_apply.profile_of(run)
    if profile is None:
        raise Unreadable("The profile is unavailable.")
    lists = {}
    for where, command in (("PHP-FPM", profile.module_list), ("the CLI", profile.cli_module_list)):
        result = shell.run(command)
        if result.exit_status != 0 or result.truncated:
            raise Unreadable("A capability listing could not be read.")
        lists[where] = {line.strip().casefold() for line in result.stdout.splitlines()}
    return [
        f"{item.name} is not loaded by {where}."
        for item in runtime.CAPABILITIES
        for where, listed in lists.items()
        if item.name not in listed
    ]


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/wordpress.md#php-runtime: fresh reads after a successful run, in the selected CLI
    and PHP-FPM; the unit's own probe already required the site's pool to agree."""
    plan = run.plan
    if plan is None:
        return Verification.UNAVAILABLE
    verification = bootstrap_apply.verify_profile(shell, run)
    if verification == Verification.UNAVAILABLE:
        return verification
    try:
        problems = _problems(shell, run, plan)
        for socket in plan.driver_pools.values_list("socket", flat=True):
            result = shell.run(bootstrap_inspection.socket_listeners(socket))
            if result.exit_status != 0 or result.truncated:
                return Verification.UNAVAILABLE
            if socket not in parse_socket_listeners(result.stdout):
                problems.append(f"{socket} is not listening.")
    except Unreadable:
        return Verification.UNAVAILABLE
    if verification == Verification.FAILED and not problems:
        problems.append("The packages, their marks or the service do not match the review.")
    if not RuntimeRunResult.objects.filter(run=run).exists():
        RuntimeRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = RuntimeRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    stamp = f"{timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}"
    if result.problems:
        return [f"Verified {stamp}.", *result.problems.splitlines()]
    return [
        f"Verified {stamp}: the selected CLI and PHP-FPM list every baseline capability.",
        (
            "The unit's temporary probe confirmed the site's own pool and the selected CLI "
            "reported the same capabilities, then removed the probe."
        ),
    ]


def verification_failure(run: ApplyRun) -> str:
    result = RuntimeRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
