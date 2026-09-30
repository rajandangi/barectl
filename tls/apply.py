"""Applying a reviewed challenge route: its payload, outcome and verification.

docs/tls.md#applying; the replacement and its compensation are recorded in
docs/adr/0012-publish-site-files-without-replacing-them.md#replacement.
"""

import re
from dataclasses import dataclass, field

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import apply as site_apply
from sites.convention import BACKUP_DIRECTORY, CHALLENGE_ROOT, WEB_USER, SitePaths

from . import native
from .models import ChallengeRunResult, PlanChallenge, RunChallenge

Exit = native.Exit
EVIDENCE_FAILURE = (
    "The reviewed challenge route plan is incomplete or its site file differs from the "
    "convention, so Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the route afterwards, so Barectl submitted nothing. Barectl never installs "
    "a sudo policy or asks for a password."
)
VERIFICATION_FAILED = (
    "The challenge route was applied, but the server does not match the review: {problems} "
    "Barectl does not repair or remove anything; inspect the server through ordinary "
    "administration (docs/tls.md#recovering-a-partial-challenge-route)."
)
_PARTIAL = frozenset(
    {
        Exit.DIRECTORIES,
        Exit.REPLACEMENT,
        Exit.RESTORED,
        Exit.NOT_RESTORED,
        Exit.NGINX_RELOAD,
        Exit.NOT_SERVING,
        Exit.PROBE_LEFT,
    }
)
_AFTER = (
    " Barectl never removes the webroot or the backup automatically and never resumes a "
    "partial route. A new plan shows what exists (docs/tls.md#recovering-a-partial-challenge-"
    "route)."
)


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _PARTIAL:
        return Execution.PARTIAL
    return evidence.execution


def _boundaries(challenge: RunChallenge) -> dict[int, str]:
    """docs/tls.md#recovering-a-partial-challenge-route: what exists after each boundary."""
    paths = SitePaths(challenge.identifier, challenge.php_version)
    source, webroot, backup = paths.source, paths.webroot, challenge.backup_path
    restore = f"cp {backup} {source}"
    return {
        Exit.DIRECTORIES: (
            f"Creating {webroot}, {BACKUP_DIRECTORY} or the backup {backup} stopped; "
            f"{source} was not changed. Inspect them with ls -ld {CHALLENGE_ROOT} {webroot} "
            f"{BACKUP_DIRECTORY} {backup}."
        ),
        Exit.REPLACEMENT: (
            f"{webroot} and the backup {backup} exist, but {source} could not be replaced or "
            "no longer had its reviewed bytes, so it was left as it was. Nothing was reloaded."
        ),
        Exit.RESTORED: (
            f"nginx -t refused the candidate, so {source} was restored from {backup} and nginx "
            "-t accepts the configuration again. Nothing was reloaded. The webroot and the "
            "backup remain."
        ),
        Exit.NOT_RESTORED: (
            f"nginx -t refused the configuration and {source} could not be restored, or the "
            "configuration is still refused after restoring it. Nothing was reloaded, but a "
            f"later reload would fail. Restore the preimage with {restore}, then run nginx -t."
        ),
        Exit.NGINX_RELOAD: (
            f"{source} holds the challenge route and nginx -t accepted it, but reloading "
            "nginx.service failed, so Nginx may still serve the earlier configuration. Inspect "
            "it with systemctl status nginx.service."
        ),
        Exit.NOT_SERVING: (
            "The route was applied and Nginx reloaded, but the temporary probe was not served "
            "exactly, a .php or directory request did not answer 404, or the front page's "
            "status changed. The probe was removed. Inspect the site with nginx -T and the "
            f"access log; restore the preimage with {restore} and systemctl reload nginx.service "
            "if the site no longer serves as before."
        ),
        Exit.PROBE_LEFT: (
            "The run stopped after writing the temporary probe "
            f"{paths.challenge_probe(challenge.probe_token)}, which could not be removed or "
            "had changed, so verification is incomplete. Inspect and remove it."
        ),
    }


_REFUSALS: dict[Execution, str] = {
    **{
        outcome: text
        for outcome, text in site_apply.REFUSALS.items()
        if outcome not in {Execution.DRIFT, Execution.ACCOUNT_BUSY}
    },
    Execution.DRIFT: (
        "The site file, the webroot's or the backup's directories, the Nginx or PHP-FPM "
        "configuration, accounts, services or listeners changed after review, so the run "
        "stopped before changing anything. Prepare a new plan to review the current state."
    ),
}


def failure(run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
    challenge = RunChallenge.objects.filter(run=run).first()
    if outcome in _REFUSALS:
        return _REFUSALS[outcome]
    if outcome == Execution.PARTIAL and challenge is not None and exit_status is not None:
        text = _boundaries(challenge).get(exit_status, "")
        return f"Stopped at exit status {exit_status}: {text}{_AFTER}"
    if outcome == Execution.SUCCEEDED:
        return ""
    if outcome == Execution.TIMED_OUT:
        limit = bootstrap_native.RUNTIME_MAX
        return f"The run reached its {limit} limit and systemd stopped it.{_AFTER}"
    if outcome == Execution.KILLED:
        return f"The run was terminated by a signal before it finished.{_AFTER}"
    return f"The run failed. Inspect its unit with systemctl status and journalctl.{_AFTER}"


# Audit --------------------------------------------------------------------------------------


def _plan_challenge(plan: ConfigurationPlan) -> PlanChallenge:
    return PlanChallenge.objects.get(plan=plan)


def reviewed_changes(plan: ConfigurationPlan) -> str:
    challenge = _plan_challenge(plan)
    paths = SitePaths(challenge.identifier, challenge.php_version)
    lines = []
    if challenge.creates_letsencrypt:
        lines.append(f"Create directory {CHALLENGE_ROOT}, root:root 0755")
    lines.append(f"Create directory {paths.webroot}, root:{WEB_USER} 0750")
    if challenge.creates_backups:
        lines.append(f"Create directory {BACKUP_DIRECTORY}, root:root 0700")
    lines += [
        f"Back up {paths.source}, SHA-256 {challenge.preimage_sha256}, root:root 0600",
        f"Replace {paths.source}, root:root 0644, SHA-256 {challenge.content_sha256}",
        "Reload nginx.service",
    ]
    return "\n".join(lines)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    challenge = _plan_challenge(plan)
    paths = SitePaths(challenge.identifier, challenge.php_version)
    suffix = run.unit_name.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    copied = (
        "identifier",
        "php_version",
        "names",
        "ipv6",
        "probe_token",
        "preimage",
        "preimage_sha256",
        "content",
        "content_sha256",
        "creates_letsencrypt",
        "creates_backups",
    )
    RunChallenge.objects.create(
        run=run,
        backup_path=paths.backup(suffix),
        **{name: getattr(challenge, name) for name in copied},
    )


# Payload ------------------------------------------------------------------------------------


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        challenge = _plan_challenge(plan)
        digest = (
            plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION)
            .values_list("fingerprint", flat=True)
            .first()
        )
        change = native.ChallengeChange(
            paths=SitePaths(challenge.identifier, challenge.php_version),
            names=challenge.name_list,
            ipv6=challenge.ipv6,
            token=challenge.probe_token,
            digest=digest or "",
            preimage=challenge.preimage,
            content=challenge.content,
        )
        if (change.preimage_sha256, change.content_sha256) != (
            challenge.preimage_sha256,
            challenge.content_sha256,
        ):
            raise ValueError("The site file differs from its reviewed digests.")
        return native.challenge_payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, change
        )
    except ValueError, ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _state_argv(challenge: RunChallenge) -> list[str]:
    paths = SitePaths(challenge.identifier, challenge.php_version)
    return native.challenge_state(paths, challenge.probe_token, challenge.backup_path)


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    challenge = RunChallenge.objects.filter(run=run).first()
    if challenge is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    if shell.run(bootstrap_native.authorization(_state_argv(challenge))).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Verification -------------------------------------------------------------------------------


class Unreadable(Exception):
    pass


@dataclass
class _State:
    records: dict[str, str] = field(default_factory=dict)
    # Type, owner, group, mode and link count as stat reports them.
    paths: dict[str, tuple[str, str, str, str, str]] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    digests: dict[str, str] = field(default_factory=dict)


_PATH = re.compile(
    r"([a-z ]{1,30})\|([a-z_][a-z0-9_.-]{0,31}|UNKNOWN|[0-9]+)\|"
    r"([a-z_][a-z0-9_.-]{0,31}|UNKNOWN|[0-9]+)\|([0-7]{1,4})\|([0-9]{1,10})\|(/\S+)"
)


def parse_state(text: str) -> _State:
    state = _State()
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind in {"target", "unit", "nginx"}:
            state.records[kind] = rest[:300]
        elif kind == "path":
            match = _PATH.fullmatch(rest)
            if match is None:
                raise Unreadable
            state.paths[match[6]] = (match[1], match[2], match[3], match[4], match[5])
        elif kind == "absent":
            state.absent.add(rest)
        elif kind == "sha":
            digest, _, path = rest.partition(" ")
            state.digests[path] = digest
        else:
            raise Unreadable
    return state


def _problems(challenge: RunChallenge, state: _State) -> list[str]:
    paths = SitePaths(challenge.identifier, challenge.php_version)
    backup = challenge.backup_path
    problems = []
    source = state.paths.get(paths.source)
    if source != ("regular file", "root", "root", "644", "1") or (
        state.digests.get(paths.source) != challenge.content_sha256
    ):
        problems.append(f"{paths.source} does not have the reviewed bytes, owner and mode.")
    if state.records.get("target") != paths.source or state.paths.get(paths.link, ("",))[0] != (
        "symbolic link"
    ):
        problems.append(f"{paths.link} is not the site's link to {paths.source}.")
    if state.paths.get(paths.webroot, ())[:4] != ("directory", "root", WEB_USER, "750"):
        problems.append(f"{paths.webroot} is not a directory owned by root:{WEB_USER}, 0750.")
    if state.paths.get(backup) != ("regular file", "root", "root", "600", "1") or (
        state.digests.get(backup) != challenge.preimage_sha256
    ):
        problems.append(f"The backup {backup} does not hold the preimage, root:root 0600.")
    probe = paths.challenge_probe(challenge.probe_token)
    if probe not in state.absent or f"{paths.webroot}/.well-known" not in state.absent:
        problems.append("The temporary probe or its directories remain.")
    if state.records.get("unit") != "active/running":
        problems.append("nginx.service is not active and running.")
    if state.records.get("nginx") != "valid":
        problems.append("nginx -t rejects the configuration.")
    return problems


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/tls.md#applying: fresh reads after a successful run."""
    challenge = RunChallenge.objects.filter(run=run).first()
    if challenge is None:
        return Verification.UNAVAILABLE
    root = bootstrap_native.is_root(shell)
    argv = _state_argv(challenge)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return Verification.UNAVAILABLE
    try:
        state = parse_state(result.stdout)
    except Unreadable:
        return Verification.UNAVAILABLE
    problems = _problems(challenge, state)
    if not ChallengeRunResult.objects.filter(run=run).exists():
        ChallengeRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    challenge = RunChallenge.objects.filter(run=run).first()
    lines = [f"The preimage is kept at {challenge.backup_path}."] if challenge else []
    result = ChallengeRunResult.objects.filter(run=run).first()
    if result is not None:
        lines.insert(
            0, f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}."
        )
        lines += result.problems.splitlines()
    return lines


def verification_failure(run: ApplyRun) -> str:
    result = ChallengeRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
