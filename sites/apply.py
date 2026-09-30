"""Applying a reviewed site plan: its payload, outcome and verification.

docs/ssh-connections.md#applying-sites; the boundaries and compensation are recorded in
docs/adr/0012-publish-site-files-without-replacing-them.md.
"""

import re
from dataclasses import dataclass, field

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import native
from .convention import NOLOGIN, WEB_USER, SitePaths
from .models import (
    RunAccountChange,
    RunDirectoryChange,
    RunFileChange,
    RunSite,
    SiteRunResult,
)

Exit = native.Exit
EVIDENCE_FAILURE = (
    "The reviewed site plan is incomplete or its files differ from their reviewed digests, so "
    "Barectl submitted nothing. Prepare a new site plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the site afterwards, so Barectl submitted nothing. Barectl never installs a "
    "sudo policy or asks for a password."
)
VERIFICATION_FAILED = (
    "The site was created, but it does not match the review or does not serve as reviewed: "
    "{problems} Barectl does not repair or remove anything; inspect the server through "
    "ordinary administration. The refreshed discovery shows what is there now."
)
_PARTIAL = frozenset(range(Exit.ACCOUNT, Exit.PROBE_LEFT + 1))
_AFTER = (
    " Barectl never removes accounts, directories or content automatically, and never "
    "resumes or adopts a partial site. A new site plan shows what exists; it is refused as "
    "incomplete until ordinary administration completes or removes the site "
    "(docs/sites.md#recovering-a-partial-site)."
)


def execution(evidence: UnitEvidence) -> Execution:
    """The site payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status == Exit.ACCOUNT_BUSY:
        return Execution.ACCOUNT_BUSY
    if terminal and evidence.exec_main_status in _PARTIAL:
        return Execution.PARTIAL
    return evidence.execution


def _boundaries(paths: SitePaths, token: str) -> dict[int, str]:
    """docs/sites.md#recovering-a-partial-site: what exists after each boundary."""
    user, php = paths.user, paths.php
    return {
        Exit.ACCOUNT: (
            f"useradd failed after the account databases changed, so {user} may or may not "
            f"exist. Inspect it with getent passwd {user} and getent group {user}."
        ),
        Exit.ACCOUNT_MISMATCH: (
            f"useradd created {user}, but it differs from the review: its IDs are outside the "
            f"reviewed range, it has another group, home or shell, or its password is not "
            f"locked. Inspect it with getent passwd {user} and id {user}; remove it with "
            f"userdel {user} only if nothing uses it."
        ),
        Exit.DIRECTORIES: (
            f"{user} exists; creating {paths.boundary} and its public and private directories "
            f"stopped. Inspect them with ls -ld {paths.boundary} {paths.boundary}/*."
        ),
        Exit.CONTENT: (
            f"{user} and the site directories exist; writing the placeholder or the probe "
            f"stopped, and a staged file named .index.html.<unit> or .probe-{token}.php.<unit> "
            f"may remain in {paths.public}. Remove the probe {paths.probe(token)} if it exists."
        ),
        Exit.POOL: (
            f"The account, directories and content exist; publishing the pool {paths.pool} "
            f"stopped, and a staged .{paths.identifier}.conf.<unit> file may remain beside it. "
            "PHP-FPM was not reloaded."
        ),
        Exit.POOL_WITHDRAWN: (
            f"php-fpm{php} -t rejected the configuration with the new pool, so Barectl removed "
            "the unchanged pool file again and the configuration is valid; PHP-FPM was not "
            "reloaded. The account, directories and content remain."
        ),
        Exit.POOL_INVALID: (
            f"php-fpm{php} -t rejected the configuration, and still rejected it after Barectl "
            "withdrew the unchanged pool file, or the pool file had changed and was kept; "
            f"PHP-FPM was not reloaded. Run php-fpm{php} -t, and if {paths.pool} exists and is "
            "the cause, remove it before PHP-FPM is next reloaded or restarted."
        ),
        Exit.FPM_RELOAD: (
            f"The pool {paths.pool} is published, but systemctl reload {paths.fpm_service} "
            f"failed, so PHP-FPM's state is unknown. Inspect it with systemctl status "
            f"{paths.fpm_service} and journalctl -u {paths.fpm_service}."
        ),
        Exit.SOCKET: (
            f"PHP-FPM reloaded with the pool, but {paths.socket} did not appear as a socket "
            f"owned by www-data with mode 0600. Inspect it with ls -l {paths.socket} and "
            f"journalctl -u {paths.fpm_service}."
        ),
        Exit.SITE_FILE: (
            f"The pool is active; publishing the Nginx site file {paths.source} stopped, and a "
            f"staged .{paths.identifier}.conf.<unit> file may remain beside it. Nginx was not "
            "reloaded, so the site is not enabled."
        ),
        Exit.SITE_LINK: (
            f"The pool is active and {paths.source} is published; enabling it with "
            f"{paths.link} stopped. Nginx was not reloaded. Inspect it with ls -l {paths.link}."
        ),
        Exit.LINK_WITHDRAWN: (
            f"nginx -t rejected the configuration with the site enabled, so Barectl removed "
            f"the unchanged link {paths.link} again and the configuration is valid; Nginx was "
            f"not reloaded. {paths.source} remains and is not loaded."
        ),
        Exit.NGINX_INVALID: (
            "nginx -t rejected the configuration, and still rejected it after Barectl withdrew "
            f"the unchanged link {paths.link}, or the link had changed and was kept; Nginx was "
            f"not reloaded. Run nginx -t, and if {paths.link} exists and is the cause, remove it "
            f"with rm {paths.link} before Nginx is next reloaded."
        ),
        Exit.NGINX_RELOAD: (
            "Every file is published, but systemctl reload nginx.service failed. Inspect it "
            "with systemctl status nginx.service and nginx -t."
        ),
        Exit.NOT_SERVING: (
            "Every file is published and both services reloaded, but the site did not answer "
            "as reviewed: a name did not return the placeholder, an unknown name did, or the "
            f"probe did not report the identity of {user}. The probe was removed."
        ),
        Exit.PROBE_LEFT: (
            f"The run stopped after writing the temporary probe {paths.probe(token)}, which "
            "could not be removed or had changed, so verification is incomplete; the account, "
            "directories and any files published before it stopped remain. Inspect the probe, "
            f"then remove it with rm {paths.probe(token)}."
        ),
    }


_REFUSALS = {
    Execution.LOCK_CONFLICT: (
        "Another change held Barectl's mutation lock on the server, so the run stopped before "
        "changing anything. Prepare a new plan after that change finishes."
    ),
    Execution.UNSAFE_LOCK: (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before changing anything."
    ),
    Execution.BOOT_CHANGED: (
        "The server restarted after the plan was reviewed, so the run stopped before changing "
        "anything. Prepare a new plan."
    ),
    Execution.EXPIRED: (
        "The plan's admission deadline had passed on the server's clock when the run started, "
        "so it stopped before changing anything. Prepare a new plan."
    ),
    Execution.OTHER_RUN_ACTIVE: (
        "Another Barectl run still had processes on the server, so this run stopped before "
        "changing anything. Prepare a new plan after it finishes."
    ),
    Execution.RENEWAL_ACTIVE: bootstrap_apply.RENEWAL_ACTIVE,
    Execution.CAPACITY: (
        "The server kept too many finished runs when this run held the lock, so it stopped "
        "before changing anything. Clear finished runs with a reviewed cleanup, then prepare "
        "again."
    ),
    Execution.DRIFT: (
        "The Nginx or PHP-FPM configuration, accounts, allocation policy, parent directories, "
        "services, packages, listeners or site paths changed after review, so the run stopped "
        "before changing anything. Prepare a new site plan to review the current state."
    ),
    Execution.ACCOUNT_BUSY: (
        "useradd could not change the account databases, for example because another tool "
        "held their lock, and they are unchanged, so the run stopped before changing anything. "
        "Prepare a new site plan after that tool finishes."
    ),
}


def failure(run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
    site = RunSite.objects.filter(run=run).first()
    if outcome in _REFUSALS:
        return _REFUSALS[outcome]
    if outcome == Execution.PARTIAL and site is not None and exit_status is not None:
        paths = SitePaths(site.identifier, site.php_version)
        text = _boundaries(paths, site.probe_token).get(exit_status, "")
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


def reviewed_changes(plan: ConfigurationPlan) -> str:
    lines = []
    account = getattr(plan, "site_account", None)
    if account is not None:
        lines.append(f"Create {account.user} and its group with {account.command}")
    lines += [
        f"Create directory {item.path}, {item.owner}:{item.group} {item.mode}"
        for item in plan.site_directories.all()
    ]
    for item in plan.site_files.all():
        if item.file_type == RunFileChange.Type.SYMLINK:
            lines.append(f"Link {item.path} to {item.link_target}, {item.owner}:{item.group}")
        else:
            removed = ", removed before success" if item.temporary else ""
            lines.append(
                f"Publish {item.path}, {item.owner}:{item.group} {item.mode}, SHA-256 "
                f"{item.content_sha256}{removed}"
            )
    return "\n".join(lines)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    site = plan.site
    RunSite.objects.create(
        run=run,
        identifier=site.identifier,
        php_version=site.php_version,
        names="\n".join(plan.site_names.values_list("name", flat=True)),
        ipv6=site.ipv6,
        probe_token=site.probe_token,
    )
    copied = (
        "position",
        "role",
        "path",
        "file_type",
        "owner",
        "group",
        "mode",
        "link_target",
        "content",
        "content_sha256",
        "preimage_absent",
        "temporary",
    )
    RunFileChange.objects.bulk_create(
        RunFileChange(run=run, **{name: getattr(item, name) for name in copied})
        for item in plan.site_files.all()
    )
    RunDirectoryChange.objects.bulk_create(
        RunDirectoryChange(
            run=run,
            position=item.position,
            path=item.path,
            owner=item.owner,
            group=item.group,
            mode=item.mode,
        )
        for item in plan.site_directories.all()
    )
    account = plan.site_account
    RunAccountChange.objects.create(
        run=run,
        **{
            name: getattr(account, name)
            for name in (
                "user",
                "group",
                "home",
                "login_shell",
                "command",
                "uid_min",
                "uid_max",
                "gid_min",
                "gid_max",
                "free_uids",
                "free_gids",
                "predicted_uid",
                "predicted_gid",
                "subordinate_ids",
            )
        },
    )


# Payload ------------------------------------------------------------------------------------


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        site = plan.site
        account = plan.site_account
        digest = (
            plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION)
            .values_list("fingerprint", flat=True)
            .first()
        )
        files = {}
        for item in plan.site_files.all():
            generated = native.GeneratedFile(
                item.role,
                item.path,
                item.file_type,
                item.owner,
                item.group,
                item.mode,
                item.link_target,
                item.content,
                item.temporary,
            )
            if generated.sha256 != item.content_sha256:
                raise ValueError("A file differs from its reviewed digest.")
            files[item.role] = generated
        paths = SitePaths(site.identifier, site.php_version)
        if account.command != native.useradd(paths):
            raise ValueError("The reviewed account command is not the convention's.")
        change = native.SiteChange(
            paths=paths,
            names=tuple(plan.site_names.values_list("name", flat=True)),
            ipv6=site.ipv6,
            token=site.probe_token,
            digest=digest or "",
            uid_range=(account.uid_min, account.uid_max),
            gid_range=(account.gid_min, account.gid_max),
            placeholder=files["placeholder"],
            probe=files["probe"],
            pool=files["pool"],
            site=files["nginx_source"],
        )
        return native.site_payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, change
        )
    except ValueError, KeyError, ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _state_argv(run: ApplyRun) -> list[str]:
    site = run.site
    return native.site_state(SitePaths(site.identifier, site.php_version), site.probe_token)


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    if root:
        return
    if shell.run(bootstrap_native.authorization(_state_argv(run))).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Verification -------------------------------------------------------------------------------


class Unreadable(Exception):
    pass


@dataclass
class _State:
    records: dict[str, str] = field(default_factory=dict)
    paths: dict[str, tuple[str, int, str, str, int]] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    digests: dict[str, str] = field(default_factory=dict)
    units: dict[str, str] = field(default_factory=dict)
    checks: set[str] = field(default_factory=set)


_KINDS = {0o100000: "f", 0o040000: "d", 0o120000: "l", 0o140000: "s"}
_ACCOUNT = r"[a-z_][a-z0-9_.-]{0,31}|UNKNOWN"


def parse_state(text: str) -> _State:
    state = _State()
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind in {"passwd", "group", "groups", "lock", "target", "listening"}:
            state.records[kind] = rest[:300]
        elif kind == "path":
            match = re.fullmatch(
                rf"([0-9a-f]{{1,8}}) ({_ACCOUNT}|[0-9]+) ({_ACCOUNT}|[0-9]+) "
                r"([0-9]{1,10}) (/\S+)",
                rest,
            )
            if match is None:
                raise Unreadable
            raw = int(match[1], 16)
            state.paths[match[5]] = (
                _KINDS.get(raw & 0o170000, "o"),
                raw & 0o7777,
                match[2],
                match[3],
                int(match[4]),
            )
        elif kind == "absent":
            state.absent.add(rest)
        elif kind == "sha":
            digest, _, path = rest.partition(" ")
            state.digests[path] = digest
        elif kind == "unit":
            name, _, value = rest.partition(" ")
            state.units[name] = value
        elif kind in {"nginx", "fpm"}:
            state.checks.add(f"{kind} {rest}")
        else:
            raise Unreadable
    return state


def _account_problems(run: ApplyRun, state: _State, uid: int | None, gid: int | None) -> list[str]:
    account = run.site_account
    user = account.user
    problems: list[str] = []
    in_range = (
        uid is not None
        and gid is not None
        and account.uid_min <= uid <= account.uid_max
        and account.gid_min <= gid <= account.gid_max
    )
    expected = f"{user}:x:{uid}:{gid}::{account.home}:{NOLOGIN}"
    if not in_range or state.records.get("passwd") != expected:
        problems.append(f"{user} does not have the reviewed account entry.")
    groups = (state.records.get("group"), state.records.get("groups"))
    if groups != (f"{user}:x:{gid}:", str(gid)):
        problems.append(f"The group {user} or {user}'s groups differ from the review.")
    if state.records.get("lock") != "!":
        problems.append(f"The password of {user} is not locked.")
    return problems


def _file_problem(item: RunFileChange, state: _State) -> str:
    found = state.paths.get(item.path)
    if item.temporary:
        return "" if item.path in state.absent else f"The temporary probe {item.path} remains."
    if item.file_type == RunFileChange.Type.SYMLINK:
        link = found is not None and found[0] == "l" and found[2] == item.owner
        if link and state.records.get("target") == item.link_target:
            return ""
        return f"{item.path} is not the reviewed link to {item.link_target}."
    expected = ("f", int(item.mode, 8), item.owner, item.group, 1)
    if found == expected and state.digests.get(item.path) == item.content_sha256:
        return ""
    return f"{item.path} does not have its reviewed bytes, owner and mode."


def _path_problems(run: ApplyRun, state: _State) -> list[str]:
    problems = [
        f"{directory.path} does not have its reviewed owner and mode."
        for directory in run.site_directories.all()
        if state.paths.get(directory.path, ("",))[:4]
        != ("d", int(directory.mode, 8), directory.owner, directory.group)
    ]
    problems += [
        problem for item in run.site_files.all() if (problem := _file_problem(item, state))
    ]
    return problems


def _service_problems(paths: SitePaths, state: _State) -> list[str]:
    problems = []
    socket = state.paths.get(paths.socket, ("",))[:4]
    if socket != ("s", 0o600, WEB_USER, WEB_USER) or state.records.get("listening", "0") == "0":
        problems.append(f"{paths.socket} is not the pool's listening socket.")
    problems += [
        f"{unit} is not active and running."
        for unit in ("nginx.service", paths.fpm_service)
        if state.units.get(unit) != "active/running"
    ]
    if state.checks != {"nginx valid", "fpm valid"}:
        problems.append("nginx -t or the PHP-FPM syntax check rejects the configuration.")
    return problems


def _serving_problems(site: RunSite, text: str) -> list[str]:
    lines = set(text.splitlines())
    families = ("127.0.0.1", "[::1]") if site.ipv6 else ("127.0.0.1",)
    problems = [
        f"{name} did not return the placeholder over {address}."
        for address in families
        for name in site.names.splitlines()
        if f"served {address} {name}" not in lines
    ]
    problems += [
        f"A name no site declares reached the site over {address}."
        for address in families
        if f"missing {address} unknown-{site.probe_token}.invalid" not in lines
    ]
    return problems


def _read(shell: RemoteShell, run: ApplyRun, site: RunSite) -> tuple[str, str] | None:
    """The privileged state and the serving answers, or ``None`` when unreadable."""
    root = bootstrap_native.is_root(shell)
    argv = _state_argv(run)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    served = shell.run(
        native.serving(
            site.php_version,
            site.identifier,
            tuple(site.names.splitlines()),
            ipv6=site.ipv6,
            token=site.probe_token,
        )
    )
    if result.exit_status or result.truncated or served.exit_status or served.truncated:
        return None
    return result.stdout, served.stdout


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/ssh-connections.md#applying-sites: fresh reads after a successful run."""
    site = RunSite.objects.filter(run=run).first()
    read = None if site is None else _read(shell, run, site)
    if site is None or read is None:
        return Verification.UNAVAILABLE
    try:
        state = parse_state(read[0])
    except Unreadable:
        return Verification.UNAVAILABLE
    fields = state.records.get("passwd", "").split(":")
    uid = int(fields[2]) if len(fields) == 7 and fields[2].isdigit() else None
    gid = int(fields[3]) if len(fields) == 7 and fields[3].isdigit() else None
    paths = SitePaths(site.identifier, site.php_version)
    problems = [
        *_account_problems(run, state, uid, gid),
        *_path_problems(run, state),
        *_service_problems(paths, state),
        *_serving_problems(site, read[1]),
    ]
    if not SiteRunResult.objects.filter(run=run).exists():
        SiteRunResult.objects.create(
            run=run,
            uid=uid,
            gid=gid,
            probe_absent=all(
                item.path in state.absent for item in run.site_files.filter(temporary=True)
            ),
            problems="\n".join(problems),
            verified_at=timezone.now(),
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = SiteRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    site = RunSite.objects.filter(run=run).first()
    user = f"s{site.identifier}" if site else "The site user"
    lines = [
        f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}.",
        f"{user} was bound to UID {result.uid} and GID {result.gid}."
        if result.uid is not None
        else f"{user}'s IDs could not be read.",
        "The temporary probe was removed."
        if result.probe_absent
        else "The temporary probe still exists.",
    ]
    lines += result.problems.splitlines()
    return lines


def verification_failure(run: ApplyRun) -> str:
    result = SiteRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the site's discovery.")
