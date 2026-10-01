"""Certbot renewal setup: the package review, the renewal evidence and their admission.

docs/tls.md#certbot-renewal-setup. Bootstrap reviews the packages exactly as it reviews
any profile; this module adds what setup changes besides them, and refuses Certbot state
or automation that the guarded renewal cannot account for.
"""

import re
from dataclasses import dataclass, field
from typing import override

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap import review as bootstrap_review
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Privilege,
)
from bootstrap.profiles import PROFILE_REVISION, profile
from bootstrap.review import Draft, EvidenceDraft
from discovery.ssh import RemoteShell
from sites.names import IDENTIFIER

from . import renewal, setup_native

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
_CRON_CONFFILE = "/etc/cron.d/certbot"
_HOOKS = ("renewal-hooks", "renewal-hooks/pre", "renewal-hooks/deploy", "renewal-hooks/post")
_TIMER_LINK = "/etc/systemd/system/timers.target.wants/certbot.timer"
PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "renewal inspection without a password. Renewal setup reads Certbot's configuration, "
    "systemd's unit directories and the scheduled tasks as root, as applying later checks "
    "them. Barectl never installs a sudo policy or asks for a password."
)


class Unreadable(Exception):
    pass


@dataclass
class RenewalState:
    """What the fixed renewal read reported, by kind."""

    paths: dict[str, tuple[str, str, str, str, str]] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    systemd: list[tuple[str, str, str]] = field(default_factory=list)
    sha: dict[str, str] = field(default_factory=dict)
    md5: dict[str, str] = field(default_factory=dict)
    letsencrypt: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    lib: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    cron: list[str] = field(default_factory=list)
    unit_files: list[str] = field(default_factory=list)
    snaps: list[str] = field(default_factory=list)
    conffiles: dict[str, str] = field(default_factory=dict)
    units: dict[str, dict[str, str]] = field(default_factory=dict)
    syntax: set[str] = field(default_factory=set)
    version: str = ""


_PATH = re.compile(
    r"([a-z ]{1,40})\|([a-z_][a-z0-9_.-]{0,31}|[0-9]+)\|([a-z_][a-z0-9_.-]{0,31}|[0-9]+)"
    r"\|([0-7]{1,4})\|([0-9]{1,10})\|(/\S{0,200})"
)
_ENTRY = re.compile(r"([a-z]) ([0-7]{1,4}) ([0-9]{1,10}) ([0-9]{1,10}) (/\S{0,300})")
_SYSTEMD = re.compile(r"([a-z]) (/\S{1,200})(?: (\S{0,200}))?")
_HEX = re.compile(r"([0-9a-f]{32}|[0-9a-f]{64}) (/\S{1,200})")
_NAME = re.compile(r"\S{1,200}")
_SHOW = re.compile(r"(certbot\.service|certbot\.timer) ([A-Za-z]{1,40})=(.*)")


def parse_state(text: str) -> RenewalState:  # noqa: C901 - one branch per documented kind
    state = RenewalState()
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "path" and (match := _PATH.fullmatch(rest)):
            state.paths[match[6]] = (match[1], match[2], match[3], match[4], match[5])
        elif kind == "absent" and rest.startswith("/"):
            state.absent.add(rest)
        elif kind == "unit" and (match := _SYSTEMD.fullmatch(rest)):
            state.systemd.append((match[1], match[2], match[3] or ""))
        elif kind in {"sha", "md5"} and (match := _HEX.fullmatch(rest)):
            (state.sha if kind == "sha" else state.md5)[match[2]] = match[1]
        elif kind in {"letsencrypt", "lib"} and (match := _ENTRY.fullmatch(rest)):
            entry = (match[1], match[2], match[3], match[4], match[5])
            (state.letsencrypt if kind == "letsencrypt" else state.lib).append(entry)
        elif kind in {"cron", "unitfile", "snap"} and _NAME.fullmatch(rest):
            {"cron": state.cron, "unitfile": state.unit_files, "snap": state.snaps}[kind].append(
                rest
            )
        elif kind == "conffile" and (match := re.fullmatch(r"([0-9a-f]{32}) (/\S{1,200})", rest)):
            state.conffiles[match[2]] = match[1]
        elif kind == "show" and (match := _SHOW.fullmatch(rest)):
            state.units.setdefault(match[1], {})[match[2]] = match[3][:500]
        elif kind == "syntax" and rest.startswith("ok /"):
            state.syntax.add(rest.removeprefix("ok "))
        elif kind == "version":
            state.version = rest[:100]
        else:
            raise Unreadable("The renewal inspection is not in its expected form.")
    return state


@dataclass
class SetupDraft(Draft):
    # Whether the packages are installed already.
    installed: bool = False
    # The renewal files that do not exist yet, by path.
    publishes: tuple[str, ...] = ()
    payload_bytes: int | None = None
    # What renewal's units reported, for the review's read-only renewal inspection.
    observed: dict[str, str] = field(default_factory=dict)

    @property
    @override
    def revision(self) -> int:
        return PROFILE_REVISION


def _listed(items: list[str]) -> str:
    shown = "; ".join(items[:5])
    return f"{shown}; and {len(items) - 5} more" if len(items) > 5 else shown


def _read(shell: RemoteShell, argv: list[str], root: bool, what: str) -> str | None:
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        raise Unreadable(f"Barectl could not read {what}.")
    return result.stdout


def prepare(shell: RemoteShell) -> SetupDraft:
    evidence = bootstrap_inspection.inspect(shell, Action.CERTBOT)
    draft = SetupDraft(**vars(bootstrap_review.review(Action.CERTBOT, evidence)))
    platform = evidence.platform
    if draft.release is None or platform is None:
        return draft
    root = platform.privilege == Privilege.ROOT
    try:
        before = _read(shell, setup_native.renewal_digest_argv(), root, "the renewal digest")
        if before is None:
            draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
            return draft
        text = _read(shell, setup_native.renewal_state(), root, "the renewal state")
        after = _read(shell, setup_native.renewal_digest_argv(), root, "the renewal digest")
        state = parse_state(text or "")
        digest = bootstrap_native.parse_digest(after or "")
    except (Unreadable, bootstrap_native.Unreadable) as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return draft
    if before != after:
        draft.refuse(
            Reason.INCOMPLETE,
            "Certbot's configuration, units or scheduled tasks changed while Barectl read "
            "them. Prepare again once they are settled.",
        )
    draft.evidence.append(
        EvidenceDraft(
            PlanEvidence.Kind.RENEWAL_REVALIDATION,
            digest,
            "Certbot's configuration and state directories, its units and drop-ins, the "
            "renewal files, scheduled tasks and other certificate automation, rechecked as "
            "root under the mutation lock before applying.",
        )
    )
    admit(draft, state)
    draft.observed = observation(state)
    return draft


def observation(state: RenewalState) -> dict[str, str]:
    service = state.units.get("certbot.service", {})
    timer = state.units.get("certbot.timer", {})
    return {
        "timer_enablement": timer.get("UnitFileState", ""),
        "timer_state": timer.get("ActiveState", ""),
        "last_trigger": timer.get("LastTriggerUSec", ""),
        "next_elapse": timer.get("NextElapseUSecRealtime", ""),
        "last_result": service.get("Result", ""),
        "last_status": service.get("ExecMainStatus", ""),
        "last_exit": service.get("ExecMainExitTimestamp", ""),
    }


def admit(draft: SetupDraft, state: RenewalState) -> None:
    release = draft.release
    if release is None:
        return
    installed = any(root.name == "certbot" and root.installed for root in draft.roots)
    draft.installed = installed
    _automation(draft, state, installed=installed)
    _certbot_state(draft, state, installed=installed)
    _systemd(draft, state)
    files = _files(draft, state, installed=installed)
    if installed and state.version != f"certbot {release.certbot}":
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            f"Certbot reports {state.version or 'no version'}, not certbot {release.certbot}, "
            f"the version {release.name}'s qualified renewal setup uses.",
        )
    if not draft.eligible:
        return
    draft.publishes = tuple(path for path, exists in files.items() if not exists)
    if installed and not draft.publishes and _satisfied(state):
        draft.effects = [
            (
                Effect.NO_CHANGES,
                (
                    "No changes. Certbot is installed at the qualified version, its renewal is "
                    "guarded by Barectl's wrapper and deploy hook, and certbot.timer is enabled "
                    "and active with the packaged schedule."
                ),
            )
        ]
        return
    draft.effects = [item for item in draft.effects if item[0] != Effect.NO_CHANGES]
    _payload(draft)
    if draft.eligible:
        _effects(draft)


def _automation(draft: SetupDraft, state: RenewalState, *, installed: bool) -> None:
    others = [name for name in state.unit_files if name not in {"certbot.service", "certbot.timer"}]
    for name in others:
        draft.refuse(
            Reason.AUTOMATION,
            f"The unit {name} may renew or issue certificates outside Barectl's guarded "
            f"renewal. Barectl does not stop or disable it; if it is not needed, run systemctl "
            f"disable --now {name} through ordinary administration, then prepare again.",
        )
    for name in state.snaps:
        draft.refuse(
            Reason.AUTOMATION,
            f"The snap {name} is installed and brings its own renewal. Barectl does not remove "
            f"it; if it is not needed, run snap remove {name}, then prepare again.",
        )
    conffile = state.conffiles.get(_CRON_CONFFILE)
    for path in state.cron:
        unmodified = path == _CRON_CONFFILE and conffile and state.md5.get(path) == conffile
        if not (installed and unmodified):
            draft.refuse(
                Reason.AUTOMATION,
                f"The scheduled task {path} mentions certificate automation. Barectl admits "
                f"only Certbot's unmodified {_CRON_CONFFILE}, which does nothing under "
                "systemd; remove or change the task through ordinary administration, then "
                "prepare again.",
            )


def _certbot_state(draft: SetupDraft, state: RenewalState, *, installed: bool) -> None:
    allowed = {"/etc/letsencrypt/cli.ini": "f", **{f"/etc/letsencrypt/{p}": "d" for p in _HOOKS}}
    found = [
        path for kind, _mode, _uid, _gid, path in state.letsencrypt if allowed.get(path) != kind
    ]
    if installed and found:
        draft.refuse(
            Reason.AUTOMATION,
            f"Certbot already has accounts, certificates, renewal configuration or hooks "
            f"({_listed(found)}). Renewal setup is admitted only before any "
            "lineage or account exists, so that nothing can renew unguarded; Barectl does not "
            "adopt, move or remove them.",
        )
    if "/root/.config/letsencrypt" not in state.absent:
        draft.refuse(
            Reason.AUTOMATION,
            "/root/.config/letsencrypt exists, a per-user Certbot configuration the guarded "
            "renewal does not account for. Remove it through ordinary administration, then "
            "prepare again.",
        )
    webroots = [
        path
        for kind, mode, uid, _gid, path in state.lib
        if not (kind == "d" and uid == "0" and IDENTIFIER.fullmatch(path.rpartition("/")[2]))
    ]
    if webroots:
        draft.refuse(
            Reason.AUTOMATION,
            f"/var/lib/letsencrypt holds {_listed(webroots)}, which are not "
            "site webroots. Barectl does not adopt another tool's working files.",
        )


def _systemd(draft: SetupDraft, state: RenewalState) -> None:
    allowed = {
        ("l", _TIMER_LINK, "/usr/lib/systemd/system/certbot.timer"),
        ("d", renewal.DROP_IN_DIRECTORY, ""),
    }
    for kind, path, target in state.systemd:
        if (kind, path, target) in allowed:
            continue
        if path.startswith("/run/systemd/system/certbot."):
            draft.refuse(
                Reason.SERVICE_UNIT,
                f"{path} exists: Certbot's units are masked or overridden at runtime, as an "
                "interrupted setup leaves them until the server restarts. Run systemctl "
                "unmask --runtime certbot.timer certbot.service, then prepare again.",
            )
        else:
            draft.refuse(
                Reason.AUTOMATION,
                f"{path} overrides Certbot's packaged units. Barectl admits only its own "
                f"{renewal.DROP_IN}; remove it through ordinary administration, then prepare "
                "again.",
            )
    service = state.units.get("certbot.service", {})
    if service.get("DropInPaths", "") not in {"", renewal.DROP_IN}:
        draft.refuse(
            Reason.AUTOMATION,
            f"certbot.service has other drop-ins ({service['DropInPaths']}). Barectl admits "
            f"only {renewal.DROP_IN}.",
        )
    timer = state.units.get("certbot.timer", {})
    if timer.get("DropInPaths", ""):
        draft.refuse(
            Reason.AUTOMATION,
            f"certbot.timer has drop-ins ({timer['DropInPaths']}); the guarded renewal uses the "
            "packaged schedule unchanged.",
        )


def _files(draft: SetupDraft, state: RenewalState, *, installed: bool) -> dict[str, bool]:
    """Whether each renewal file exists as reviewed; refuses any other form of it."""
    problems = []
    for path in ("/usr", "/usr/local", "/usr/local/sbin", "/etc/systemd/system"):
        found = state.paths.get(path)
        if (
            found is None
            or found[0] != "directory"
            or found[1] != "root"
            or int(found[3], 8) & 0o022
        ):
            problems.append(f"{path} is not a directory owned by root that only root can write")
    exists = {}
    for file in renewal.files():
        found = state.paths.get(file.path)
        exists[file.path] = found is not None
        if found is None:
            continue
        exact = found == ("regular file", "root", "root", file.mode.lstrip("0"), "1")
        if not exact or state.sha.get(file.path) != file.sha256:
            problems.append(f"{file.path} exists and is not the reviewed file")
        elif not installed:
            problems.append(f"{file.path} exists although Certbot is not installed")
    directory = state.paths.get(renewal.DROP_IN_DIRECTORY)
    if directory is not None and directory[:4] != ("directory", "root", "root", "755"):
        problems.append(f"{renewal.DROP_IN_DIRECTORY} is not a root:root 0755 directory")
    if problems:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"{_listed(problems)}. Barectl does not replace files it did not "
            "publish; remove or correct them through ordinary administration, then prepare "
            "again.",
        )
    return exists


def _satisfied(state: RenewalState) -> bool:
    service = state.units.get("certbot.service", {})
    timer = state.units.get("certbot.timer", {})
    return (
        service.get("DropInPaths") == renewal.DROP_IN
        and timer.get("UnitFileState") == "enabled"
        and timer.get("ActiveState") == "active"
        and timer.get("RandomizedDelayUSec") == renewal.TIMER_RANDOMIZED_DELAY
        and {renewal.WRAPPER, renewal.DEPLOY_HOOK} <= state.syntax
    )


def _payload(draft: SetupDraft) -> None:
    platform, release = draft.platform, draft.release
    if platform is None or platform.uptime_centiseconds is None or release is None:
        return
    certbot = profile(release, Action.CERTBOT)
    digests = {item.kind: item.fingerprint for item in draft.evidence}
    try:
        payload = setup_native.setup_payload(
            bootstrap_native.new_unit_name(),
            platform.boot_id,
            platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            apt=digests.get(PlanEvidence.Kind.APT_REVALIDATION, "0" * 64),
            packages=digests.get(PlanEvidence.Kind.PACKAGE_REVALIDATION, "0" * 64),
            scope=certbot.revalidation,
            digest=digests.get(PlanEvidence.Kind.RENEWAL_REVALIDATION, "0" * 64),
            roots=[(root.name, root.version) for root in draft.roots if not root.installed],
            actions=actions(draft),
            check=certbot.check,
        )
    except ValueError:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    draft.payload_bytes = len(payload.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this setup would need {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run.",
        )


def actions(draft: Draft) -> list[bootstrap_native.PackageAction]:
    return [
        bootstrap_native.PackageAction(
            transition.step == PackageTransition.Step.INSTALL,
            transition.package,
            transition.version,
            transition.architecture,
        )
        for transition in draft.transitions
    ]


def _effects(draft: SetupDraft) -> None:
    publishes = [file for file in renewal.files() if file.path in draft.publishes]
    names = ", ".join(file.path for file in publishes) or "none; they exist as reviewed"
    if draft.installed:
        draft.effects.insert(
            0,
            (
                Effect.SERVICE_INHIBITION,
                (
                    "certbot.timer and certbot.service are masked at runtime for the whole run, "
                    "so neither can start while the override is published; the masks are removed "
                    "only after the override is verified, and a restart removes them too."
                ),
            ),
        )
    draft.effects.extend(
        [
            (
                Effect.RENEWAL_INTEGRATION,
                (
                    f"Publishes the files listed below ({names}), each staged beside its "
                    "destination and linked into place only while the destination is absent. "
                    "After systemctl daemon-reload, requires certbot.service to load the packaged "
                    "unit with exactly this drop-in, its one ExecStart the wrapper, success exit "
                    f"statuses {renewal.Outcome.LOCK_HELD} and {renewal.Outcome.APPLY_ACTIVE}, a "
                    "30 minute start limit, a 60 second stop limit and control-group killing, "
                    "and both scripts valid shell. Only then unmasks certbot.timer and enables and "
                    f"starts it, with its packaged schedule: {renewal.TIMER_CALENDAR} plus a "
                    "random delay of up to 12 hours. No certificate, account or lineage is "
                    "created and no certificate authority is contacted."
                ),
            ),
            (
                Effect.COMPATIBLE_CLIENTS,
                (
                    "Guarded renewal takes Barectl's mutation lock and skips while any Barectl "
                    "run has processes; every Barectl run refuses while renewal has processes. "
                    "That needs controllers from this version on: upgrade or stop older "
                    "controllers, such as v0.2, before relying on it. No remote registry of "
                    "controllers exists, and administrative commands that ignore the lock remain "
                    "outside the guarantee."
                ),
            ),
        ]
    )
    if not any(kind == Effect.NO_ROLLBACK for kind, _ in draft.effects):
        draft.effects.append(
            (
                Effect.NO_ROLLBACK,
                (
                    "Barectl does not roll back. A stop after the first change leaves what it "
                    "reached, recorded with its boundary; the runtime masks keep renewal "
                    "inhibited until the server restarts, and the timer stays disabled."
                ),
            )
        )
    draft.postconditions.extend(
        [
            "Each renewal file has its reviewed bytes, root:root and mode.",
            "certbot.service loads the packaged unit with exactly the reviewed drop-in.",
            (
                "certbot.timer is enabled and active with the packaged schedule; no runtime mask "
                "remains."
            ),
            "certbot --version reports the reviewed version.",
        ]
    )
