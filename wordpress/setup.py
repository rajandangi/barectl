"""WP-CLI tool setup: the review, the artifact admission and its refusals.

docs/wordpress.md#wp-cli-setup. The tool is not a package: preparation reviews only the
fixed installation path's native state and the pinned official artifacts, and refuses
foreign tools, unsafe ancestry and missing native tooling rather than repairing them.
"""

import re
from dataclasses import dataclass, field
from typing import override

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap import releases as bootstrap_releases
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Privilege,
)
from bootstrap.review import Draft, EvidenceDraft, check_platform
from discovery.ssh import RemoteShell

from . import setup_native

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
# The revision of the WordPress tool definitions a plan was reviewed against.
PROFILE_REVISION = 1
INTENT = f"Install the authenticated WP-CLI {setup_native.VERSION} PHAR at {setup_native.PHAR}"
PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "WP-CLI inspection without a password. Setup reads the installation path's state as "
    "root, as applying later rechecks it. Barectl never installs a sudo policy or asks for "
    "a password."
)
TOOLS = (
    "The server does not have the native tools this setup needs: /usr/bin/gpg and "
    "/usr/bin/curl. Install them through ordinary administration, then prepare again; "
    "Barectl installs neither."
)


class Unreadable(Exception):
    pass


@dataclass
class WpcliState:
    """What the fixed WP-CLI read reported, by kind."""

    paths: dict[str, tuple[str, str, str, str, str]] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    sha: dict[str, str] = field(default_factory=dict)
    entries: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    tools: dict[str, bool] = field(default_factory=dict)
    version: str = ""


_PATH = re.compile(
    r"([a-z ]{1,40})\|([a-z_][a-z0-9_.-]{0,31}|[0-9]+)\|([a-z_][a-z0-9_.-]{0,31}|[0-9]+)"
    r"\|([0-7]{1,4})\|([0-9]{1,10})\|(/\S{0,200})"
)
_ENTRY = re.compile(r"([a-z]) ([0-7]{1,4}) ([0-9]{1,10}) ([0-9]{1,10}) (/\S{0,300})")
_HEX = re.compile(r"[0-9a-f]{64} (/\S{1,200})")


def parse_state(text: str) -> WpcliState:
    state = WpcliState()
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "path" and (match := _PATH.fullmatch(rest)):
            state.paths[match[6]] = (match[1], match[2], match[3], match[4], match[5])
        elif kind == "absent" and rest.startswith("/"):
            state.absent.add(rest)
        elif kind == "sha" and (match := _HEX.fullmatch(rest)):
            state.sha[match[1]] = rest.removesuffix(f" {match[1]}")
        elif kind == "entry" and (match := _ENTRY.fullmatch(rest)):
            state.entries.append((match[1], match[2], match[3], match[4], match[5]))
        elif kind == "tool" and re.fullmatch(r"(gpg|curl) (ok|missing)", rest):
            name, _, found = rest.partition(" ")
            state.tools[name] = found == "ok"
        elif kind == "version":
            state.version = rest[:100]
        else:
            raise Unreadable("The WP-CLI inspection is not in its expected form.")
    return state


@dataclass
class SetupDraft(Draft):
    # Whether the reviewed artifact is already installed with its exact bytes.
    installed: bool = False
    # Whether the installation directory is absent and the run creates it.
    creates_directory: bool = False
    payload_bytes: int | None = None
    # What the tool inspection observed, for the review's own words.
    observed: dict[str, str] = field(default_factory=dict)

    @property
    @override
    def revision(self) -> int:
        return PROFILE_REVISION


def _read(shell: RemoteShell, argv: list[str], root: bool, what: str) -> str | None:
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        raise Unreadable(f"Barectl could not read {what}.")
    return result.stdout


def observation(state: WpcliState) -> dict[str, str]:
    return {
        "phar": "absent" if setup_native.PHAR in state.absent else "present",
        "sha256": state.sha.get(setup_native.PHAR, ""),
        "gpg": state.version or ("ok" if state.tools.get("gpg") else "missing"),
        "curl": "ok" if state.tools.get("curl") else "missing",
    }


def prepare(shell: RemoteShell) -> SetupDraft:
    reader = bootstrap_inspection.Reader(shell)
    platform = bootstrap_inspection.read_platform(reader)
    release = bootstrap_releases.of(platform.os) if platform is not None else None
    draft = SetupDraft(Action.WPCLI, INTENT, platform, release)
    check_platform(draft, platform)
    for gap in reader.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    if platform is None or release is None or not draft.eligible:
        return draft
    root = platform.privilege == Privilege.ROOT
    try:
        before = _read(shell, setup_native.wpcli_digest_argv(), root, "the WP-CLI digest")
        if before is None:
            draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
            return draft
        text = _read(shell, setup_native.wpcli_state(), root, "the WP-CLI state")
        after = _read(shell, setup_native.wpcli_digest_argv(), root, "the WP-CLI digest")
        state = parse_state(text or "")
        digest = bootstrap_native.parse_digest(after or "")
    except (Unreadable, bootstrap_native.Unreadable) as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return draft
    if before != after:
        draft.refuse(
            Reason.INCOMPLETE,
            "The WP-CLI installation path changed while Barectl read it. Prepare again "
            "once it is settled.",
        )
    draft.evidence.append(
        EvidenceDraft(
            PlanEvidence.Kind.WPCLI_REVALIDATION,
            digest,
            "The tool installation path, its entries and the native tools GPG and curl, "
            "rechecked as root under the mutation lock before applying.",
        )
    )
    admit(draft, state)
    draft.observed = observation(state)
    return draft


def _ancestry(draft: SetupDraft, state: WpcliState) -> None:
    problems = []
    for path in ("/usr", "/usr/local", "/usr/local/lib"):
        found = state.paths.get(path)
        if (
            found is None
            or found[0] != "directory"
            or found[1] != "root"
            or int(found[3], 8) & 0o022
        ):
            problems.append(f"{path} is not a directory owned by root that only root can write")
    if problems:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"{'.'.join(problems)}. Barectl does not install beneath writable ancestry; "
            "correct it through ordinary administration, then prepare again.",
        )


def admit(draft: SetupDraft, state: WpcliState) -> None:
    _ancestry(draft, state)
    if not draft.eligible:
        return
    directory = state.paths.get(setup_native.DIRECTORY)
    if directory is not None and directory[0:4] != ("directory", "root", "root", "755"):
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"{setup_native.DIRECTORY} exists and is not a root:root 0755 directory. Barectl "
            "does not adopt or replace another layout; correct it through ordinary "
            "administration, then prepare again.",
        )
        return
    phar = state.paths.get(setup_native.PHAR)
    if phar is None:
        entries = [entry[4] for entry in state.entries]
        if entries:
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"{setup_native.DIRECTORY} holds {', '.join(entries[:5])}, which Barectl did "
                "not publish. Barectl does not adopt another tool's files; remove them "
                "through ordinary administration, then prepare again.",
            )
            return
        missing = sorted(name for name, present in state.tools.items() if not present)
        if missing:
            draft.refuse(Reason.PREREQUISITE, TOOLS)
            return
        draft.installed = False
        draft.creates_directory = directory is None
        _propose(draft, creates_directory=directory is None)
        return
    exact = phar == ("regular file", "root", "root", "644", "1") and (
        state.sha.get(setup_native.PHAR) == setup_native.SHA256
    )
    if not exact:
        found = " or ".join(filter(None, (phar[0], phar[3])))
        draft.refuse(
            Reason.COLLISION,
            f"{setup_native.PHAR} exists ({found}), and is not the reviewed authenticated "
            f"WP-CLI {setup_native.VERSION} artifact. Barectl does not overwrite foreign "
            "tools or self-update WP-CLI; remove or correct it through ordinary "
            "administration, then prepare again.",
        )
        return
    draft.installed = True
    draft.effects = [
        (
            Effect.NO_CHANGES,
            (
                f"No changes. The authenticated WP-CLI {setup_native.VERSION} artifact is "
                "installed at its reviewed path, owner, mode and digest."
            ),
        )
    ]
    draft.postconditions.append(
        f"{setup_native.PHAR} keeps its reviewed bytes, owner root:root and mode 0644."
    )


def _propose(draft: SetupDraft, *, creates_directory: bool) -> None:
    if draft.platform is None or draft.platform.uptime_centiseconds is None:
        return
    digests = {item.kind: item.fingerprint for item in draft.evidence}
    try:
        payload = setup_native.setup_payload(
            bootstrap_native.new_unit_name(),
            draft.platform.boot_id,
            draft.platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            digest=digests.get(PlanEvidence.Kind.WPCLI_REVALIDATION, "0" * 64),
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
        return
    draft.effects.extend(
        [
            (
                Effect.TOOL_DOWNLOAD,
                (
                    f"Downloads the pinned official release artifacts over HTTPS "
                    f"({setup_native.PHAR_URL} and its detached signature) and the published "
                    f"signing key, then authenticates them with native GPG against the "
                    f"approved primary signing identity {setup_native.FINGERPRINT}, requiring "
                    "the actual signer to be that key or one of its bound signing subkeys. A "
                    "changed key or artifact, an invalid, revoked or expired signature, or a "
                    f"digest other than {setup_native.SHA256} refuses before anything is "
                    "installed. Nothing downloaded is executed."
                ),
            ),
            (
                Effect.TOOL_INSTALL,
                (
                    (
                        f"Creates {setup_native.DIRECTORY} (root:root 0755) and publishes "
                        if creates_directory
                        else "Publishes "
                    )
                    + f"{setup_native.PHAR}, root:root 0644, staged beside its "
                    "destination and linked into place only while the destination is absent. "
                    "No PHP runs in any step, and no package, service or site changes."
                ),
            ),
            (
                Effect.NO_ROLLBACK,
                (
                    "Barectl does not roll back. A stop after the first change leaves what it "
                    "reached, recorded with its boundary; the run's private staging directory "
                    "under /run and a staged file beside the destination are safe to remove."
                ),
            ),
        ]
    )
    draft.postconditions.extend(
        [
            (
                f"{setup_native.PHAR} is a regular file owned by root:root with mode 0644 and "
                f"SHA-256 {setup_native.SHA256}."
            ),
            (
                f"{setup_native.DIRECTORY} holds only the reviewed artifact, on root-owned, "
                "non-writable ancestry."
            ),
            "The run's journal records the signing identity its signature authenticated.",
        ]
    )
