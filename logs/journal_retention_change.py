"""Set the server's journald log retention policy (#551).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. One reviewed Shared
change writes a disk cap and a maximum age together to Barectl's own drop-in, restarts
journald and verifies both effective values. Discovery reconstructs the same state from the
fixed foundation read.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from logs.journal_retention import (
    DISK_CAP_CHOICES,
    DISK_CAP_LABELS,
    MANAGED,
    MAX_AGE_CHOICES,
    MAX_AGE_LABELS,
    OUTSIDE,
    RETENTION_PATH,
    RetentionObservation,
    reconstruct,
    render,
)
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

from .bodies.reasons import JOURNAL_RETENTION_REASONS

SLUG: Final = "set_journal_retention"
LABEL: Final = "Change journal retention"
STAGES: Final = ("preflight", "publish", "verify")
# The compressed reviewed document is one native argument; the bound leaves room for the
# engine's admission and the body itself under ADR 0006's payload limit.
MAX_ARGUMENT: Final = 4096

SOURCE: Final = importlib.resources.files("logs.bodies").joinpath("journal_retention.py")
BODY_SOURCE: Final = SOURCE.read_text()
BODY_BYTES: Final = (
    "#!/bin/sh\nexec python3 -c "
    + shlex.quote(
        "import base64,gzip; exec(gzip.decompress(base64.b64decode("
        + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
        + ")))"
    )
    + ' "$@"'
).encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()

_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_UPTIME = re.compile(r"[0-9]{1,16}")
_JOURNAL_VALUE = re.compile(r"[A-Za-z0-9.%:+-]{0,32}")


def encode_document(document: dict[str, object]) -> str:
    """The one native argument: the reviewed texts compressed and base64 encoded."""
    value = {
        "disk_cap": document.get("disk_cap"),
        "max_age": document.get("max_age"),
        "retention": document.get("retention"),
        "previous": document.get("previous"),
        "previous_disk_cap": document.get("previous_disk_cap"),
        "previous_max_age": document.get("previous_max_age"),
    }
    return base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()


@dataclass(frozen=True)
class JournalRetentionEvidence:
    standing: Standing | None
    boot_id: str
    uptime_centiseconds: int | None
    observation: RetentionObservation | None
    previous: str | None
    previous_disk_cap: str
    previous_max_age: str


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> JournalRetentionEvidence:
    """The target-stack judgment and the review's one reconstructed previous state.

    ``collect`` establishes standing only. The fixed foundation read supplies both the
    reconstructed observation and the previous effective values, so a review cannot pair a
    file from one read with effective values from another.
    """
    from bootstrap import foundation
    from discovery.observations import collect

    observed = collect(shell, sites=False)
    values = foundation.read(shell)
    standing = observed.standing.standing if observed.standing else None
    if values is None:
        return JournalRetentionEvidence(standing, "", None, None, None, "", "")
    observation = reconstruct(
        values.get("journal_retention_file", ""),
        values.get("journal_system_max_use", ""),
        values.get("journal_max_retention", ""),
    )
    uptime = values.get("uptime", "")
    return JournalRetentionEvidence(
        standing=standing,
        boot_id=values.get("boot", ""),
        uptime_centiseconds=int(uptime) if _UPTIME.fullmatch(uptime) else None,
        observation=observation,
        previous=(
            render(observation.disk_cap, observation.max_age)
            if observation.state == MANAGED
            else None
        ),
        previous_disk_cap=values.get("journal_system_max_use", ""),
        previous_max_age=values.get("journal_max_retention", ""),
    )


def _refusals(evidence: JournalRetentionEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing log retention.")
    observation = evidence.observation
    if observation is None:
        refusals.append("The server's log retention configuration could not be read.")
    elif observation.state == OUTSIDE:
        refusals.append(
            "Log retention is outside supported settings. "
            f"{observation.reason} Resolve it through ordinary administration."
        )
    if (
        _BOOT.fullmatch(evidence.boot_id) is None
        or evidence.uptime_centiseconds is None
        or _JOURNAL_VALUE.fullmatch(evidence.previous_disk_cap) is None
        or _JOURNAL_VALUE.fullmatch(evidence.previous_max_age) is None
    ):
        refusals.append("The server's clock or effective retention values could not be read.")
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, JournalRetentionEvidence):
        raise ValueError("A log retention change needs native evidence.")
    refusals = _refusals(evidence)
    disk_cap, max_age = inputs.disk_cap, inputs.max_age
    candidate = render(disk_cap, max_age)
    observation = evidence.observation
    unchanged = (
        not refusals
        and observation is not None
        and observation.state == MANAGED
        and observation.disk_cap == disk_cap
        and observation.max_age == max_age
    )
    previous_label = (
        DISK_CAP_LABELS.get(evidence.previous_disk_cap, evidence.previous_disk_cap) or "Not set"
    )
    previous_age_label = (
        MAX_AGE_LABELS.get(evidence.previous_max_age, evidence.previous_max_age) or "Not set"
    )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "path": RETENTION_PATH,
        "disk_cap": disk_cap,
        "max_age": max_age,
        "disk_cap_label": DISK_CAP_LABELS[disk_cap],
        "max_age_label": MAX_AGE_LABELS[max_age],
        "retention": candidate,
        "previous": evidence.previous,
        "previous_disk_cap": evidence.previous_disk_cap,
        "previous_max_age": evidence.previous_max_age,
        "details": [
            {
                "label": "Log retention file",
                "value": f"{RETENTION_PATH} (root:root, 0644):\n{candidate}",
            },
            {
                "label": "Disk cap",
                "value": (
                    f"{previous_label} → {DISK_CAP_LABELS[disk_cap]} ({disk_cap})"
                    + (
                        " (unchanged)"
                        if unchanged
                        and observation is not None
                        and observation.disk_cap == disk_cap
                        else ""
                    )
                ),
            },
            {
                "label": "Maximum age",
                "value": (
                    f"{previous_age_label} → {MAX_AGE_LABELS[max_age]} ({max_age})"
                    + (
                        " (unchanged)"
                        if unchanged and observation is not None and observation.max_age == max_age
                        else ""
                    )
                ),
            },
            {
                "label": "Journald restart",
                "value": (
                    "Restart systemd-journald after writing the file and check that it is active."
                ),
            },
            {
                "label": "No logs deleted",
                "value": (
                    "No logs are deleted and no vacuum runs. Journald reclaims space itself "
                    "under this policy."
                ),
            },
        ],
    }
    if not refusals and len(encode_document(document)) > MAX_ARGUMENT:
        refusals.append("The reviewed log retention setting is larger than one change publishes.")
    return ReviewDraft(
        kind=SLUG,
        intent="Change this server's log retention.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SERVER,
                "Write this server's journald log retention policy, restart journald for every "
                "site, and keep every retained log.",
            ),
        ),
        stages=STAGES,
        postconditions=(
            "The log retention file holds the reviewed pair as root:root 0644.",
            "Both effective journald values equal it and the journal service is active.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={
            **document,
            "note": (
                "This server's log retention already follows the reviewed settings."
                if unchanged
                else ""
            ),
        },
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    disk_cap = document.get("disk_cap")
    max_age = document.get("max_age")
    retention = document.get("retention")
    previous = document.get("previous")
    previous_disk_cap = document.get("previous_disk_cap")
    previous_max_age = document.get("previous_max_age")
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(disk_cap, str)
        or disk_cap not in DISK_CAP_CHOICES
        or not isinstance(max_age, str)
        or max_age not in MAX_AGE_CHOICES
        or retention != render(disk_cap, max_age)
        or document.get("path") != RETENTION_PATH
        or (
            previous is not None
            and (
                not isinstance(previous, str)
                or not any(
                    previous == render(cap, age)
                    for cap in DISK_CAP_CHOICES
                    for age in MAX_AGE_CHOICES
                )
            )
        )
        or not isinstance(previous_disk_cap, str)
        or _JOURNAL_VALUE.fullmatch(previous_disk_cap) is None
        or not isinstance(previous_max_age, str)
        or _JOURNAL_VALUE.fullmatch(previous_max_age) is None
    ):
        raise ValueError("The log retention review is not a valid native selection.")
    encoded = encode_document(document)
    if len(encoded) > MAX_ARGUMENT:
        raise ValueError("The log retention review is larger than one native argument.")
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    from discovery.observations import collect

    body(stored.document, BodyContext("", "", 0))
    observation = collect(shell, sites=False).journal_retention
    if observation is None:
        return None
    return (
        observation.state == MANAGED
        and observation.disk_cap == stored.document["disk_cap"]
        and observation.max_age == stored.document["max_age"]
    )


SET_JOURNAL_RETENTION: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.JOURNAL_RETENTION,
    reasons=JOURNAL_RETENTION_REASONS,
    body_sources=("logs/bodies/journal_retention.py",),
)
