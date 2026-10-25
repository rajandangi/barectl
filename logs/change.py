"""Set up a site's root-owned logrotate file (Phase C #389, docs/logs.md#rotation).

The reviewed action exists for a site created before log rotation was part of the layout, or
for one whose file an operator edited outside the supported shape. A new site gets the file
from the create path, so it is never offered this review.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview
from sites.bodies.logrotate import (
    LOGROTATE_KNOWN_FILES,
    LOGROTATE_PHP_FILES,
    logrotate_render,
)

SLUG: Final = "set_up_log_rotation"
BODY_SOURCE: Final = importlib.resources.files("logs.bodies").joinpath("rotation.py").read_text()
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

STAGES: Final = ("preflight", "publish", "verify")
ROTATION_SOURCE: Final = (
    importlib.resources.files("sites.bodies").joinpath("logrotate.py").read_text()
    + "\nimport json,pwd,pathlib,sys\n"
    "identifier = sys.argv[1]\n"
    "state, problem, names = logrotate_state(identifier)\n"
    "site = pathlib.Path('/etc/caddy/sites/' + identifier + '.caddy')\n"
    "present = site.is_file() and not site.is_symlink() and site.stat().st_uid == 0\n"
    "try:\n"
    "    pwd.getpwnam('s' + identifier)\n"
    "except KeyError:\n"
    "    present = False\n"
    "print(json.dumps({'state': state, 'problem': problem, 'files': list(names), "
    "'present': list(logrotate_present(identifier)), 'site': present, "
    "'boot': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), "
    "'uptime': int(float(pathlib.Path('/proc/uptime').read_text().split()[0]) * 100)}))\n"
)


@dataclass(frozen=True)
class RotationState:
    state: str
    problem: str
    files: tuple[str, ...]
    present: tuple[str, ...]


@dataclass(frozen=True)
class RotationEvidence:
    site: bool
    boot_id: str
    uptime_centiseconds: int
    rotation: RotationState | None


def rotation_command(identifier: str) -> str:
    packed = base64.b64encode(gzip.compress(ROTATION_SOURCE.encode(), mtime=0)).decode()
    code = "import base64,gzip; exec(gzip.decompress(base64.b64decode(" + repr(packed) + ")))"
    inner = shlex.join(["python3", "-c", code, identifier])
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + inner]))


def read_site(shell: RemoteShell, identifier: str) -> RotationEvidence:
    """The site's existence, its boot identity and its rotation file, in one fixed read."""
    result = run_root(shell, rotation_command(identifier))
    if result.exit_status or result.truncated:
        return RotationEvidence(False, "", 0, None)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        return RotationEvidence(False, "", 0, None)
    if not isinstance(value, dict) or type(value.get("site")) is not bool:
        return RotationEvidence(False, "", 0, None)
    rotation = _rotation_from(value)
    return RotationEvidence(
        bool(value["site"]),
        str(value.get("boot", ""))[:36],
        int(value.get("uptime", 0)) if isinstance(value.get("uptime"), int) else 0,
        rotation,
    )


def _rotation_from(value: dict[str, object]) -> RotationState | None:
    problem = value.get("problem")
    files = value.get("files")
    present = value.get("present")
    if (
        value.get("state") not in ("supported", "partial", "outside", "missing", "unavailable")
        or not isinstance(problem, str)
        or len(problem) > 500
        or not isinstance(files, list)
        or not isinstance(present, list)
        or any(name not in LOGROTATE_KNOWN_FILES for name in [*files, *present])
    ):
        return None
    return RotationState(
        str(value["state"]),
        problem,
        tuple(str(name) for name in files),
        tuple(str(name) for name in present),
    )


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RotationEvidence:
    """Read the site and its rotation file; the change needs no host-standing gate.

    It publishes one root-owned file and proves logrotate accepts it, so it does not change
    a site's code, schema, runtime or serving configuration.
    """
    return read_site(shell, inputs.identifier)


def reviewed_files(rotation: RotationState) -> tuple[str, ...]:
    """Every log to rotate: the PHP pair plus the WordPress debug log when it exists."""
    found = set(rotation.present)
    return tuple(
        name
        for name in (*LOGROTATE_PHP_FILES, "wp-debug.log")
        if name in LOGROTATE_PHP_FILES or name in found
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RotationEvidence):
        raise ValueError("A log rotation review needs native evidence.")
    refusals: list[str] = []
    if not evidence.site:
        refusals.append("The site was not observed in the current server configuration.")
    rotation = evidence.rotation
    if rotation is None:
        refusals.append("The site's log rotation file could not be read.")
    elif rotation.state == "unavailable":
        refusals.append(
            "This server does not run logrotate. Install and enable it with ordinary "
            "administration, then check the server again."
        )
    reportable = evidence.site and not refusals
    names = reviewed_files(rotation) if rotation is not None else LOGROTATE_PHP_FILES
    unchanged = reportable and rotation is not None and rotation.state == "supported"
    document: dict[str, object] = {
        "version": 1,
        "identifier": inputs.identifier,
        "files": list(names),
        "rotation": logrotate_render(inputs.identifier, names),
        "body_sha256": BODY_SHA256,
        "precondition_digest": _digest(evidence.boot_id),
        "details": [
            {"label": "Site", "value": inputs.identifier},
            {"label": "Files", "value": ", ".join(names)},
            {
                "label": "Rotation",
                "value": "Daily or at 20 MiB, keeping 5 compressed files for 14 days.",
            },
            {
                "label": "Apply",
                "value": "Publish this site's own root-owned rotation file after testing it.",
            },
        ],
    }
    if unchanged:
        document["note"] = "This site's log rotation already follows the supported settings."
    return ReviewDraft(
        SLUG,
        f"Set up log rotation for {inputs.identifier}.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                "Publish this site's own log rotation file.",
                (inputs.identifier,),
            ),
        ),
        sites_read=(
            "find /etc/caddy/sites -maxdepth 1 -type f -name "
            + shlex.quote(inputs.identifier + ".caddy")
            + " -printf '%f\\n' | sed 's/\\.caddy$//'"
        )
        if reportable
        else "",
        current_sites=(inputs.identifier,) if reportable else None,
        stages=STAGES,
        refusals=tuple(refusals),
        document=document,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
    )


def _digest(boot_id: str) -> str:
    return hashlib.sha256(boot_id.encode()).hexdigest()


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = decode_inputs(
        {key: document.get(key) for key in ("version", "identifier")},
        (),
        InputShape.SITE_LOG_ROTATION,
    )
    files = document.get("files")
    rotation = document.get("rotation")
    digest = document.get("precondition_digest")
    if (
        document.get("body_sha256") != BODY_SHA256
        or not isinstance(files, list)
        or not all(isinstance(name, str) for name in files)
        or not isinstance(rotation, str)
        or rotation != logrotate_render(inputs.identifier, tuple(files))
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("The log rotation review is not a valid immutable native selection.")
    return NativeBody(BODY_BYTES, (json.dumps(document),))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    evidence = read_site(shell, str(stored.document["identifier"]))
    if not evidence.site or evidence.rotation is None:
        return None
    return evidence.rotation.state == "supported"


SET_UP_LOG_ROTATION: Final = ChangeKind(
    SLUG,
    "Set up log rotation",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_LOG_ROTATION,
)
