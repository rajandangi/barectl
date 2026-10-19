"""A minimal secret-writing kind, used by the confidential channel's fast tests.

The real secret-bearing kinds land later (docs/target-architecture.md#settings-and-secrets);
this one exercises the whole channel end to end: the sealed value in the run's row, the
root-only tmpfs staging, the body that consumes and removes it, the permission rechecks and
the canary that no secret reaches a command, a unit property, a journal line or a response.
"""

import hashlib
from dataclasses import dataclass
from typing import Final

from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs

SLUG: Final = "secret_probe"
LABEL: Final = "Write a confidential value"
INTENT: Final = "Write one confidential value to a private file on the server."

STAGES: Final = (
    "Take the mutation lock and admit the reviewed change",
    "Consume the confidential value and write it to a private file",
    "Remove the staged value on every exit path",
)

# Consumes the staged file named by its only argument and removes it, and the staged body,
# on every exit path. Every exit path prints one structured result line
# (docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
BODY_SOURCE: Final = (
    "# shellcheck shell=sh\n"
    "result_reported=0\n"
    "result() { result_reported=1; printf 'barectl-result %s\\n' \"$1\"; }\n"
    "staged=${1:?the confidential value is required}\n"
    "finish() {\n"
    "  status=$?\n"
    '  rm -f -- "$staged" "$0"\n'
    '  if [ "$result_reported" -eq 0 ] && [ "$status" -ne 0 ]; then\n'
    '    result \'{"class":"failed"}\'\n'
    "  fi\n"
    "}\n"
    "trap 'finish' EXIT\n"
    'trap \'result "{\\"class\\":\\"timed_out\\"}"; exit 3\' TERM\n'
    'test -f "$staged" || { result \'{"class":"refused","reason":"precondition"}\'; exit 1; }\n'
    'value=$(cat -- "$staged")\n'
    'test -n "$value" || { result \'{"class":"refused","reason":"precondition"}\'; exit 1; }\n'
    "printf '%s' \"$value\" >/dev/null\n"
    'result \'{"class":"succeeded"}\'\n'
)
BODY_BYTES: Final = BODY_SOURCE.rstrip("\n").encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()

UPTIME: Final = "cut -d' ' -f1 /proc/uptime | tr -d ."
UNREADABLE: Final = "Barectl could not read the server's boot time."


@dataclass(frozen=True)
class SecretProbeEvidence:
    boot_id: str
    uptime_centiseconds: int | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SecretProbeEvidence:
    states = shell.run(native.RETAINED_STATES)
    uptime = shell.run(UPTIME)
    try:
        boot_id, _ = native.parse_retained_states(states.stdout)
    except native.Unreadable:
        return SecretProbeEvidence("", None)
    if (
        states.exit_status != 0
        or states.truncated
        or uptime.exit_status != 0
        or uptime.truncated
        or not uptime.stdout.strip().isdigit()
    ):
        return SecretProbeEvidence(boot_id, None)
    return SecretProbeEvidence(boot_id, int(uptime.stdout.strip()))


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if (
        not isinstance(evidence, SecretProbeEvidence)
        or not evidence.boot_id
        or evidence.uptime_centiseconds is None
    ):
        return ReviewDraft(kind=SLUG, intent=INTENT, stages=STAGES, refusals=(UNREADABLE,))
    return ReviewDraft(
        kind=SLUG,
        intent=INTENT,
        effects=(DeclaredEffect(Scope.SERVER, "Write one confidential value to a private file."),),
        stages=STAGES,
        postconditions=("The staged value was consumed and removed.",),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={"version": 1, "body_sha256": BODY_SHA256},
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if not context.secret_path:
        raise ValueError("The secret probe needs a staged confidential value.")
    return NativeBody(BODY_BYTES, (context.secret_path,))


def verify(shell: RemoteShell, review: object) -> bool:
    return True


SECRET_PROBE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    writes_secrets=True,
)
