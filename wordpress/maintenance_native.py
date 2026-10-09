"""The WordPress maintenance action's native body and result record grammar.

docs/wordpress.md#maintaining-wordpress describes the actions; docs/wordpress-native-design.md
owns the upstream rules. The body is a pure function of the reviewed rows and evidence, so its
SHA-256 is part of the review. It reuses the inspection's passive state read and the shared
application-execution boundary (``execution``): it revalidates under the lock, runs one fixed
WP-CLI command as the site user, captures its output in private files and publishes one
validated record.
"""

from dataclasses import dataclass
from typing import Final

from . import execution, inspection_native
from .execution import Step
from .inspection_native import Evidence, InvalidRecord, target_of
from .maintenance_models import MaintenanceReview, Operation

COMMAND_SECONDS: Final = inspection_native.COMMAND_SECONDS
MAX_FILE_BYTES: Final = inspection_native.MAX_FILE_BYTES
MEMORY_MAX_BYTES: Final = inspection_native.MEMORY_MAX_BYTES
RUNTIME_LIMIT_SECONDS: Final = inspection_native.RUNTIME_LIMIT_SECONDS
# The review shares the inspection's binding row, so it records the same budget.
BUDGET_SECONDS: Final = inspection_native.BUDGET_SECONDS
WHY: Final = frozenset({"overflow", "output", "timeout", "failed", "skipped"})
FAILED_WHY: Final = frozenset({"error", "timeout", "overflow"})
RULES: Final = frozenset({"stored", "empty"})

# The command each action runs, as the site user.
COMMANDS: Final = {Operation.REWRITE: "rewrite flush", Operation.CACHE: "cache flush"}
# Whether ordinary plugins and themes load for the command, so their registered hooks run.
LOADS_EXTENSIONS: Final = {Operation.REWRITE: True, Operation.CACHE: False}


class Exit:
    """The maintenance body's own status, beside the shared ones."""

    COMMAND = 64


def limits() -> tuple[int, int]:
    return inspection_native.limits()


def body_steps(row: MaintenanceReview, evidence: Evidence) -> list[Step]:
    """The named fragments of the run's native body, in order."""
    evidence.checked()
    target = target_of(row)
    target.verified()
    if row.operation not in set(Operation):
        raise ValueError("Not a maintenance action.")
    operation = Operation(row.operation)
    return [
        Step(
            "helpers",
            execution.helpers(
                target,
                command_seconds=COMMAND_SECONDS,
                load_extensions=LOADS_EXTENSIONS[operation],
            ),
        ),
        Step("tools", execution.tools(target)),
        Step(
            "revalidation",
            execution.revalidation(
                site=evidence.site,
                wpcli=evidence.wpcli,
                state_script=inspection_native.state_script(row.identifier),
                state=evidence.state,
                target=target,
            ),
        ),
        Step("stage", execution.stage()),
        Step("run", f"W flush {COMMANDS[operation]}"),
        Step("project", execution.emit(PROJECTION, row.operation)),
        # A command that did not complete publishes its record, then ends the unit as failed.
        Step("finish", f'case "$r" in *\'"done":false\'*) exit {Exit.COMMAND};; esac; exit 0'),
    ]


def body(row: MaintenanceReview, evidence: Evidence) -> str:
    return "; ".join(step.text for step in body_steps(row, evidence))


def staged(
    unit: str, boot_id: str, deadline: int, row: MaintenanceReview, evidence: Evidence
) -> tuple[str, str]:
    """The submitted script and the body it carries."""
    text = body(row, evidence)
    return execution.payload(unit, boot_id, deadline, text), text


# Run as the site user over the files the command left: it accepts only the exact output forms
# of the fixed command and prints one record. A command that did not succeed is recorded as
# failed; any other output makes the result unavailable. Nothing a command printed is copied.
PROJECTION: Final = (
    execution.PROJECTION_PRELUDE
    + r"""
REWRITE_OK = "Success: Rewrite rules flushed.\n"
REWRITE_EMPTY = (
    "Warning: Rewrite rules are empty, possibly because of a missing permalink_structure "
    "option. Use 'wp rewrite list' to verify, or 'wp rewrite structure' to update "
    "permalink_structure.\n"
)
CACHE_OK = "Success: The cache was flushed.\n"


def status_of():
    try:
        return int(read(directory + "/flush.rc").decode("ascii").strip())
    except (OSError, ValueError):
        return None


def flush():
    # A command stopped by its time or file-size limit did not complete, whatever it printed.
    stopped = {124: "timeout", 137: "timeout", 153: "overflow"}.get(status_of())
    if stopped:
        return {"state": "failed", "done": False, "why": stopped}
    status, out, err = run("flush")
    if status != 0:
        return {"state": "failed", "done": False, "why": "error"}
    if operation == "rewrite":
        if out == REWRITE_OK and not err:
            return {"state": "ok", "done": True, "rules": "stored"}
        if not out and err == REWRITE_EMPTY:
            return {"state": "ok", "done": True, "rules": "empty"}
    elif operation == "cache" and out == CACHE_OK and not err:
        return {"state": "ok", "done": True}
    raise Unavailable("output")


try:
    body = flush()
except Unavailable as unavailable:
    body = {"state": "unavailable", "why": str(unavailable)}
body.update(v=1, op=operation, at=int(time.time()))
line = MARKER + " " + json.dumps(body, separators=(",", ":"), sort_keys=True)
if len(line) > LIMIT:
    body = {"state": "unavailable", "why": "overflow", "v": 1, "op": operation, "at": body["at"]}
    line = MARKER + " " + json.dumps(body, separators=(",", ":"), sort_keys=True)
print(line)
"""
)


@dataclass(frozen=True)
class Record:
    operation: str
    # "ok" (the command completed in its exact form), "failed" (it did not complete) or
    # "unavailable" (its output was not in a form Barectl accepts).
    state: str
    why: str
    at: int
    rules: str = ""


def parse_record(line: str, operation: str) -> Record:
    """The record the unit published, or ``InvalidRecord`` for anything that is not exactly the
    grammar: wrong keys, types, values or duplicates."""
    if operation not in set(Operation):
        raise InvalidRecord
    data, at = inspection_native.envelope(line, operation)
    state = data.get("state")
    if state == "unavailable":
        fields = inspection_native.mapping(data, {"v", "op", "at", "state", "why"})
        return Record(operation, "unavailable", inspection_native.fixed(fields["why"], WHY), at)
    if state == "failed":
        keys = {"v", "op", "at", "state", "done", "why"}
        fields = inspection_native.mapping(data, keys)
        if fields["done"] is not False:
            raise InvalidRecord
        return Record(operation, "failed", inspection_native.fixed(fields["why"], FAILED_WHY), at)
    if state != "ok":
        raise InvalidRecord
    rewrite = operation == Operation.REWRITE
    fields = inspection_native.mapping(
        data, {"v", "op", "at", "state", "done"} | ({"rules"} if rewrite else set())
    )
    if fields["done"] is not True:
        raise InvalidRecord
    rules = inspection_native.fixed(fields["rules"], RULES) if rewrite else ""
    return Record(operation, "ok", "", at, rules)
