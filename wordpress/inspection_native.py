"""The WordPress inspection's passive state read, native body and result record grammar.

docs/wordpress.md#inspecting-wordpress describes the operation; docs/wordpress-native-design.md
owns the upstream rules. The body is a pure function of the reviewed rows and evidence, so its
SHA-256 is part of the review. It runs the fixed WP-CLI commands as the site user through
``execution``, captures their output in private files and publishes one validated record.
"""

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Final

from sites import native as site_native

from . import convention, execution
from .execution import Step, Target
from .inspection_models import InspectionReview, Operation

COMMAND_SECONDS: Final = 120
# The longest the per-plugin checks may run in total; the unit's own runtime limit is 30 minutes.
BUDGET_SECONDS: Final = 600
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
MEMORY_MAX_BYTES: Final = 512 * 1024 * 1024
RUNTIME_LIMIT_SECONDS: Final = 30 * 60
SLUG: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}")
_NAME: Final = re.compile(r"[A-Za-z0-9._@+~-]{1,100}")
_VERSION: Final = re.compile(r"[0-9A-Za-z.+_~-]{0,40}")
_RELEASE: Final = re.compile(r"[0-9A-Za-z.-]{1,40}")
_PATH: Final = re.compile(r"[A-Za-z0-9._@+~/ -]{1,200}")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
# The WordPress drop-ins (https://developer.wordpress.org/reference/functions/get_dropins/):
# files of wp-content that WordPress loads itself.
DROPINS: Final = (
    "advanced-cache.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
    "db-error.php",
    "db.php",
    "fatal-error-handler.php",
    "install.php",
    "maintenance.php",
    "object-cache.php",
    "php-error.php",
    "sunrise.php",
)
MAX_LISTED: Final = 300
WHY: Final = frozenset(
    {"overflow", "output", "timeout", "failed", "catalog", "skipped", "not_installed"}
)
KINDS: Final = ("plugin", "mu-plugin", "dropin", "theme")
_PLUGIN_STATUSES: Final = frozenset({"active", "inactive", "active-network", "must-use", "dropin"})
_THEME_STATUSES: Final = frozenset({"active", "inactive", "parent"})
_CHECKS: Final = frozenset({"match", "mismatch", "unavailable"})

# The command each operation runs, as the site user (docs/wordpress.md#inspecting-wordpress).
COMMANDS: Final = {
    Operation.INSPECT: (
        "core is-installed",
        "core version",
        "plugin list --fields=name,status,version --format=json",
        "theme list --fields=name,status,version --format=json",
    ),
    Operation.CORE: ("core verify-checksums --version=<observed> --locale=en_US",),
    Operation.PLUGINS: ("plugin verify-checksums <slug> --format=json, once per observed slug",),
}
# Whether the commands load WordPress, and so run the must-use plugins and drop-ins.
RUNS_APPLICATION: Final = {Operation.INSPECT: True, Operation.CORE: False, Operation.PLUGINS: True}


def limits() -> tuple[int, int]:
    return MAX_FILE_BYTES, MEMORY_MAX_BYTES


def state_script(identifier: str, php_version: str = "") -> str:
    """Everything the review and the run's revalidation bind about the application, read as
    root without starting WordPress: the loader, private configuration and version through
    the fixed server-side parser, the schema signature and canonical options, and the names
    of the plugins, must-use plugins, themes and drop-ins with the digests of the files WordPress
    loads by itself. Nothing is a secret and nothing is a row of content."""
    if not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    public = convention.public_root(identifier)
    content = f"{public}/wp-content"
    database = f"s{identifier}"
    hashed = "| cut -d' ' -f1"
    dropins = " ".join(DROPINS)
    return "; ".join(
        (
            "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
            f"{convention.inspection_command(identifier)} | sed 's/^/config /'",
            f"echo \"package $(grep -c '^\\$wp_local_package' {public}/wp-includes/version.php)\"",
            f"{convention.schema_command([database])} | LC_ALL=C sort | sed 's/^/schema /'",
            f"{convention.options_command(database)} | sed 's/^/option /'",
            (
                f"for d in plugins mu-plugins themes; do find {content}/$d -mindepth 1 "
                "-maxdepth 1 -printf 'entry '\"$d\"' %y %u %f\\n' 2>/dev/null | sort "
                f'| head -n {MAX_LISTED + 1}; echo "end $d"; done'
            ),
            (
                f"for f in {dropins}; do p={content}/$f; "
                'if [ -e "$p" ] || [ -L "$p" ]; then if [ -f "$p" ] && [ ! -L "$p" ]; then '
                f'echo "dropin $f $(sha256sum <"$p" {hashed})"; else echo "dropin $f other"; '
                "fi; fi; done"
            ),
            (
                f'for p in {content}/mu-plugins/*.php; do if [ -f "$p" ] && [ ! -L "$p" ]; '
                f'then echo "mufile $(basename "$p") $(sha256sum <"$p" {hashed})"; fi; done'
            ),
            "true",
        )
    )


def state_argv(identifier: str) -> list[str]:
    return site_native.script(state_script(identifier))


@dataclass
class State:
    config: convention.FileInspection | None = None
    packaged: int = -1
    schema: str = ""
    options: str = ""
    # (directory, type, owner, name) of every listed entry.
    entries: list[tuple[str, str, str, str]] = field(default_factory=list)
    ended: set[str] = field(default_factory=set)
    dropins: dict[str, str] = field(default_factory=dict)
    mufiles: dict[str, str] = field(default_factory=dict)


class Unreadable(Exception):
    pass


_ENTRY = re.compile(
    r"entry (plugins|mu-plugins|themes) ([a-zA-Z]) ([a-z_][a-z0-9_-]{0,31}) (.{1,255})"
)
_UNEXPECTED = "The application state read is not in its expected form."


def _file_digest(rest: str) -> tuple[str, str]:
    name, _, value = rest.partition(" ")
    if not _NAME.fullmatch(name) or not (_DIGEST.fullmatch(value) or value == "other"):
        raise Unreadable(_UNEXPECTED)
    return name, value


def parse_state(text: str) -> State:
    """The state read's lines; any other line is an unreadable answer."""
    state = State()
    config: list[str] = []
    schema: list[str] = []
    options: list[str] = []
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "config":
            config.append(rest)
        elif kind == "package" and rest.isdigit() and state.packaged < 0:
            state.packaged = int(rest)
        elif kind == "schema":
            schema.append(rest)
        elif kind == "option":
            options.append(rest)
        elif kind == "end" and rest in {"plugins", "mu-plugins", "themes"}:
            state.ended.add(rest)
        elif match := _ENTRY.fullmatch(line):
            state.entries.append((match[1], match[2], match[3], match[4]))
        elif kind in {"dropin", "mufile"}:
            name, value = _file_digest(rest)
            (state.dropins if kind == "dropin" else state.mufiles)[name] = value
        else:
            raise Unreadable(_UNEXPECTED)
    state.config = convention.parse_inspection("\n".join(config))
    if (
        state.config is None
        or state.packaged < 0
        or state.ended != {"plugins", "mu-plugins", "themes"}
    ):
        raise Unreadable(_UNEXPECTED)
    state.schema = "\n".join(schema)
    state.options = "\n".join(options)
    return state


@dataclass(frozen=True)
class Inventory:
    """The names the review shows and the run may execute or check."""

    plugins: list[str]
    slugs: list[str]
    mu_plugins: list[str]
    dropins: list[str]
    themes: list[str]

    @property
    def count(self) -> int:
        return len(self.plugins) + len(self.mu_plugins) + len(self.dropins) + len(self.themes)

    def targets(self) -> str:
        """The review's ``targets`` text: one ``kind name`` per line."""
        lines = [f"plugin {name}" for name in self.slugs]
        lines += [f"mu-plugin {name}" for name in self.mu_plugins]
        lines += [f"dropin {name}" for name in self.dropins]
        lines += [f"theme {name}" for name in self.themes]
        return "\n".join(lines)


def inventory(state: State) -> Inventory:
    """The observed extensions: every plugin ``plugin list`` would report (directories and
    single-file plugins), the repository-slug directories among them, the must-use files and
    the drop-ins that exist."""
    plugins = [
        name
        for directory, kind, _, name in state.entries
        if directory == "plugins"
        and (kind == "d" or (kind == "f" and name.endswith(".php")))
        and name != "index.php"
    ]
    slugs = [
        name
        for directory, kind, _, name in state.entries
        if directory == "plugins" and kind == "d" and SLUG.fullmatch(name)
    ]
    return Inventory(
        plugins,
        slugs,
        sorted(state.mufiles),
        sorted(state.dropins),
        [
            name
            for directory, kind, _, name in state.entries
            if directory == "themes" and kind == "d"
        ],
    )


@dataclass(frozen=True)
class Evidence:
    """The digests the plan recorded and the run rechecks under the mutation lock."""

    site: str
    wpcli: str
    state: str

    def checked(self) -> None:
        for value in (self.site, self.wpcli, self.state):
            execution.digest_ok(value)


def target_of(row: InspectionReview) -> Target:
    return Target(
        row.identifier,
        row.php_version,
        row.site_revision,
        row.site_user,
        row.canonical_name,
        row.url,
        row.tool_path,
    )


def _run(row: InspectionReview) -> str:
    operation = row.operation
    if operation == Operation.INSPECT:
        return "; ".join(
            (
                "W installed core is-installed",
                "W version core version",
                "W plugins plugin list --fields=name,status,version --format=json",
                "W themes theme list --fields=name,status,version --format=json",
            )
        )
    if operation == Operation.CORE:
        if not _RELEASE.fullmatch(row.core_version) or row.core_locale != "en_US":
            raise ValueError("Not an observed core release.")
        return (
            f"W core core verify-checksums --version={shlex.quote(row.core_version)} "
            f"--locale={row.core_locale}"
        )
    slugs = row.names("plugin")
    if not slugs or len(slugs) > execution.MAX_ITEMS or not all(SLUG.fullmatch(s) for s in slugs):
        raise ValueError("Not observed repository plugin slugs.")
    return "; ".join(
        (
            "t0=$(cut -d. -f1 /proc/uptime)",
            (
                f"for p in {' '.join(shlex.quote(slug) for slug in slugs)}; do "
                "now=$(cut -d. -f1 /proc/uptime); "
                f'[ "$((now - t0))" -lt {BUDGET_SECONDS} ] || break; '
                'W "pv.$p" plugin verify-checksums "$p" --format=json; done'
            ),
        )
    )


def _arguments(row: InspectionReview) -> list[str]:
    if row.operation == Operation.CORE:
        return [row.core_version]
    if row.operation == Operation.PLUGINS:
        return row.names("plugin")
    return []


def body_steps(row: InspectionReview, evidence: Evidence) -> list[Step]:
    """The named fragments of the run's native body, in order."""
    evidence.checked()
    target = target_of(row)
    target.verified()
    if row.operation not in set(Operation):
        raise ValueError("Not an operation.")
    return [
        Step("helpers", execution.helpers(target, command_seconds=COMMAND_SECONDS)),
        Step("tools", execution.tools(target)),
        Step(
            "revalidation",
            execution.revalidation(
                site=evidence.site,
                wpcli=evidence.wpcli,
                state_script=state_script(row.identifier),
                state=evidence.state,
                target=target,
            ),
        ),
        Step("stage", execution.stage()),
        Step("run", _run(row)),
        Step("project", execution.emit(PROJECTION, row.operation, *_arguments(row))),
        Step("finish", "exit 0"),
    ]


def body(row: InspectionReview, evidence: Evidence) -> str:
    return "; ".join(step.text for step in body_steps(row, evidence))


def staged(
    unit: str, boot_id: str, deadline: int, row: InspectionReview, evidence: Evidence
) -> tuple[str, str]:
    """The submitted script and the body it carries."""
    text = body(row, evidence)
    return execution.payload(unit, boot_id, deadline, text), text


# Run as the site user over the files the commands left: it accepts only the exact output
# forms of the fixed commands, caps items and bytes, and prints one record. Any other output
# makes the result unavailable; nothing a command printed is copied through unvalidated.
PROJECTION: Final = (
    execution.PROJECTION_PRELUDE
    + r"""
ITEMS = 128
NAME = re.compile(r"[A-Za-z0-9._@+~-]{1,100}")
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}")
VERSION = re.compile(r"[0-9A-Za-z.+_~-]{0,40}")
RELEASE = re.compile(r"[0-9A-Za-z.-]{1,40}")
PATH = re.compile(r"[A-Za-z0-9._@+~/ -]{1,200}")


def pairs(items):
    keys = [key for key, _ in items]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(items)


def listing(name, statuses):
    status, out, err = run(name)
    if status != 0:
        raise Unavailable("failed")
    if err:
        raise Unavailable("output")
    try:
        data = json.loads(out, object_pairs_hook=pairs)
    except ValueError:
        raise Unavailable("output")
    if not isinstance(data, list):
        raise Unavailable("output")
    found = []
    for entry in data:
        if not isinstance(entry, dict) or set(entry) != {"name", "status", "version"}:
            raise Unavailable("output")
        values = (entry["name"], entry["status"], entry["version"])
        if not all(isinstance(value, str) for value in values):
            raise Unavailable("output")
        if (
            not NAME.fullmatch(values[0])
            or values[1] not in statuses
            or not VERSION.fullmatch(values[2])
        ):
            raise Unavailable("output")
        found.append(values)
    return found


def inventory():
    status, out, err = run("installed")
    if out or err or status not in (0, 1):
        raise Unavailable("output" if out or err else "failed")
    status_version, out, err = run("version")
    if status_version != 0 or err or not RELEASE.fullmatch(out.rstrip("\n")):
        raise Unavailable("output" if out or err else "failed")
    version = out.rstrip("\n")
    if status == 1:
        return {"core": {"installed": False, "version": version}, "items": []}
    items = []
    kinds = {"must-use": "mu-plugin", "dropin": "dropin"}
    for name, state, number in listing(
        "plugins", ("active", "inactive", "active-network", "must-use", "dropin")
    ):
        items.append({"k": kinds.get(state, "plugin"), "n": name, "s": state, "v": number})
    for name, state, number in listing("themes", ("active", "inactive", "parent")):
        items.append({"k": "theme", "n": name, "s": state, "v": number})
    if len(items) > ITEMS:
        raise Unavailable("overflow")
    return {"core": {"installed": True, "version": version}, "items": items}


def core():
    version = arguments[0]
    if not RELEASE.fullmatch(version):
        raise Unavailable("output")
    verdict = {"state": "unavailable", "why": "output", "modified": 0, "missing": 0, "extra": 0}
    files = []
    try:
        status, out, err = run("core")
    except Unavailable as unavailable:
        verdict["why"] = str(unavailable)
        return {"core": {"version": version}, "integrity": verdict, "files": files}
    success = "Success: WordPress installation verifies against checksums.\n"
    failure = "Error: WordPress installation doesn't verify against checksums."
    patterns = (
        ("modified", "Warning: File doesn't verify against checksum: "),
        ("missing", "Warning: File doesn't exist: "),
        ("extra", "Warning: File should not exist: "),
    )
    counts = {"modified": 0, "missing": 0, "extra": 0}
    other = False
    failed = False
    errors = []
    lines = err.splitlines()
    for line in lines:
        if line == failure:
            failed = True
            continue
        for kind, prefix in patterns:
            if line.startswith(prefix) and PATH.fullmatch(line[len(prefix):]):
                counts[kind] += 1
                if len(files) < 20:
                    files.append({"k": kind, "p": line[len(prefix):]})
                break
        else:
            if line.startswith("Error: ") and line.isascii() and line.isprintable():
                errors.append(line)
            else:
                other = True
    drift = counts["modified"] + counts["missing"]
    if other or len(errors) > 1:
        pass
    elif not errors and status == 0 and out == success and not lines:
        verdict = {"state": "match", "why": "", **counts}
    elif not errors and status == 1 and not out and failed and drift:
        verdict = {"state": "mismatch", "why": "", **counts}
    elif not errors and status == 0 and out == success and counts["extra"] and not drift:
        verdict = {"state": "mismatch", "why": "", **counts}
    elif errors and status == 1 and not out and len(lines) == 1:
        verdict["why"] = "catalog"
    if verdict["state"] != "unavailable":
        verdict["why"] = ""
    return {"core": {"version": version}, "integrity": verdict, "files": files}


def plugin(slug):
    item = {"k": "plugin", "n": slug, "c": "unavailable", "w": "output", "m": 0, "a": 0}
    try:
        status, out, err = run("pv." + slug)
    except Unavailable as unavailable:
        item["w"] = str(unavailable)
        return item
    if status == 0 and out == "Success: Verified 1 of 1 plugins.\n" and not err:
        return {**item, "c": "match", "w": ""}
    skipped = out == "Success: Verified 0 of 1 plugins (1 skipped).\n"
    lines = err.splitlines()
    if (
        status == 0
        and skipped
        and 0 < len(lines) <= 4
        and all(
            line.startswith("Warning: ") and line.isascii() and line.isprintable()
            for line in lines
        )
        and sum(
            line.startswith("Warning: Could not retrieve the checksums for version ")
            for line in lines
        )
        == 1
    ):
        return {**item, "w": "catalog"}
    if status == 1 and err == "Error: No plugins verified (1 failed).\n":
        try:
            rows = json.loads(out, object_pairs_hook=pairs)
        except ValueError:
            return item
        modified = added = 0
        if not isinstance(rows, list) or not rows:
            return item
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"plugin_name", "file", "message"}
                or row["plugin_name"] != slug
                or not isinstance(row["file"], str)
                or not PATH.fullmatch(row["file"])
            ):
                return item
            if row["message"] == "Checksum does not match":
                modified += 1
            elif row["message"] == "File was added":
                added += 1
            else:
                return item
        return {**item, "c": "mismatch", "w": "", "m": modified, "a": added}
    return item


def plugins():
    if not arguments or len(arguments) > ITEMS or not all(SLUG.fullmatch(a) for a in arguments):
        raise Unavailable("output")
    return {"items": [plugin(slug) for slug in arguments]}


try:
    body = {"inspect": inventory, "core": core, "plugins": plugins}[operation]()
    body["state"] = "ok"
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


class InvalidRecord(Exception):
    pass


@dataclass(frozen=True)
class Item:
    kind: str
    name: str
    status: str = ""
    version: str = ""
    verdict: str = ""
    why: str = ""
    modified: int = 0
    added: int = 0


@dataclass(frozen=True)
class Record:
    operation: str
    state: str
    why: str
    at: int
    core_version: str = ""
    core_installed: bool | None = None
    integrity: str = ""
    integrity_why: str = ""
    modified: int = 0
    missing: int = 0
    extra: int = 0
    files: tuple[tuple[str, str], ...] = ()
    items: tuple[Item, ...] = ()


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in items]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(items)


def _text(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise InvalidRecord
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000:
        raise InvalidRecord
    return value


def mapping(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InvalidRecord
    return {str(key): item for key, item in value.items()}


def fixed(value: object, allowed: frozenset[str]) -> str:
    """A non-empty member of a fixed vocabulary."""
    if not isinstance(value, str) or value not in allowed:
        raise InvalidRecord
    return value


def _why(value: object) -> str:
    if not isinstance(value, str) or (value and value not in WHY):
        raise InvalidRecord
    return value


def envelope(line: str, operation: str) -> tuple[dict[str, object], int]:
    """The canonical JSON object of ``line`` for ``operation`` and its time."""
    if len(line) > execution.MAX_RECORD or not line.isascii() or not line.isprintable():
        raise InvalidRecord
    try:
        data = json.loads(line, object_pairs_hook=_pairs)
    except ValueError:
        raise InvalidRecord from None
    if not isinstance(data, dict) or data.get("v") != 1 or data.get("op") != operation:
        raise InvalidRecord
    if json.dumps(data, separators=(",", ":"), sort_keys=True) != line:
        raise InvalidRecord
    at = data.get("at")
    if type(at) is not int or not 1_500_000_000 <= at <= 4_100_000_000:
        raise InvalidRecord
    return data, at


def parse_record(line: str, operation: str) -> Record:
    """The record the unit published, or ``InvalidRecord`` for anything that is not exactly the
    grammar: wrong keys, types, values, duplicates, sizes or counts."""
    data, at = envelope(line, operation)
    if data.get("state") == "unavailable":
        why = _why(mapping(data, {"v", "op", "at", "state", "why"})["why"])
        if not why:
            raise InvalidRecord
        return Record(operation, "unavailable", why, at)
    parsers = {Operation.INSPECT: _inventory, Operation.CORE: _core, Operation.PLUGINS: _plugins}
    if data.get("state") != "ok" or operation not in parsers:
        raise InvalidRecord
    return parsers[Operation(operation)](data, at)


def _inventory(data: dict[str, object], at: int) -> Record:
    body = mapping(data, {"v", "op", "at", "state", "core", "items"})
    core = mapping(body["core"], {"installed", "version"})
    installed = core["installed"]
    if type(installed) is not bool:
        raise InvalidRecord
    items = body["items"]
    if not isinstance(items, list) or len(items) > execution.MAX_ITEMS or (items and not installed):
        raise InvalidRecord
    found: list[Item] = []
    for entry in items:
        fields = mapping(entry, {"k", "n", "s", "v"})
        kind = fields["k"]
        status = _text(fields["s"], re.compile(r"[a-z-]{1,20}"))
        allowed = _THEME_STATUSES if kind == "theme" else _PLUGIN_STATUSES
        if kind not in KINDS or status not in allowed:
            raise InvalidRecord
        found.append(
            Item(
                str(kind),
                _text(fields["n"], _NAME),
                status,
                _text(fields["v"], _VERSION),
            )
        )
    return Record(
        Operation.INSPECT,
        "ok",
        "",
        at,
        core_version=_text(core["version"], _RELEASE),
        core_installed=installed,
        items=tuple(found),
    )


def _core(data: dict[str, object], at: int) -> Record:
    body = mapping(data, {"v", "op", "at", "state", "core", "integrity", "files"})
    core = mapping(body["core"], {"version"})
    verdict = mapping(body["integrity"], {"state", "why", "modified", "missing", "extra"})
    state = verdict["state"]
    why = _why(verdict["why"])
    counts = (_count(verdict["modified"]), _count(verdict["missing"]), _count(verdict["extra"]))
    if state not in _CHECKS or (state == "unavailable") != bool(why):
        raise InvalidRecord
    if state != "mismatch" and any(counts):
        raise InvalidRecord
    listed = body["files"]
    if not isinstance(listed, list) or len(listed) > 20 or (listed and state != "mismatch"):
        raise InvalidRecord
    files: list[tuple[str, str]] = []
    for entry in listed:
        fields = mapping(entry, {"k", "p"})
        if fields["k"] not in {"modified", "missing", "extra"}:
            raise InvalidRecord
        files.append((str(fields["k"]), _text(fields["p"], _PATH)))
    if state == "mismatch" and not any(counts):
        raise InvalidRecord
    return Record(
        Operation.CORE,
        "ok",
        "",
        at,
        core_version=_text(core["version"], _RELEASE),
        integrity=str(state),
        integrity_why=why,
        modified=counts[0],
        missing=counts[1],
        extra=counts[2],
        files=tuple(files),
    )


def _plugins(data: dict[str, object], at: int) -> Record:
    body = mapping(data, {"v", "op", "at", "state", "items"})
    items = body["items"]
    if not isinstance(items, list) or not 0 < len(items) <= execution.MAX_ITEMS:
        raise InvalidRecord
    found: list[Item] = []
    for entry in items:
        fields = mapping(entry, {"k", "n", "c", "w", "m", "a"})
        verdict, why = fields["c"], _why(fields["w"])
        if (
            fields["k"] != "plugin"
            or verdict not in _CHECKS
            or (verdict == "unavailable") != bool(why)
        ):
            raise InvalidRecord
        modified, added = _count(fields["m"]), _count(fields["a"])
        if verdict != "mismatch" and (modified or added):
            raise InvalidRecord
        found.append(
            Item(
                "plugin",
                _text(fields["n"], re.compile(SLUG.pattern)),
                verdict=str(verdict),
                why=why,
                modified=modified,
                added=added,
            )
        )
    return Record(Operation.PLUGINS, "ok", "", at, items=tuple(found))
