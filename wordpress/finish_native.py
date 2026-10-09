"""The WordPress Finish's fixed reads, the release comparison and the reviewed native body.

docs/wordpress.md#finishing-a-partial-installation describes the workflow and
docs/wordpress-native-design.md#installation-admission-and-execution owns the rule. A Finish
review stands on the same workflows as an installation review; this module adds only what a
partly installed site needs: reads of every existing resource, a comparison of the published
release files with a copy of the pinned archive, and a body that creates only the verified
missing resources and then publishes the ready routing. Every fragment the two workflows
share is the installation's own (``install_native``), so a boundary behaves identically in
both. Nothing here starts WordPress before the staged archive and the existing files have
been verified, and nothing prints a secret.
"""

import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap import native as bootstrap_native
from bootstrap.releases import RELEASES
from sites import native as site_native
from sites.convention import SITES_AVAILABLE, SITES_ENABLED, SitePaths

from . import convention, core_native, install_native
from .install_native import Evidence, Step
from .models import FinishReview

_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"


class Exit(install_native.Exit):
    """docs/wordpress.md#finishing-a-partial-installation: the Finish's own refusals.

    Every other status is the installation's (``install_native.Exit``); a Finish never
    publishes the gate, so statuses 38 to 40 are not used.
    """

    NOT_GATED = 53
    EDITED = 54


class Unreadable(Exception):
    pass


def _checked(identifier: str) -> str:
    if not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def _layout_text(identifier: str, inspection: str) -> str:
    files = core_native.files_argv(_checked(identifier), shallow=True)[2]
    return f"{files}; {inspection} | sed 's/^/inspect /'"


def layout_argv(identifier: str) -> list[str]:
    """The site directory's entries, the top level of the public and private trees, the
    placeholder's digest and the fixed file inspection (loader, private configuration grammar
    and digest, version literal), as root."""
    return site_native.script(_layout_text(identifier, convention.inspection_command(identifier)))


@dataclass(frozen=True)
class Layout:
    files: core_native.FileState
    inspection: convention.FileInspection


def parse_layout(text: str) -> Layout:
    lines = text.splitlines()
    inspected = [line.removeprefix("inspect ") for line in lines if line.startswith("inspect ")]
    files = "".join(f"{line}\n" for line in lines if not line.startswith("inspect "))
    parsed = convention.parse_inspection("\n".join(inspected))
    if parsed is None:
        raise Unreadable("The WordPress file inspection did not answer in a supported format.")
    try:
        return Layout(core_native.parse_files(files), parsed)
    except core_native.Unreadable as unreadable:
        raise Unreadable(str(unreadable)) from None


def _database_text(identifier: str, schema: str, options: str) -> str:
    counts = core_native.database_argv(_checked(identifier))[2]
    return "; ".join(
        (
            _ENV,
            "echo 'part counts'",
            f"{{ {counts}; }}",
            "echo 'part schema'",
            schema,
            "echo 'part options'",
            f"{options} 2>/dev/null",
            "true",
        )
    )


def database_state_argv(identifier: str) -> list[str]:
    """The site database's object counts, its core schema summary and the two canonical
    options, as root: names and counts only, no row of any other table."""
    database = f"s{_checked(identifier)}"
    return site_native.script(
        _database_text(
            identifier,
            convention.schema_command([database]),
            convention.options_command(database),
        )
    )


@dataclass(frozen=True)
class DatabaseFacts:
    counts: core_native.DatabaseState
    # The schema summary, absent while the database does not exist.
    schema: convention.Schema | None
    options: dict[str, str]

    @property
    def installed(self) -> bool:
        """The exact core schema and canonical options, with any plugin tables beside it."""
        return (
            self.schema is not None
            and self.schema.complete
            and not self.schema.ambiguous
            and set(self.options) == set(convention.SITE_OPTIONS)
        )


def parse_database(text: str, identifier: str) -> DatabaseFacts:
    database = f"s{_checked(identifier)}"
    parts: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("part ") and line[5:] in {"counts", "schema", "options"}:
            if line[5:] in parts:
                raise Unreadable("The application database read is not in its expected form.")
            current = parts.setdefault(line[5:], [])
        elif current is not None:
            current.append(line)
        else:
            raise Unreadable("The application database read is not in its expected form.")
    if set(parts) != {"counts", "schema", "options"}:
        raise Unreadable("The application database read is not in its expected form.")
    try:
        counts = core_native.parse_database("\n".join(parts["counts"]))
        schema = convention.parse_schema("\n".join(parts["schema"]), [database])[database]
        options = convention.parse_options("\n".join(parts["options"]))
    except core_native.Unreadable, convention.CatalogFormatError:
        raise Unreadable("The application database read is not in its expected form.") from None
    return DatabaseFacts(counts, schema, options)


def _revalidation(row: FinishReview, evidence: Evidence, paths: SitePaths, release: str) -> str:
    """Everything the review recorded, recomputed as root under the lock before any change."""
    drift = f"exit {Exit.DRIFT}"
    layout = _layout_text(row.identifier, "ins")
    database = _database_text(row.identifier, "sq", "oq")
    cut = '| cut -d" " -f1)"'
    absent = [
        '"$stg"',
        '"$bak"',
        '"$phb"',
        '"$sn"',
        '"$pr"',
        '"$base/.wp-config.php.$q"',
        '"$base/.wp-private.$q"',
        *(['"$pub/wp-config.php"'] if row.creates_loader else []),
        *(['"$prv/wp-config.php"'] if row.creates_configuration else []),
    ]
    return "; ".join(
        (
            *install_native._evidence_checks(row, evidence, paths, release),
            f'[ "$({{ {layout}; }} | sha256sum {cut} = {evidence.files} ] || {drift}',
            f'[ "$({{ {database}; }} | sha256sum {cut} = {evidence.database} ] || {drift}',
            (
                "n \"$src\" 'regular file root root 644' && "
                f'[ "$(z "$src")" = {row.preimage_sha256} ] || {drift}'
            ),
            f'for p in {" ".join(absent)}; do [ ! -e "$p" ] && [ ! -L "$p" ] || {drift}; done',
            f'a "$base" {SITES_AVAILABLE} {SITES_ENABLED} /var/backups || {drift}',
            (
                "m \"$base\" 'directory root root 755' && "
                'm "$pub" "directory $u www-data 750" && '
                f'm "$prv" "directory $u $u 700" || {drift}'
            ),
            (
                'for d in "$base" /var/www /var /; do [ ! -e "$d/wp-cli.yml" ] && '
                f'[ ! -e "$d/wp-cli.local.yml" ] || exit {Exit.STAGING}; done'
            ),
            (
                f"[ \"$(df -P -B1 {convention.WEB_ROOT} | awk 'NR==2{{print $4}}')\" -ge "
                f"{core_native.REQUIRED_FREE_BYTES} ] || exit {Exit.STAGING}"
            ),
        )
    )


def _commands(row: FinishReview) -> dict[str, str]:
    """The fixed reads that both the revalidation and the later steps run, defined once."""
    return {
        "ins": convention.inspection_command(row.identifier),
        "sq": convention.schema_command([row.database_name]),
        "oq": convention.options_command(row.database_name),
    }


def _defined(row: FinishReview) -> str:
    return "; ".join(f"{name}(){{ {text}; }}" for name, text in _commands(row).items())


def _reusing(row: FinishReview, text: str) -> str:
    """``text`` with each fixed read replaced by the function that runs it."""
    for name, command in _commands(row).items():
        text = text.replace(command, name)
    return text


# The listing of one release entry: every path with its type, mode, owner and link count, and
# every file's SHA-256. Two entries are equal when the sorted listings are.
_LISTING: Final = (
    'cd "$1" && { find "./$2" -printf "%y %m %U %n %p\\n"; '
    'find "./$2" -type f -exec sha256sum -- {} +; } | sort | sha256sum'
)


def _compare(row: FinishReview) -> str:
    """The staged copy has exactly the pinned release's entries, and every release entry that
    exists equals it, or the run stops before changing anything. Absent entries are published;
    wp-content is the operator's content once the database holds the installation."""
    refuse = f"exit {Exit.EDITED}"
    drift = f"exit {Exit.DRIFT}"
    names = " ".join(sorted(core_native.RELEASE_ENTRIES))
    content = (
        ""
        if row.strict_content
        else (
            '[ "$t" = wp-content ] && { [ -d "$pub/$t" ] && [ ! -L "$pub/$t" ] && '
            f'[ "$(stat -c %U -- "$pub/$t")" = "$u" ] || {refuse}; continue; }}; '
        )
    )
    return "; ".join(
        (
            f'[ "$(ls -A -- "$stg/tree" | tr "\\n" " ")" = "{names} " ] || {drift}',
            f'd(){{ s /usr/bin/sh -c {shlex.quote(_LISTING)} sh "$1" "$2"; }}',
            (
                'for t in $(ls -A -- "$stg/tree"); do '
                '[ -e "$pub/$t" ] || [ -L "$pub/$t" ] || continue; '
                f'{content}[ "$(d "$stg/tree" "$t")" = "$(d "$pub" "$t")" ] || '
                f'{{ echo "barectl-wordpress: $t differs from the pinned release"; {refuse}; }}; '
                "done"
            ),
        )
    )


def _gated(row: FinishReview) -> str:
    """The site file already is the reviewed gate and answers as one; keep its bytes as the
    recovery preimage, as publishing the ready routing replaces them."""
    gate = row.gate_sha256
    refuse = f"exit {Exit.NOT_GATED}"
    return "; ".join(
        (
            f"gv || {refuse}",
            f'[ -d "$bkd" ] || mkdir -m 0700 -- "$bkd" || {refuse}',
            f'a "$avl" "$bkd" || {refuse}',
            (f'n "$src" \'regular file root root 644\' && [ "$(z "$src")" = {gate} ] || {refuse}'),
            (
                'cat -- "$src" >"$bak" && n "$bak" \'regular file root root 600\' && '
                f'[ "$(z "$bak")" = {gate} ] && sync -- "$bak" "$bkd" || {refuse}'
            ),
            "echo 'barectl-wordpress: gate verified'",
        )
    )


def _publish() -> str:
    """Rename each release entry the public root lacks into place; an entry that exists was
    compared identical to the staged copy and is left untouched."""
    refuse = f"exit {Exit.PUBLISH}"
    return "; ".join(
        (
            f'a "$base" && m "$pub" "directory $u www-data 750" || {refuse}',
            (
                'for t in $(ls -A -- "$stg/tree"); do d="$pub/$t"; '
                '[ ! -e "$d" ] && [ ! -L "$d" ] || continue; '
                '/usr/bin/mv --no-copy --no-clobber -T -- "$stg/tree/$t" "$d" '
                f'|| {refuse}; [ -e "$d" ] && [ ! -e "$stg/tree/$t" ] || {refuse}; done'
            ),
        )
    )


def body_steps(row: FinishReview, evidence: Evidence, release: str) -> list[Step]:
    """The named fragments of the run's native body, in order. A fragment appears only when
    the review found its resource missing."""
    paths = install_native._verified(row, evidence)
    if release not in RELEASES:
        raise ValueError("Not a reviewed release.")
    steps = [
        Step("helpers", install_native._helpers(row, paths)),
        Step("reads", _defined(row)),
        Step("tools", install_native._tools(row)),
        Step("revalidation", _revalidation(row, evidence, paths, release)),
        Step("stage", install_native._stage()),
        Step("download", install_native._download(row)),
        Step("archive", install_native._archive(row)),
        Step("extract", install_native._extract(row)),
        Step("checksums", install_native._checksums(row)),
    ]
    steps.append(Step("compare", _compare(row)))
    steps += [
        Step("gated", _gated(row)),
        Step("publish", _publish()),
        Step("placeholder", "; ".join(install_native._placeholder(row))),
    ]
    if row.creates_loader:
        steps.append(Step("loader", install_native._loader(row)))
    if row.creates_configuration:
        steps.append(Step("configuration", _reusing(row, install_native._configuration(row))))
    if row.runs_install:
        steps.append(Step("install", install_native._install(row)))
    steps += [
        Step(
            "schema",
            _reusing(row, install_native._schema(row, exact_tables=row.runs_install)),
        ),
        Step("integrity", install_native._integrity(row)),
        Step("access", install_native._access(row, administrator=row.runs_install)),
        Step("ready", install_native._ready(row)),
        Step("serving", install_native._serving()),
        Step("finish", "exit 0"),
    ]
    return steps


def body(row: FinishReview, evidence: Evidence, release: str) -> str:
    return "; ".join(step.text for step in body_steps(row, evidence, release))


def staged_payload(
    unit: str,
    boot_id: str,
    deadline: int,
    row: FinishReview,
    evidence: Evidence,
    release: str,
) -> tuple[str, str]:
    """The submitted script and the body it carries: the shared admission under the mutation
    lock, then the reviewed body, compressed and bound to its digest."""
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    if not install_native.SUFFIX.fullmatch(suffix):
        raise ValueError("Not a valid unit suffix.")
    text = body(row, evidence, release)
    steps = [
        *bootstrap_native.admission(unit, boot_id, deadline),
        f"q={suffix}",
        *bootstrap_native.staged(text),
    ]
    return "; ".join(steps), text
