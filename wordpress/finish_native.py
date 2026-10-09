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

import hashlib
import re
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
    """docs/wordpress.md#finishing-a-partial-installation: the Finish's own refusal.

    Every other status is the installation's (``install_native.Exit``); a Finish never
    publishes the gate, so statuses 38 to 40 are not used.
    """

    NOT_GATED = 53


# The release comparison ------------------------------------------------------------------

# Run as root by the review, reading the pinned archive once from a pipe into memory. It reads
# files and names only as data: it follows no link, runs nothing and prints only fixed tokens
# and bounded safe paths. The expected side is the release as publication leaves it
# (directories 0755, files 0644, owned by the site user); wp-content is compared only when the
# database is empty, because after an installation it is the operator's content. The run
# itself compares with the staged copy by native tools (``_compare``).
_HEAD: Final = r"""
import hashlib, os, re, stat, sys@IMPORT@
root, uid, strict = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
ENTRIES, TREE, FILE = @LIMITS@
SKIP = ("wp-config.php", "index.html")
safe = re.compile(r"[A-Za-z0-9._@,+~-]{1,200}")
seen = [0, 0]
def charge(entries, size):
    seen[0] += entries
    seen[1] += size
    if seen[0] > ENTRIES or seen[1] > TREE:
        sys.exit(6)
def deep(top):
    return strict or top != "wp-content"
def walk(base, top, found):
    stack = [(top, base + "/" + top)]
    while stack:
        rel, path = stack.pop()
        charge(1, 0)
        info = os.lstat(path)
        own = stat.S_IMODE(info.st_mode), info.st_uid
        if stat.S_ISDIR(info.st_mode):
            found[rel] = ("d", "") + own
            if rel != top or deep(top):
                with os.scandir(path) as names:
                    for entry in names:
                        charge(1, 0)
                        if safe.fullmatch(entry.name):
                            stack.append((rel + "/" + entry.name, path + "/" + entry.name))
                        else:
                            found[rel + "/?"] = ("x", "", 0, 0)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= FILE:
            charge(0, info.st_size)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                digest = hashlib.sha256()
                while chunk := os.read(fd, 1 << 20):
                    digest.update(chunk)
            finally:
                os.close(fd)
            found[rel] = ("f", digest.hexdigest()) + own
        else:
            found[rel] = ("x", "", 0, 0)
"""
_UNPACK: Final = r"""
ARCHIVE, SIZE, SHA = @ARCHIVE@
class Hashed:
    def __init__(self, source):
        self.source, self.digest, self.size = source, hashlib.sha256(), 0
    def read(self, count=-1):
        data = self.source.read(count)
        self.size += len(data)
        self.digest.update(data)
        if self.size > ARCHIVE:
            sys.exit(7)
        return data
def expect(found):
    stream = Hashed(sys.stdin.buffer)
    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            parts = member.name.rstrip("/").split("/")
            names = parts[1:]
            if parts[0] != "wordpress" or not all(safe.fullmatch(part) for part in names) or (
                "." in names or ".." in names
            ):
                sys.exit(3)
            if len(parts) == 1:
                continue
            charge(1, 0)
            rel = "/".join(parts[1:])
            if not deep(parts[1]) and len(parts) > 2:
                found.setdefault(parts[1], ("d", "", 0o755, uid))
                continue
            for depth in range(1, len(parts) - 1):
                found.setdefault("/".join(parts[1 : depth + 1]), ("d", "", 0o755, uid))
            if member.isdir():
                found[rel] = ("d", "", 0o755, uid)
            elif member.isreg() and member.size <= FILE:
                charge(0, member.size)
                digest, source = hashlib.sha256(), archive.extractfile(member)
                while chunk := source.read(1 << 20):
                    digest.update(chunk)
                found[rel] = ("f", digest.hexdigest(), 0o644, uid)
            else:
                sys.exit(5)
    while stream.read(1 << 20):
        pass
    if stream.size != SIZE or stream.digest.hexdigest() != SHA:
        sys.exit(8)
"""
_TAIL: Final = r"""
def group(found):
    names = {}
    for rel, value in found.items():
        names.setdefault(rel.split("/")[0], {})[rel] = value
    return names
def judge(name, have, want):
    if not deep(name):
        have = {name: (have[name][0], have[name][3]) if name in have else ("x", 0)}
        want = {name: ("d", want[name][3])}
        return ("content" if have == want else "differs"), {}
    if have == want:
        return "same", {}
    changes = {key: "missing" for key in want if key not in have}
    changes.update({key: "extra" for key in have if key not in want})
    changes.update({key: "changed" for key in want if key in have and have[key] != want[key]})
    return "differs", changes
def main():
    expected = {}
    expect(expected)
    wanted = group(expected)
    seen[:] = [0, 0]
    present = set(os.listdir(root))
    actual = {}
    for name in sorted(wanted):
        if name in present:
            walk(root, name, actual)
    found = group(actual)
    print("tops", len(wanted))
    for name in sorted(wanted):
        if name in present:
            state, changes = judge(name, found.get(name, {}), wanted[name])
        else:
            state, changes = "absent", {}
        print("top", name, state)
        for rel in sorted(changes)[:3]:
            print("diff", name, changes[rel], rel if safe.fullmatch(rel.replace("/", "_")) else "?")
    for name in sorted(present - set(wanted) - set(SKIP)):
        print("foreign", name if safe.fullmatch(name) else "?")
    print("end")
try:
    main()
except SystemExit:
    raise
except Exception:
    sys.exit(9)
"""


def compare_script() -> str:
    """The comparison's source: the published release files against the pinned archive."""
    limits = (
        f"{core_native.MAX_ENTRIES}, {core_native.MAX_TREE_BYTES}, {core_native.MAX_FILE_BYTES}"
    )
    archive = (
        f"{core_native.MAX_ARCHIVE_BYTES}, {core_native.ARCHIVE_BYTES}, "
        f"{core_native.ARCHIVE_SHA256!r}"
    )
    head = _HEAD.replace("@IMPORT@", ", tarfile").replace("@LIMITS@", limits)
    return head + _UNPACK.replace("@ARCHIVE@", archive) + _TAIL


def _checked(identifier: str) -> str:
    if not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def stream_argv(identifier: str, uid: int, *, strict: bool) -> list[str]:
    """Compare the published release files with the pinned archive, read once from the
    official URL through a pipe into memory: nothing is written, nothing is extracted and the
    archive's size and SHA-256 must be the pinned ones before any result is printed."""
    if not 0 < uid < 2**31:
        raise ValueError("Not a site user ID.")
    fetch = (
        "curl --silent --show-error --fail --location --max-redirs 3 --proto =https "
        "--proto-redir =https --connect-timeout 10 --max-time 12 "
        f"--max-filesize {core_native.MAX_ARCHIVE_BYTES} {shlex.quote(core_native.ARCHIVE_URL)}"
    )
    compare = (
        f"python3 -I -c {shlex.quote(compare_script())} "
        f"{shlex.quote(convention.public_root(_checked(identifier)))} {uid} {int(strict)}"
    )
    return site_native.script(f"{_ENV}; {fetch} 2>/dev/null | {compare}")


@dataclass(frozen=True)
class Difference:
    top: str
    why: str
    path: str


@dataclass(frozen=True)
class Comparison:
    # Each release entry of the pinned archive: absent, same, differs or (without comparing
    # wp-content) content.
    tops: dict[str, str]
    # Public entries that are neither release entries nor the loader or the placeholder.
    foreign: tuple[str, ...]
    differences: tuple[Difference, ...]


class Unreadable(Exception):
    pass


_STATES = frozenset({"absent", "same", "differs", "content"})
_NAME = re.compile(r"[A-Za-z0-9._@,+~-]{1,200}|\?")
_PATH = re.compile(r"[A-Za-z0-9._@,+~/-]{1,400}|\?")
_UNEXPECTED = "The release comparison is not in its expected form."


def parse_comparison(text: str) -> Comparison:
    tops: dict[str, str] = {}
    foreign: list[str] = []
    differences: list[Difference] = []
    count = -1
    ended = False
    for line in text.splitlines():
        match line.split(" "):
            case ["tops", number] if number.isdigit() and count < 0:
                count = int(number)
            case ["top", name, state] if state in _STATES and _NAME.fullmatch(name):
                tops[name] = state
            case ["diff", name, why, path] if (
                why in {"missing", "extra", "changed"}
                and _NAME.fullmatch(name)
                and _PATH.fullmatch(path)
            ):
                differences.append(Difference(name, why, path))
            case ["foreign", name] if _NAME.fullmatch(name):
                foreign.append(name)
            case ["end"]:
                ended = True
            case _:
                raise Unreadable(_UNEXPECTED)
    if not ended or count != len(tops) or count < 1:
        raise Unreadable(_UNEXPECTED)
    return Comparison(tops, tuple(foreign), tuple(differences))


def comparison_digest(text: str) -> str:
    """The digest the body recomputes: command substitution drops trailing newlines."""
    return hashlib.sha256(text.rstrip("\n").encode()).hexdigest()


# The reads the review records and the lock rechecks ---------------------------------------


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


# The body ---------------------------------------------------------------------------------


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
    """Every release entry that exists must equal the staged copy of the pinned archive, or the
    run stops before changing anything. Absent entries are published; wp-content is the
    operator's content once the database holds the installation."""
    refuse = f"exit {Exit.DRIFT}"
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
            f'd(){{ s /usr/bin/sh -c {shlex.quote(_LISTING)} sh "$1" "$2"; }}',
            (
                'for t in $(ls -A -- "$stg/tree"); do '
                '[ -e "$pub/$t" ] || [ -L "$pub/$t" ] || continue; '
                f'{content}[ "$(d "$stg/tree" "$t")" = "$(d "$pub" "$t")" ] || {refuse}; done'
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
    if row.compares:
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
