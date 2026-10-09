"""WP-CLI setup preparation and apply against the simulated Ubuntu server.

The fake answers the fixed read-only WP-CLI scripts deterministically from a small
state, mirroring what the native payload does on a real server; it establishes nothing
about real GPG, curl or systemd behaviour.
"""

import hashlib
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from discovery import ssh
from discovery.fakes import FakeServer
from discovery.observations.databases import ROOT_QUERY
from discovery.ssh import CommandResult
from sites import native as site_native
from sites.convention import render_placeholder

from . import convention, core_native, install_native, setup_native
from .models import InstallationReview

_MARKER = "/usr/local/lib/wp-cli"
_ANCESTRY = (
    ("directory", "root", "root", "755", "12", "/usr"),
    ("directory", "root", "root", "755", "10", "/usr/local"),
    ("directory", "root", "root", "755", "6", "/usr/local/lib"),
)
_GPG_VERSION = "gpg (GnuPG) 2.4.4"


def _reads() -> frozenset[str]:
    """The WP-CLI reads' exact command forms: plain, through sudo, and its listing."""
    argvs = (setup_native.wpcli_state(), setup_native.wpcli_digest_argv())
    plain = {shlex.join(argv) for argv in argvs}
    return frozenset(
        plain | {f"sudo -n {read}" for read in plain} | {f"sudo -n -l {read}" for read in plain}
    )


def wpcli_read_only(command: str) -> bool:
    return command in _reads()


def _inner_script(command: str) -> str | None:
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if argv[:2] == [site_native.SHELL, "-c"] and len(argv) == 3:
        return argv[2]
    return None


@dataclass
class WpcliServer:
    """A server's WP-CLI installation state, as the fixed reads report it."""

    # "absent", "installed" (exact reviewed artifact) or "foreign" (other bytes or mode).
    phar: str = "absent"
    # "absent", "ok" (root:root 0755) or "foreign".
    directory: str = "absent"
    # Extra entries in the installation directory, by path.
    entries: tuple[str, ...] = ()
    # The native tools present, out of gpg and curl.
    tools: tuple[str, ...] = ("gpg", "curl")
    # The phar's digest when foreign, to make the mismatch observable.
    foreign_sha256: str = "0" * 64
    gpg_version: str = _GPG_VERSION
    ancestry: tuple[tuple[str, str, str, str, str, str], ...] = field(
        default_factory=lambda: _ANCESTRY
    )

    def state(self) -> str:
        """The fixed read's exact output for this state."""
        lines = [
            f"path {kind}|{user}|{group}|{mode}|{links}|{path}"
            for kind, user, group, mode, links, path in self.ancestry
        ]
        if self.directory == "absent":
            lines.append(f"absent {setup_native.DIRECTORY}")
        elif self.directory == "ok":
            lines.append(f"path directory|root|root|755|2|{setup_native.DIRECTORY}")
        else:
            lines.append(f"path directory|root|root|777|2|{setup_native.DIRECTORY}")
        entries: list[tuple[str, str, str, str, str]] = [
            ("f", "644", "0", "0", path) for path in self.entries
        ]
        if self.phar != "absent":
            mode = "644" if self.phar == "installed" else "755"
            entries.append(("f", mode, "0", "0", setup_native.PHAR))
        lines += [
            f"entry {kind} {mode} {user} {group} {path}"
            for kind, mode, user, group, path in sorted(entries, key=lambda entry: entry[4])
        ]
        if self.phar == "absent":
            lines.append(f"absent {setup_native.PHAR}")
        else:
            mode = "644" if self.phar == "installed" else "755"
            lines.append(f"path regular file|root|root|{mode}|1|{setup_native.PHAR}")
            digest = setup_native.SHA256 if self.phar == "installed" else self.foreign_sha256
            lines.append(f"sha {digest} {setup_native.PHAR}")
        lines += [
            f"tool {name} {'ok' if name in self.tools else 'missing'}" for name in ("gpg", "curl")
        ]
        if "gpg" in self.tools:
            lines.append(f"version {self.gpg_version}")
        return "\n".join(lines) + "\n"

    def answer(self, remote: FakeServer) -> None:
        if self._answer not in remote.answers:
            remote.answers.insert(0, self._answer)

    def install(self) -> None:
        """A successful run's effect, as the payload leaves it."""
        self.directory = "ok"
        self.phar = "installed"
        self.entries = ()

    def _answer(self, command: str) -> CommandResult | None:
        if command.startswith("sudo -n -l ") and _MARKER in command:
            return CommandResult(0, "")
        inner = command.removeprefix("sudo -n ")
        script = _inner_script(inner)
        if script is None or _MARKER not in script:
            return None
        state = self.state()
        if script.rstrip().endswith("sha256sum"):
            return CommandResult(0, f"{hashlib.sha256(state.encode()).hexdigest()}  -\n")
        return CommandResult(0, state)


SALT_VALUES = tuple(f"{chr(97 + n) * 24}0123456789ABCDEFGHIJKLMNOPQRSTUV!@#"[:64] for n in range(8))
_INSPECTION = re.compile(r"python3 -I -c '.*' [a-z0-9]+", re.DOTALL)


@dataclass
class ApplicationServer:
    """WordPress applications on a ``FakeServer`` whose sites already follow the site
    convention: public and private files, the catalog reads and the fixed file inspection.

    The inspection command runs the real server-side script against a temporary copy of the
    simulated files, so the fake establishes the script's own parsing; it establishes
    nothing about real MariaDB or file permissions.
    """

    remote: FakeServer
    # Catalog rows by database name, as the fixed reads print them.
    schemas: dict[str, str] = field(default_factory=dict)
    options: dict[str, str] = field(default_factory=dict)
    # Reads that fail, by kind: "schema" or "options".
    failing: set[str] = field(default_factory=set)
    # Everything the fixture was asked to run; none of it may ever be application code.
    inspections: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.remote.answers.insert(0, self._answer)

    def as_root(self) -> None:
        self.remote.results[ROOT_QUERY] = ssh.CommandResult(0, "0\n")

    def install(
        self,
        identifier: str = "shop",
        names: tuple[str, ...] = ("shop.test",),
        *,
        version: str = "7.1.3",
        core: bool = True,
        loader: str | None = None,
        configuration: str | None = None,
        tables: str = "complete",
        url: str | None = None,
        ambiguous: bool = False,
    ) -> None:
        """Make the site's tree and database a WordPress application as ``tables`` says:
        complete, partial, altered or none. ``loader`` and ``configuration`` replace the
        files' text; ``core`` False leaves the release files out."""
        user = f"s{identifier}"
        for path in [p for p in self.remote.files if p.startswith(f"/var/www/{identifier}/")]:
            del self.remote.files[path]
            self.remote.ownership.pop(path, None)
        public, private = f"/var/www/{identifier}/public", f"/var/www/{identifier}/private"
        entries = ["wp-config.php"] if loader != "" else []
        if core:
            entries += [marker for marker in convention.MARKERS if "/" not in marker]
        self.remote.directories[public] = sorted(entries)
        self.remote.directories[private] = [] if configuration == "" else ["wp-config.php"]
        if loader != "":
            self.remote.files[f"{public}/wp-config.php"] = (
                convention.render_loader(identifier) if loader is None else loader
            )
            self.remote.ownership[f"{public}/wp-config.php"] = (user, "www-data", 0o640)
        if configuration != "":
            self.remote.files[f"{private}/wp-config.php"] = (
                convention.render_private_configuration(identifier, SALT_VALUES)
                if configuration is None
                else configuration
            )
            self.remote.ownership[f"{private}/wp-config.php"] = (user, user, 0o600)
        if core:
            self.remote.files[f"{public}/wp-includes/version.php"] = (
                f"<?php\n$wp_version = '{version}';\n"
            )
        self.schemas[user] = _schema_rows(user, tables, ambiguous=ambiguous)
        canonical = url if url is not None else f"https://{names[0]}"
        self.options[user] = f"home\t{canonical}\nsiteurl\t{canonical}\n" if canonical else ""

    def _answer(self, command: str) -> CommandResult | None:
        if command.startswith(convention.MARIADB_CLIENT + " "):
            sql = shlex.split(command)[-1]
            if sql.startswith("SELECT option_name"):
                return self._options(sql)
            return self._schema(sql)
        if _INSPECTION.fullmatch(command):
            return self._inspect(command)
        return None

    def _schema(self, sql: str) -> CommandResult:
        if "schema" in self.failing:
            return CommandResult(1, "")
        listed = sql.partition("TABLE_SCHEMA IN (")[2].partition(")")[0]
        names = re.findall(r"'(s[a-z0-9]+)'", listed)
        return CommandResult(0, "".join(self.schemas.get(name, "") for name in names))

    def _options(self, sql: str) -> CommandResult:
        if "options" in self.failing:
            return CommandResult(1, "")
        name = sql.partition("FROM `")[2].partition("`")[0]
        return CommandResult(0, self.options.get(name, ""))

    def _inspect(self, command: str) -> CommandResult:
        self.inspections.append(command)
        identifier = shlex.split(command)[-1]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            prefix = f"/var/www/{identifier}/"
            for path, text in self.remote.files.items():
                if path.startswith(prefix):
                    target = base / path.removeprefix("/var/www/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(text.replace("/var/www", directory))
                    if path in self.remote.unreadable:
                        target.chmod(0)
            argv = shlex.split(convention.inspection_command(identifier, base=directory))
            result = subprocess.run(  # noqa: S603 - the fixed script, on a temporary copy
                [sys.executable, *argv[1:]], capture_output=True, text=True, check=False
            )
            for entry in base.rglob("*"):
                entry.chmod(0o700)
        return CommandResult(result.returncode, result.stdout)


def _schema_rows(database: str, tables: str, *, ambiguous: bool) -> str:
    rows = ""
    if tables in {"complete", "altered"}:
        for index, (table, columns) in enumerate(convention.CORE_TABLES.items()):
            count = len(columns) - (1 if tables == "altered" and index == 0 else 0)
            rows += f"C\t{database}\twp_{table}\t{count}\n"
        rows += f"W\t{database}\t{len(convention.CORE_TABLES)}\n"
    elif tables == "partial":
        for table in ("options", "users", "posts"):
            rows += f"C\t{database}\twp_{table}\t{len(convention.CORE_TABLES[table])}\n"
        rows += f"W\t{database}\t3\n"
    if ambiguous:
        rows += f"X\t{database}\t1\n"
    return rows


def issued_lineage(names: tuple[str, ...]) -> str:
    """The production lineage's fixed read for ``names``, as Certbot's ECDSA lineage prints."""
    return (
        "subject=\n"
        "notBefore=Sep 30 12:00:00 2026 GMT\n"
        "notAfter=Dec 29 12:00:00 2026 GMT\n"
        "X509v3 Subject Alternative Name: \n"
        f"    {', '.join(f'DNS:{name}' for name in names)}\n"
        "serial=0A1B2C\n"
        "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
        "pubkey_cert=" + "1" * 64 + "\n"
        "pubkey_key=" + "1" * 64 + "\n"
        "curve=prime256v1\n"
        "renewal=yes\n"
    )


@dataclass
class InstallationServer:
    """The state the installation review's fixed reads report for one site: its public and
    private trees, its database catalog, the toolchain and the announced archive.

    The reads' formats are the real scripts' output; the fake establishes nothing about
    real find, MariaDB or curl behaviour.
    """

    identifier: str = "shop"
    uid: int = 1003
    # The public tree's entries by name, with find's type letter.
    public: dict[str, str] = field(default_factory=lambda: {"index.html": "f"})
    private: dict[str, str] = field(default_factory=dict)
    # Entries beside public and private in the site directory.
    beside: dict[str, str] = field(default_factory=dict)
    placeholder: str | None = None
    exists: bool = True
    tables: tuple[str, ...] = ()
    routines: int = 0
    events: int = 0
    triggers: int = 0
    tools: tuple[str, ...] = ("curl", "tar", "sha256sum")
    free_bytes: int = 4 * 2**30
    archive_status: int = 200
    archive_bytes: int = core_native.ARCHIVE_BYTES
    # Whether a successful installation run left the application, and which differences from
    # the review its verification read should find: "ready", "preimage", "placeholder",
    # "loader", "configuration", "version", "entries", "schema", "tables", "options" or "nginx".
    applied: bool = False
    # The tables a successful run leaves: the twelve core ones unless plugins added more.
    table_total: int = len(convention.CORE_TABLES)
    differences: set[str] = field(default_factory=set)
    # Reads that fail, by name: "files", "database" or "supply".
    failing: set[str] = field(default_factory=set)
    # The reads that changed the state when they ran, by name.
    flapping: set[str] = field(default_factory=set)
    reads: list[str] = field(default_factory=list)
    _count: dict[str, int] = field(default_factory=dict)

    def answer(self, remote: FakeServer) -> None:
        if self._answer not in remote.answers:
            remote.answers.insert(0, self._answer)

    def owns(self, command: str) -> bool:
        """Whether ``command`` is one of the review's own fixed reads, which only read."""
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        return inner in {
            shlex.join(argv)
            for argv in (
                core_native.files_argv(self.identifier),
                core_native.database_argv(self.identifier),
                core_native.supply_argv(),
            )
        }

    def files(self) -> str:
        gid = 33
        site = {"public": "d", "private": "d", **self.beside}
        rows = [f"site {kind} 750 {self.uid} {gid} 2 4096 {name}" for name, kind in site.items()]
        rows += ["end site"]
        rows += [
            f"public {kind} {'755' if kind == 'd' else '640'} {self.uid} {gid} 1 4096 {name}"
            for name, kind in sorted(self.public.items())
        ]
        rows += ["end public"]
        rows += [
            f"private {kind} {'700' if kind == 'd' else '600'} {self.uid} {self.uid} 1 4096 {name}"
            for name, kind in sorted(self.private.items())
        ]
        rows += ["end private"]
        if self.public.get("index.html") == "f":
            text = (
                render_placeholder(self.identifier)
                if self.placeholder is None
                else self.placeholder
            )
            rows.append(f"sha {hashlib.sha256(text.encode()).hexdigest()}")
        return "".join(f"{row}\n" for row in rows)

    def database(self) -> str:
        rows = [
            f"S\t{int(self.exists)}",
            f"T\t{len(self.tables)}",
            f"R\t{self.routines}",
            f"E\t{self.events}",
            f"G\t{self.triggers}",
            *(f"N\t{name}" for name in self.tables[:5]),
        ]
        return "".join(f"{row}\n" for row in rows)

    def supply(self) -> str:
        rows = [
            f"tool {name} {'ok' if name in self.tools else 'missing'}"
            for name in ("curl", "tar", "sha256sum")
        ]
        rows += [f"free {self.free_bytes}", f"archive {self.archive_status} {self.archive_bytes}"]
        return "".join(f"{row}\n" for row in rows)

    def run_review(self) -> InstallationReview:
        """The review the applied run consumed."""
        from .models import RunWordpressInstall

        return RunWordpressInstall.objects.get()

    def installed(self) -> str:
        """The installation verification read's output after a successful run."""
        row = self.run_review()
        identifier = row.identifier
        suffix = self.suffix
        source = f"/etc/nginx/sites-available/{identifier}.conf"
        backup = f"/var/backups/nginx/{identifier}.conf.{suffix}"
        found = self.differences
        digest = install_native.digest
        ready = "0" * 64 if "ready" in found else row.ready_sha256
        user = row.site_user
        loader = f"{row.public_root}/wp-config.php"
        lines = [
            f"path regular file|root|root|644|1|{source}",
            f"sha {ready} {source}",
            f"sha {'0' * 64 if 'preimage' in found else row.preimage_sha256} {backup}",
            (
                f"path regular file|{user}|{'root' if 'loader' in found else 'www-data'}"
                f"|640|1|{loader}"
            ),
            (
                f"path regular file|{user}|{user}|{'644' if 'configuration' in found else '600'}"
                f"|1|{row.private_configuration}"
            ),
        ]
        if row.placeholder_present:
            placeholder = f"/var/backups/nginx/{identifier}.index.html.{suffix}"
            lines.append(
                f"sha {'0' * 64 if 'placeholder' in found else row.placeholder_sha256} "
                f"{placeholder}"
            )
        schema = install_native.expected_schema_digest(row.database_name)
        options = digest(install_native.expected_options(row.url))
        entries = ["private", "public", *(["wp-staging"] if "entries" in found else [])]
        lines += [f"entry d {user} {user} 755 {name}" for name in sorted(entries)]
        lines += [
            f"inspect loader {'other' if 'loader' in found else 'exact'}",
            f"inspect configuration {'unsupported' if 'configuration' in found else 'supported'}",
            f"inspect digest {digest('configuration')}",
            f"inspect version {'6.0.0' if 'version' in found else row.core_version}",
            f"schema {'0' * 64 if 'schema' in found else schema}",
            f"tables {'13' if 'tables' in found else self.table_total}",
            f"options {'0' * 64 if 'options' in found else options}",
            f"nginx {'invalid' if 'nginx' in found else 'valid'}",
        ]
        return "".join(f"{line}\n" for line in lines)

    suffix: str = ""

    def _answer(self, command: str) -> CommandResult | None:
        authorization = command.startswith("sudo -n -l ")
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        script = _inner_script(inner) or ""
        if "echo 'nginx valid'" in script and "sed 's/^/inspect /'" in script:
            if authorization:
                return CommandResult(0, "")
            found = re.search(r"\.conf\.([0-9a-f]{32})", script)
            if found is None or not self.applied:
                return CommandResult(1, "")
            self.suffix = found[1]
            return CommandResult(0, self.installed())
        for name, argv in (
            ("files", core_native.files_argv(self.identifier)),
            ("database", core_native.database_argv(self.identifier)),
            ("supply", core_native.supply_argv()),
        ):
            if inner != shlex.join(argv):
                continue
            if authorization:
                return CommandResult(0, "")
            self.reads.append(name)
            self._count[name] = self._count.get(name, 0) + 1
            if name in self.failing:
                return CommandResult(1, "")
            if name in self.flapping and self._count[name] % 2 == 0:
                self.public = {**self.public, "late.txt": "f"}
            return CommandResult(0, getattr(self, name)())
        return None
