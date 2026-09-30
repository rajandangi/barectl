"""A simulated server for database plans: a site server with the engine, driver and
catalogs, answering the fixed catalog and probe-path reads."""

import re
import shlex
from dataclasses import dataclass, field
from typing import ClassVar, override

from django.http.response import HttpResponseBase

from bootstrap.fakes import NOBLE_PACKAGING, Packaging
from discovery.observations.databases import satisfied_mariadb_rows
from discovery.ssh import CommandResult
from sites.fakes import SiteServer, SiteTestCase

from .binding import MARIADB_SECTION, POSTGRESQL_SECTION

DATABASE_PERMISSIONS = ("view_server", "view_databaseplan", "prepare_databaseplan")
DATABASE_APPLY = (*DATABASE_PERMISSIONS, "apply_databaseplan")
_PREFIXES = (["sudo", "-n", "-l"], ["sudo", "-n"])


@dataclass
class DatabaseServer:
    """A server with a convention site, MariaDB, its PHP driver and their catalogs."""

    site: SiteServer
    # The MariaDB catalog rows under the site's name, as the catalog read prints them.
    mariadb: str = ""
    # What the other engine's absence read prints; empty when it holds nothing.
    other: str = ""
    plugin: str = "ACTIVE"
    probe_exists: bool = False
    # What verification's state read reports after a run, when the run happened.
    state: str = ""
    catalog_reads: list[str] = field(default_factory=list)

    def answer(self, remote: object) -> None:
        self.site.ubuntu.mariadb = "installed"
        self.site.answer(remote)
        answers = remote.answers  # type: ignore[attr-defined]
        if self._answer not in answers:
            answers.insert(0, self._answer)

    def satisfy(self, name: str) -> None:
        self.mariadb = satisfied_mariadb_rows(name)

    def _answer(self, command: str) -> CommandResult | None:
        try:
            argv = shlex.split(command)
        except ValueError:
            return None
        listed = False
        for prefix in _PREFIXES:
            if argv[: len(prefix)] == prefix:
                listed = prefix[-1] == "-l"
                argv = argv[len(prefix) :]
                break
        if argv[:2] != ["/usr/bin/sh", "-c"] or len(argv) != 3:
            return None
        script = argv[2]
        own = (
            ("c(){ " in script and script.endswith("; c"))
            or "echo '== readiness'" in script
            or _PROBE_PATH.fullmatch(script) is not None
        )
        if listed:
            return CommandResult(0, "") if own else None
        if "echo '== readiness'" in script:
            return CommandResult(0, self.state) if self.state else CommandResult(1, "")
        if "c(){ " in script and script.endswith("; c"):
            self.catalog_reads.append(script)
            text = f"{MARIADB_SECTION}\nP\t{self.plugin}\n{self.mariadb}"
            if POSTGRESQL_SECTION in script:
                text += f"{POSTGRESQL_SECTION}\n{self.other}"
            return CommandResult(0, text)
        if _PROBE_PATH.fullmatch(script):
            return CommandResult(0, "present\n" if self.probe_exists else "absent\n")
        return None


_CATALOG = re.compile(
    r"export LC_ALL=C PATH=/usr/sbin:/usr/bin; c\(\)\{ .*; \} 2>/dev/null; c", re.DOTALL
)
_PROBE_PATH = re.compile(
    r"if \[ -e /var/www/[a-z0-9]+/dbprobe-[0-9a-f]{32}\.php \] \|\| "
    r"\[ -L /var/www/[a-z0-9]+/dbprobe-[0-9a-f]{32}\.php \]; then echo present; "
    r"else echo absent; fi"
)


def database_read_only(command: str) -> bool:
    """A binding preparation's own reads: the catalog read, whose statements are SELECTs,
    and the probe's path."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    for prefix in _PREFIXES:
        if argv[: len(prefix)] == prefix:
            argv = argv[len(prefix) :]
            break
    if argv[:2] != ["/usr/bin/sh", "-c"] or len(argv) != 3:
        return False
    script = argv[2]
    if _PROBE_PATH.fullmatch(script):
        return True
    if not _CATALOG.fullmatch(script):
        return False
    statements = re.findall(r"-(?:e|c) '([^']*(?:''[^']*)*)'", script)
    sql = " ".join(shlex.split(script)[1:])
    return bool(statements) and not re.search(
        r"\b(CREATE|DROP|GRANT|REVOKE|ALTER|INSERT|UPDATE|DELETE)\b", sql
    )


class DatabaseTestCase(SiteTestCase):
    """Database plans through requests and the worker, against a simulated server of
    ``packaging``'s release with the site shop, MariaDB and its PHP driver."""

    packaging: ClassVar[Packaging] = NOBLE_PACKAGING
    database: DatabaseServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", ("shop.example.com",))
        self.site.drivers = ("mysql",)
        self.database = DatabaseServer(self.site)

    @override
    def assert_read_only(self) -> None:
        self.remote.commands[:] = [c for c in self.remote.commands if not database_read_only(c)]
        super().assert_read_only()

    def prepare_database(
        self,
        identifier: str = "shop",
        action: str = "database_mariadb",
        *,
        perms: tuple[str, ...] = DATABASE_PERMISSIONS,
    ) -> HttpResponseBase:
        self.sign_in_with(*perms)
        self.database.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": action, "identifier": identifier},
        )
        self.run_worker()
        return response
