"""The state the Finish review's fixed reads report for one partly installed site.

The reads' formats are the real scripts' output; the fake establishes nothing about real find,
MariaDB, curl or tar behaviour (the native suites do). The state is described the way an
interrupted installation leaves it: which release entries exist and whether each equals the
pinned archive, the loader and the private configuration, and the database.
"""

import shlex
from dataclasses import dataclass, field
from typing import override

from discovery.ssh import CommandResult

from . import convention, core_native, finish_native
from .fakes import InstallationServer, _schema_rows
from .models import InstallationReview, RunWordpressFinish

# Where an interrupted installation can stop, in the order of the installation's steps.
BOUNDARIES = (
    "gate",
    "publish",
    "placeholder",
    "loader",
    "configuration",
    "install",
)


@dataclass
class FinishServer(InstallationServer):
    # The release entries present in the public root.
    release: set[str] = field(default_factory=set)
    # Whether the exact placeholder index.html still exists beside them.
    has_placeholder: bool = True
    # absent, exact, other or denied.
    loader: str = "absent"
    # absent, supported, unsupported or denied.
    configuration: str = "absent"
    configuration_digest: str = "c" * 64
    # empty, installed, partial, altered or ambiguous.
    database_state: str = "empty"
    plugin_tables: int = 0
    # The canonical options as stored; None means the reviewed address.
    options: str | None = None
    extras: dict[str, str] = field(default_factory=dict)
    private_extras: dict[str, str] = field(default_factory=dict)
    # Replaces the loader's and the configuration's "mode uid gid" in the listings.
    loader_attributes: str | None = None
    configuration_attributes: str | None = None
    gate_url: str = "https://www.shop.example.com"

    def leave(self, boundary: str) -> None:
        """The state an installation leaves when it stops after ``boundary``."""
        index = BOUNDARIES.index(boundary)
        self.release = set() if index < 1 else set(core_native.RELEASE_ENTRIES)
        self.has_placeholder = index < 2
        self.loader = "exact" if index >= 3 else "absent"
        self.configuration = "supported" if index >= 4 else "absent"
        self.database_state = "installed" if index >= 5 else "empty"
        self.tables = ()
        self._sync()

    def _sync(self) -> None:
        entries = {name: core_native.RELEASE_ENTRIES[name] for name in self.release}
        entries.update(self.extras)
        if self.has_placeholder:
            entries["index.html"] = "f"
        if self.loader != "absent":
            entries["wp-config.php"] = "f"
        self.public = entries
        self.private = {
            **({"wp-config.php": "f"} if self.configuration != "absent" else {}),
            **self.private_extras,
        }

    @override
    def files(self) -> str:
        text = super().files()
        for name, attributes in (
            ("wp-config.php", self.loader_attributes),
            ("wp-config.php", self.configuration_attributes),
        ):
            if attributes is None:
                continue
            kind = "public" if attributes is self.loader_attributes else "private"
            lines = text.splitlines()
            text = "".join(
                (
                    f"{kind} f {attributes} 1 4096 {name}\n"
                    if line.startswith(f"{kind} f ") and line.endswith(f" {name}")
                    else f"{line}\n"
                )
                for line in lines
            )
        return text

    def layout(self) -> str:
        self._sync()
        version = "7.1.3" if "wp-includes" in self.release else "none"
        lines = [f"inspect loader {self.loader}"]
        if self.configuration == "unsupported":
            lines.append("inspect configuration unsupported line 4")
        else:
            lines.append(f"inspect configuration {self.configuration}")
        if self.configuration == "supported":
            lines.append(f"inspect digest {self.configuration_digest}")
        lines.append(f"inspect version {version}")
        return self.files() + "".join(f"{line}\n" for line in lines)

    def state_database(self) -> str:
        name = f"s{self.identifier}"
        installed = self.database_state == "installed"
        total = len(convention.CORE_TABLES) + self.plugin_tables
        counts = {
            "installed": total,
            "partial": 3,
            "altered": len(convention.CORE_TABLES),
            "ambiguous": len(convention.CORE_TABLES),
            "empty": 0,
        }[self.database_state]
        names = (
            ["wp_commentmeta", "wp_comments", "wp_links", "wp_options", "wp_postmeta"]
            if counts
            else []
        )
        lines = [
            f"S\t{int(self.exists)}",
            f"T\t{counts}",
            f"R\t{self.routines}",
            f"E\t{self.events}",
            f"G\t{self.triggers}",
            *(f"N\t{item}" for item in names),
        ]
        schema = {
            "installed": "complete",
            "partial": "partial",
            "altered": "altered",
            "ambiguous": "complete",
            "empty": "none",
        }[self.database_state]
        rows = _schema_rows(name, schema, ambiguous=self.database_state == "ambiguous")
        options = (
            f"home\t{self.gate_url}\nsiteurl\t{self.gate_url}\n"
            if installed or self.database_state == "ambiguous"
            else ""
        )
        if self.options is not None:
            options = self.options
        return (
            "part counts\n"
            + "".join(f"{line}\n" for line in lines)
            + "part schema\n"
            + rows
            + "part options\n"
            + options
        )

    def _argvs(self) -> dict[str, str]:
        identifier = self.identifier
        return {
            "layout": shlex.join(finish_native.layout_argv(identifier)),
            "state_database": shlex.join(finish_native.database_state_argv(identifier)),
        }

    @override
    def owns(self, command: str) -> bool:
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        return inner in self._argvs().values() or super().owns(command)

    @override
    def run_review(self) -> InstallationReview:
        return RunWordpressFinish.objects.get()

    @override
    def _answer(self, command: str) -> CommandResult | None:
        authorization = command.startswith("sudo -n -l ")
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        for name, argv in self._argvs().items():
            if inner != argv:
                continue
            if authorization:
                return CommandResult(0, "")
            self.reads.append(name)
            self._count[name] = self._count.get(name, 0) + 1
            if name in self.failing:
                return CommandResult(1, "")
            if name in self.flapping and self._count[name] % 2 == 0:
                self.extras = {**self.extras, "late.txt": "f"}
            if name == "layout":
                return CommandResult(0, self.layout())
            if name == "state_database":
                return CommandResult(0, self.state_database())
        return super()._answer(command)
