"""An installed WordPress application as the inspection's fixed reads and result retrieval see
it (docs/wordpress.md#inspecting-wordpress).

The state read prints the real format from a small state, and the journal answers with the
record the real projection script produces from fixed command outputs, so the workflow tests
exercise the production grammar end to end. The fake establishes nothing about real WP-CLI,
MariaDB, find or journald behaviour; ``test_inspection_remote`` does.
"""

import json
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from discovery.ssh import CommandResult
from sites import native as site_native

from . import convention, execution, inspection_native
from .inspection_models import Operation

SALTED = "e" * 64
INSTALLED_PLUGINS = '[{"name":"akismet","status":"active","version":"5.7.2"}]'
CORE_OK = ("Success: WordPress installation verifies against checksums.\n", "")
PLUGIN_OK = "Success: Verified 1 of 1 plugins.\n"
PLUGIN_SKIPPED = "Success: Verified 0 of 1 plugins (1 skipped).\n"
Output = tuple[int, str, str]


def inventory_outputs(
    *,
    plugins: str = INSTALLED_PLUGINS,
    themes: str = '[{"name":"twentytwentysix","status":"active","version":"1.0"}]',
    installed: int = 0,
    version: str = "7.1.3",
) -> dict[str, Output]:
    return {
        "installed": (installed, "", ""),
        "version": (0, f"{version}\n", ""),
        "plugins": (0, plugins, ""),
        "themes": (0, themes, ""),
    }


def core_outputs(status: int, out: str, err: str) -> dict[str, Output]:
    return {"core": (status, out, err)}


def plugin_outputs(**results: Output) -> dict[str, Output]:
    return {f"pv.{slug}": result for slug, result in results.items()}


def project(operation: str, outputs: dict[str, Output], *arguments: str) -> str:
    """The record line the production projection prints for these command outputs."""
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        for name, (status, out, err) in outputs.items():
            (base / f"{name}.rc").write_text(f"{status}\n")
            (base / f"{name}.out").write_text(out)
            (base / f"{name}.err").write_text(err)
        done = subprocess.run(  # noqa: S603 - the production projection on the tests' own files
            [
                sys.executable,
                "-I",
                "-c",
                inspection_native.PROJECTION,
                directory,
                operation,
                *arguments,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    return done.stdout.strip()


def default_record(operation: str, slugs: tuple[str, ...] = ("akismet",)) -> str:
    """A healthy application's record for ``operation``."""
    if operation == Operation.INSPECT:
        return project(operation, inventory_outputs())
    if operation == Operation.CORE:
        return project(operation, core_outputs(0, *CORE_OK), "7.1.3")
    return project(operation, plugin_outputs(**dict.fromkeys(slugs, (0, PLUGIN_OK, ""))), *slugs)


def _schema(database: str) -> str:
    rows = [
        f"C\t{database}\twp_{table}\t{len(columns)}\n"
        for table, columns in convention.CORE_TABLES.items()
    ]
    rows.append(f"W\t{database}\t{len(convention.CORE_TABLES)}\n")
    return "".join(rows)


@dataclass
class InspectionServer:
    """One site's installed application and the journal of its inspection runs."""

    identifier: str = "shop"
    canonical: str = "www.shop.example.com"
    version: str = "7.1.3"
    loader: str = "exact"
    configuration: str = "supported"
    packaged: int = 0
    complete_schema: bool = True
    siteurl: str = ""
    plugins: dict[str, str] = field(default_factory=lambda: {"akismet": "d"})
    mu_plugins: dict[str, str] = field(default_factory=lambda: {"loader.php": "a" * 64})
    dropins: dict[str, str] = field(default_factory=dict)
    themes: tuple[str, ...] = ("twentytwentysix",)
    # Reads that fail, by name: "state" or "journal".
    failing: set[str] = field(default_factory=set)
    # The record the journal holds, per operation; the default is the healthy record.
    records: dict[str, str] = field(default_factory=dict)
    # What the retrieval prints for the journal: "ok", "empty", "error" or "duplicate".
    journal: str = "ok"
    residue: bool = False
    # The retrieval is not in its form.
    garbled: bool = False
    # The reads that changed the state when they ran.
    flapping: bool = False
    reads: list[str] = field(default_factory=list)
    retrievals: list[str] = field(default_factory=list)
    _count: int = 0

    def answer(self, remote: object) -> None:
        answers = remote.answers  # type: ignore[attr-defined]
        if self._answer not in answers:
            answers.insert(0, self._answer)

    def state(self) -> str:
        database = f"s{self.identifier}"
        url = self.siteurl or f"https://{self.canonical}"
        lines = [
            f"config loader {self.loader}",
            f"config configuration {self.configuration}",
            *(["config digest " + SALTED] if self.configuration == "supported" else []),
            f"config version {self.version}",
            f"package {self.packaged}",
        ]
        rows = sorted(_schema(database).splitlines())
        lines += [f"schema {row}" for row in (rows if self.complete_schema else rows[1:])]
        lines += [f"option home\t{url}", f"option siteurl\t{url}"]
        lines += [
            f"entry plugins {kind} s{self.identifier} {name}"
            for name, kind in sorted(self.plugins.items())
        ]
        lines.append("end plugins")
        lines += [
            f"entry mu-plugins f s{self.identifier} {name}" for name in sorted(self.mu_plugins)
        ]
        lines.append("end mu-plugins")
        lines += [f"entry themes d s{self.identifier} {name}" for name in sorted(self.themes)]
        lines.append("end themes")
        lines += [f"dropin {name} {value}" for name, value in sorted(self.dropins.items())]
        lines += [f"mufile {name} {value}" for name, value in sorted(self.mu_plugins.items())]
        return "".join(f"{line}\n" for line in lines)

    def owns(self, command: str) -> bool:
        """Whether ``command`` is one of the inspection's own fixed reads, which only read."""
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        if inner == shlex.join(inspection_native.state_argv(self.identifier)):
            return True
        return self._retrieval(command) is not None

    def _retrieval(self, command: str) -> tuple[str, str] | None:
        """The invocation and unit of a retrieval ``command``, or ``None``."""
        found = re.fullmatch(r"printf '%s\\n' ([0-9a-f]{32}) \| (?:sudo -n )?(.+)", command)
        if found is None:
            return None
        unit = re.search(r"_SYSTEMD_UNIT=(barectl-apply-[0-9a-f]{32}\.service)", found[2])
        if unit is None or not found[2].startswith(f"{site_native.SHELL} -c "):
            return None
        return found[1], unit[1]

    def _answer(self, command: str) -> CommandResult | None:
        authorization = command.startswith("sudo -n -l ")
        inner = command.removeprefix("sudo -n -l ").removeprefix("sudo -n ")
        if inner == shlex.join(inspection_native.state_argv(self.identifier)):
            if authorization:
                return CommandResult(0, "")
            return self._state()
        if authorization and re.search(r"_SYSTEMD_UNIT=barectl-apply-", inner):
            return CommandResult(0, "")
        found = self._retrieval(command)
        if found is not None:
            return self._journal(*found)
        return None

    def _state(self) -> CommandResult:
        self.reads.append("state")
        self._count += 1
        if "state" in self.failing:
            return CommandResult(1, "")
        if self.flapping and self._count % 2 == 0:
            self.plugins = {**self.plugins, "late-plugin": "d"}
        return CommandResult(0, self.state())

    def record(self) -> str:
        """The record the journal holds for the run being retrieved."""
        from .inspection_models import RunWordpressInspection

        operation = RunWordpressInspection.objects.get().operation
        slugs = tuple(sorted(name for name, kind in self.plugins.items() if kind == "d"))
        return self.records.get(operation) or default_record(operation, slugs)

    def _journal(self, invocation: str, unit: str) -> CommandResult:
        self.retrievals.append(unit)
        if "journal" in self.failing:
            return CommandResult(1, "")
        if self.garbled:
            return CommandResult(0, "nonsense\n")
        record = self.record()
        entry = json.dumps(
            {
                "MESSAGE": record
                if record.startswith(execution.RECORD_MARKER)
                else f"{execution.RECORD_MARKER} {record}",
                "_SYSTEMD_UNIT": unit,
                "_SYSTEMD_INVOCATION_ID": invocation,
                "_TRANSPORT": "stdout",
                "_UID": "0",
            }
        )
        header = f"residue {'present' if self.residue else 'absent'}\n"
        if self.journal == "error":
            return CommandResult(0, header + "journal error\n")
        body = {"ok": f"{entry}\n", "duplicate": f"{entry}\n{entry}\n", "empty": ""}[self.journal]
        return CommandResult(0, header + "journal ok\n" + body)
