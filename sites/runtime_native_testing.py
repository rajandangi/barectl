"""Run the actual switch control flow against bounded native-process fixtures."""

import ast
import io
import subprocess
from contextlib import redirect_stdout
from dataclasses import dataclass
from functools import partial
from types import SimpleNamespace

from . import runtime_native

CANARY = "private-password-token-config-output"


@dataclass(frozen=True)
class SwitchResult:
    status: int
    output: str
    calls: list[tuple[list[str], dict[str, object]]]


def process(
    scenario: str,
    files: dict[str, bytes],
    calls: list[tuple[list[str], dict[str, object]]],
    argv: list[str],
    **options: object,
) -> subprocess.CompletedProcess[bytes]:
    calls.append((argv, options))
    output, status = b"", 0
    selected = files["site"] == b"new-router"
    if scenario == "fpm-check-error" and len(calls) == 1:
        status = 78
    if argv[0] == "/usr/bin/curl":
        if "/probe-" in argv[-1]:
            branch = "8.4" if selected else "8.3"
            output = f"runtime-token {branch} 1001 1001 1".encode()
            if scenario == "both-tls-errors" or (
                selected and scenario in ("target-tls-error", "restore-read-error")
            ):
                status, output = 60, CANARY.encode()
            elif selected and scenario == "identity-error":
                output = CANARY.encode()
        else:
            output = CANARY.encode() if selected and scenario == "invalid-http" else b"200"
    return subprocess.CompletedProcess(argv, status, stdout=output, stderr=CANARY.encode())


def run_switch(scenario: str, *, program: str | None = None) -> SwitchResult:
    tree = ast.parse(runtime_native._PROGRAM if program is None else program)
    start = next(
        index
        for index, node in enumerate(tree.body)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "new_created" for target in node.targets
        )
    )
    definitions = [
        node
        for node in tree.body[:start]
        if isinstance(node, ast.FunctionDef)
        and node.name in ("command", "served", "mark", "diagnostic")
    ]
    files = {"site": b"old-router", "oldpool": b"old-pool"}
    calls: list[tuple[list[str], dict[str, object]]] = []
    clock = iter(range(100))
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001)

    def stage(path: str, data: bytes) -> None:
        if path in files:
            raise ValueError(CANARY)
        files[path] = data

    def read(path: str) -> tuple[bytes, tuple[int, int]]:
        if scenario == "restore-read-error" and path == "newpool":
            raise OSError(CANARY)
        return files[path], (1, 1)

    def replace(path: str, expected: bytes, data: bytes) -> None:
        if scenario == "publication-error" and data == b"new-router":
            raise OSError(CANARY)
        if files[path] != expected:
            raise ValueError(CANARY)
        files[path] = data

    namespace: dict[str, object] = {
        "c": {
            "branch": "8.4",
            "old_branch": "8.3",
            "names": ("shop.test",),
            "canonical": "shop.test",
            "wordpress": True,
            "https": True,
            "database_engine": "mariadb",
            "token": "token",
        },
        "account": account,
        "site": "site",
        "oldpool": "oldpool",
        "newpool": "newpool",
        "oldsite": b"old-router",
        "newsite": b"new-router",
        "oldcontent": b"old-pool",
        "newcontent": b"new-pool",
        "old_branch": "8.3",
        "new_branch": "8.4",
        "current_phase": "",
        "process_exit": None,
        "probe_result": {},
        "stage": stage,
        "read": read,
        "replace": replace,
        "probe_owned": lambda: None,
        "cleanup_probe": lambda: None,
        "os": SimpleNamespace(unlink=files.pop),
        "subprocess": SimpleNamespace(
            run=partial(process, scenario, files, calls),
            DEVNULL=subprocess.DEVNULL,
            SubprocessError=subprocess.SubprocessError,
        ),
        "sys": SimpleNamespace(exit=lambda status: (_ for _ in ()).throw(SystemExit(status))),
        "time": SimpleNamespace(monotonic=lambda: float(next(clock)), sleep=lambda _seconds: None),
    }
    output = io.StringIO()
    status = 0
    with redirect_stdout(output):
        try:
            exec(  # noqa: S102 - actual repository-owned native control flow, isolated fixtures
                compile(
                    ast.Module(body=[*definitions, *tree.body[start:]], type_ignores=[]),
                    "native-switch-control",
                    "exec",
                ),
                namespace,
            )
        except SystemExit as stopped:
            if not isinstance(stopped.code, int):
                raise AssertionError("Native exit was not an integer") from stopped
            status = stopped.code
    return SwitchResult(status, output.getvalue(), calls)
