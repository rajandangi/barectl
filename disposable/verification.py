"""Durable controller verification evidence; never an authority for skipping checks."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def revision() -> str:
    result = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def input_revision() -> dict[str, str]:
    source = subprocess.run(
        ["/usr/bin/git", "diff", "--binary", "HEAD"], capture_output=True, check=False
    )
    index = subprocess.run(
        ["/usr/bin/git", "ls-files", "--stage", "-z"], capture_output=True, check=False
    )
    working = subprocess.run(["/usr/bin/git", "diff", "--binary"], capture_output=True, check=False)
    untracked = subprocess.run(
        ["/usr/bin/git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True,
        check=False,
    )
    return {
        "revision": revision(),
        "index_sha256": hashlib.sha256(index.stdout).hexdigest()
        if index.returncode == 0
        else "unknown",
        "working_diff_sha256": hashlib.sha256(working.stdout).hexdigest()
        if working.returncode == 0
        else "unknown",
        "tracked_diff_sha256": hashlib.sha256(source.stdout).hexdigest()
        if source.returncode == 0
        else "unknown",
        "untracked_paths_sha256": hashlib.sha256(untracked.stdout).hexdigest()
        if untracked.returncode == 0
        else "unknown",
        "untracked_sources": ("present" if untracked.stdout else "none")
        if untracked.returncode == 0
        else "unknown",
    }


def record(
    path: Path,
    name: str,
    command: list[str],
    log: Path,
    code: int,
    seconds: float,
    inputs: dict[str, str],
    *,
    reveal_command: bool = False,
) -> None:
    current = input_revision()
    identity_keys = ("index_sha256", "working_diff_sha256", "untracked_paths_sha256")
    entry = {
        "name": name,
        "inputs": inputs,
        "source_unchanged": inputs["revision"] != "unknown"
        and inputs["untracked_sources"] == "none"
        and current["revision"] != "unknown"
        and current["untracked_sources"] == "none"
        and all(value != "unknown" for value in (*inputs.values(), *current.values()))
        and all(inputs[key] == current[key] for key in identity_keys),
        "command": command if reveal_command else command[:1],
        "command_redacted": not reveal_command,
        "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
        "exit_status": code,
        "result": "passed" if code == 0 else "failed",
        "duration_seconds": round(seconds, 3),
        "log": str(log.resolve()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(entry, indent=2) + "\n")
    temporary.replace(path)


def execute(log: Path, command: list[str], *, reveal_command: bool = False) -> int:
    inputs = input_revision()
    started = time.monotonic()
    with log.open("wb") as output:
        result = subprocess.run(  # noqa: S603 - explicit operator command, no shell
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    code = result.returncode if result.returncode >= 0 else 128 - result.returncode
    record(
        log.with_suffix(log.suffix + ".json"),
        log.stem,
        command,
        log,
        code,
        time.monotonic() - started,
        inputs,
        reveal_command=reveal_command,
    )
    status = log.with_suffix(log.suffix + ".status")
    temporary = status.with_suffix(".tmp")
    temporary.write_text(f"{code}\n")
    temporary.replace(status)
    return code


def process_state(pid: int) -> tuple[str, str]:
    result = subprocess.run(  # noqa: S603 - fixed ps probe
        ["/bin/ps", "-p", str(pid), "-o", "stat=", "-o", "lstart="],
        capture_output=True,
        text=True,
        check=False,
    )
    fields = result.stdout.strip().split(maxsplit=1)
    return (fields[0], fields[1]) if result.returncode == 0 and len(fields) == 2 else ("", "")


def alive(pid: int, log: Path) -> bool:
    state, started = process_state(pid)
    identity = log.with_suffix(log.suffix + ".identity")
    return (
        bool(state)
        and not state.startswith("Z")
        and identity.exists()
        and identity.read_text() == started
    )


def claim(log: Path, pid: int) -> None:
    log.with_suffix(log.suffix + ".identity").write_text(process_state(pid)[1])
    temporary = log.with_suffix(log.suffix + ".pid.tmp")
    temporary.write_text(str(pid))
    temporary.replace(log.with_suffix(log.suffix + ".pid"))


def follow(log: Path, seconds: float | None) -> int:
    status = log.with_suffix(log.suffix + ".status")
    pid_file = log.with_suffix(log.suffix + ".pid")
    deadline = None if seconds is None else time.monotonic() + seconds
    while not status.exists():
        if not pid_file.exists() or not alive(int(pid_file.read_text()), log):
            print(f"Verification process is not running; complete evidence is unavailable: {log}")  # noqa: T201 - CLI result
            return 1
        if deadline is not None and time.monotonic() >= deadline:
            print(f"Still running; use follow to retain the parent session: {log}")  # noqa: T201 - CLI result
            return 124
        time.sleep(0.1)
    print(f"Full log: {log}")  # noqa: T201 - CLI result
    if log.exists():
        lines = log.read_text(errors="replace").splitlines()
        failures = [
            line for line in lines if line.startswith(("FAIL:", "ERROR:", "AssertionError"))
        ]
        print("\n".join(failures + lines[-15:]))  # noqa: T201 - CLI result
    return int(status.read_text())


BUILD_GATES = {"controller-fast", "fast-validators", "browser", "native"}


def build_command(log: Path, env_file: str) -> list[str]:
    """Expand repository-owned gates; only these known commands expose their argv."""
    if log.stem == "controller-fast":
        return [
            "uv",
            "run",
            "--env-file",
            env_file,
            "python",
            "manage.py",
            "test",
            "--exclude-tag",
            "browser",
            "--exclude-tag",
            "scenario",
            "--parallel",
        ]
    if log.stem == "browser":
        return [
            "uv",
            "run",
            "--env-file",
            env_file,
            "python",
            "manage.py",
            "test",
            "--tag",
            "browser",
        ]
    runner = str(Path.cwd() / "docker/disposable-server/run-scenarios.sh")
    if log.stem == "fast-validators":
        return [
            "env",
            f"BARECTL_DISPOSABLE_LOGS={log.parent / 'validator-logs'}",
            runner,
            "--env-file",
            env_file,
            "--",
            "--validators",
            "--no-lock",
        ]
    if log.stem == "native":
        return [runner, "--env-file", env_file, "--", "--no-lock"]
    raise ValueError("Unknown repository build gate.")


def valid_evidence(entry: dict[str, object]) -> bool:
    """Validate command and source identities without promoting unknown evidence."""
    command = entry.get("command")
    redacted = entry.get("command_redacted")
    digest = entry.get("command_sha256")
    inputs = entry.get("inputs")
    duration = entry.get("duration_seconds")
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(argument, str) for argument in command)
        or not isinstance(redacted, bool)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not isinstance(inputs, dict)
        or not isinstance(entry.get("source_unchanged"), bool)
        or not isinstance(duration, (int, float))
        or not 0 <= duration < float("inf")
    ):
        return False
    if redacted and len(command) != 1:
        return False
    if not redacted and hashlib.sha256(json.dumps(command).encode()).hexdigest() != digest:
        return False
    fields = (
        "index_sha256",
        "working_diff_sha256",
        "tracked_diff_sha256",
        "untracked_paths_sha256",
    )
    for field in fields:
        value = inputs.get(field)
        if not isinstance(value, str) or (
            value != "unknown"
            and (
                len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            )
        ):
            return False
    if not isinstance(inputs.get("revision"), str) or inputs.get("untracked_sources") not in {
        "none",
        "present",
        "unknown",
    }:
        return False
    return not entry["source_unchanged"] or (
        all(value != "unknown" for value in inputs.values())
        and inputs["untracked_sources"] == "none"
    )


def aggregate(directory: Path) -> int:
    """Incomplete, malformed or conflicting completion evidence fails closed."""
    entries = []
    complete = True
    for path in sorted(directory.glob("*.log.json")):
        try:
            entry = json.loads(path.read_text())
            code = entry["exit_status"]
            status = path.with_suffix(".status").read_text().strip()
            valid = (
                valid_evidence(entry)
                and isinstance(code, int)
                and not isinstance(code, bool)
                and 0 <= code <= 255
                and status == str(code)
                and entry["name"] == path.name.removesuffix(".log.json")
                and entry["result"] == ("passed" if code == 0 else "failed")
                and Path(entry["log"]).resolve() == path.with_suffix("").resolve()
                and Path(entry["log"]).is_file()
            )
            complete = complete and valid
            entries.append(entry)
        except OSError, ValueError, TypeError, KeyError:
            complete = False
    complete = (
        complete
        and len(entries) == len(BUILD_GATES)
        and {entry.get("name") for entry in entries} == BUILD_GATES
    )
    (directory / "ledger.json").write_text(
        json.dumps({"version": 1, "complete": complete, "gates": entries}, indent=2) + "\n"
    )
    return 0


def prepare_command(mode: str, log: Path, remaining: list[str]) -> tuple[str, list[str], bool]:
    if mode != "build":
        return mode, remaining, False
    if len(remaining) != 1:
        raise ValueError("Expected build LOG ENV_FILE.")
    return "run", ["--", *build_command(log, remaining[0])], True


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    if len(args) < 2:
        raise ValueError("Expected run/start/follow/wait, log, and command or deadline.")
    mode, raw_log, *remaining = args
    log = Path(raw_log).resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    if mode == "worker":
        return execute(log, remaining[1:])
    if mode == "ledger":
        return aggregate(log)
    mode, remaining, reveal_command = prepare_command(mode, log, remaining)
    if mode in {"run", "start"}:
        if not remaining or remaining[0] != "--" or len(remaining) < 2:
            raise ValueError("Expected -- COMMAND after log.")
        pid_file = log.with_suffix(log.suffix + ".pid")
        if pid_file.exists() and alive(int(pid_file.read_text()), log):
            raise ValueError("A verification process already owns this log.")
        log.with_suffix(log.suffix + ".status").unlink(missing_ok=True)
        log.with_suffix(log.suffix + ".json").unlink(missing_ok=True)
        if mode == "start":
            with log.with_suffix(log.suffix + ".launcher").open("wb") as launcher:
                child = subprocess.Popen(  # noqa: S603 - this module with operator argv
                    [
                        sys.executable,
                        "-m",
                        "disposable.verification",
                        "worker",
                        str(log),
                        *remaining,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=launcher,
                    stderr=launcher,
                    start_new_session=True,
                )
            claim(log, child.pid)
            return 0
        claim(log, os.getpid())
        execute(log, remaining[1:], reveal_command=reveal_command)
        return follow(log, None)
    if mode == "follow":
        return follow(log, None)
    if mode == "wait":
        return follow(log, float(remaining[0]) if remaining else 540)
    raise ValueError("Unknown verification mode.")


if __name__ == "__main__":
    raise SystemExit(main())
