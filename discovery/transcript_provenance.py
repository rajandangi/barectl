"""Verified capture receipts and conservative state dependencies (docs/quality.md)."""

import ast
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

from . import recorded, source_manifest

PASS = source_manifest.REPOSITORY / ".quiet-run" / "transcript-pass.json"
EXCLUDED = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
        "migrations",
        ".quiet-run",
        "staticfiles",
        "exports",
    }
)
OMITTED = "security/bodies/sign_in.sh"
AUDITED_STATE = "ubuntu-24.04"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _python_files(root: Path) -> Iterator[Path]:
    for directory, children, files in root.walk():
        children[:] = [
            name for name in children if name not in EXCLUDED and not name.startswith(".")
        ]
        for name in files:
            if name.endswith(".py"):
                yield directory / name


def inputs() -> dict[str, str]:
    root = source_manifest.REPOSITORY
    paths = set(source_manifest.SOURCES)
    for path in _python_files(root):
        relative = path.relative_to(root)
        if EXCLUDED & set(relative.parts):
            continue
        if (path.name.startswith("test_") or "tests" in relative.parts) and relative.parts[
            0
        ] != "disposable":
            continue
        paths.add(relative.as_posix())
    paths.update(
        path.relative_to(root).as_posix()
        for path in (root / "docker/disposable-server").rglob("*")
        if path.is_file() and not EXCLUDED & set(path.relative_to(root).parts)
    )
    paths.add("uv.lock")
    paths.add("scripts/record-all-transcripts.sh")
    return {name: digest(root / name) for name in sorted(paths)}


def _resource_consumers_proven() -> bool:
    """Only this raw shell resource is omitted, never its reader or provisioning inputs."""
    root = source_manifest.REPOSITORY
    consumers: set[str] = set()
    for path in _python_files(root):
        relative = path.relative_to(root)
        if EXCLUDED & set(relative.parts) or path.name.startswith("test_"):
            continue
        if relative.as_posix() in {
            "discovery/source_manifest.py",
            "discovery/transcript_provenance.py",
        }:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError, UnicodeDecodeError:
            return False
        strings = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        if any("sign_in.sh" in value for value in strings):
            consumers.add(relative.as_posix())
        if "security.bodies" in strings:
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "joinpath"
                    and (not node.args or not isinstance(node.args[0], ast.Constant))
                ):
                    return False
    return consumers == {"security/sign_in.py"}


AUDITED_INPUT_DIGEST = "25ed217a5eb8cc95b36afd98438198503a0a1bb36eaa18ac3fc89d10efb4a933"


def audit_digest(values: dict[str, str]) -> str:
    protected = {
        name: value
        for name, value in values.items()
        if name
        not in {
            OMITTED,
            "discovery/transcript_provenance.py",
        }
    }
    return hashlib.sha256(json.dumps(protected, sort_keys=True).encode()).hexdigest()


def audited_exclusion() -> bool:
    return audit_digest(inputs()) == AUDITED_INPUT_DIGEST and _resource_consumers_proven()


def affected(
    states: tuple[str, ...], previous: dict[str, str], current: dict[str, str], *, proof: bool
) -> tuple[str, ...]:
    changes = {
        name for name in previous.keys() | current.keys() if previous.get(name) != current.get(name)
    }
    if not changes:
        return ()
    return tuple(
        state for state in states if state != AUDITED_STATE or not proof or changes != {OMITTED}
    )


def _object(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text())
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"Invalid capture metadata: {path.name}")
    return value


def _strings(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise ValueError("Invalid capture digest map")
    return value


def _save(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _state_path(state: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", state) or ".." in state:
        raise ValueError("Invalid transcript state name")
    return recorded.TRANSCRIPTS / f"{state}.json"


def _state_hashes(states: tuple[str, ...]) -> dict[str, str]:
    return {state: digest(_state_path(state)) for state in states}


def plan(states: tuple[str, ...]) -> tuple[str, ...]:
    manifest = _object(source_manifest.MANIFEST)
    previous = manifest.get("capture_inputs")
    pins = manifest.get("capture_pins")
    hashes = manifest.get("capture_states")
    if previous is None or pins != recorded.current_pins() or not isinstance(hashes, dict):
        return states
    selected = set(affected(states, _strings(previous), inputs(), proof=audited_exclusion()))
    for state in states:
        path = _state_path(state)
        if not path.is_file() or hashes.get(state) != digest(path):
            selected.add(state)
    return tuple(state for state in states if state in selected)


def begin(states: tuple[str, ...], *, resume: bool, incremental: bool) -> tuple[str, ...]:
    if not states or len(set(states)) != len(states):
        raise ValueError("A capture pass needs distinct states")
    for state in states:
        _state_path(state)
    current, pins = inputs(), recorded.current_pins()
    if resume:
        document = _object(PASS)
        if (
            document.get("inputs") != current
            or document.get("pins") != pins
            or document.get("states") != list(states)
        ):
            raise ValueError("Capture inputs changed; start a new pass")
        completed = _strings(document.get("completed"))
        for state, value in completed.items():
            if state not in states or digest(_state_path(state)) != value:
                raise ValueError("A completed capture changed; start a new pass")
        return tuple(state for state in states if state not in completed)
    selected = plan(states) if incremental else states
    inherited = _state_hashes(tuple(state for state in states if state not in selected))
    _save(
        PASS,
        {
            "inputs": current,
            "pins": pins,
            "states": list(states),
            "selected": list(selected),
            "completed": inherited,
        },
    )
    return selected


def start(state: str) -> None:
    document = _object(PASS)
    if document.get("inputs") != inputs() or document.get("pins") != recorded.current_pins():
        raise ValueError("Capture inputs changed")
    path = _state_path(state)
    document["started"] = {
        "state": state,
        "mtime": path.stat().st_mtime_ns if path.exists() else None,
    }
    _save(PASS, document)


def complete(state: str) -> None:
    document = _object(PASS)
    if document.get("inputs") != inputs() or document.get("pins") != recorded.current_pins():
        raise ValueError("Capture inputs changed during recording")
    started = document.get("started")
    path = _state_path(state)
    if (
        not isinstance(started, dict)
        or started.get("state") != state
        or started.get("mtime") == path.stat().st_mtime_ns
    ):
        raise ValueError("The recorder did not write this state")
    transcript = recorded.load(state)
    if dict(transcript.pins) != recorded.current_pins():
        raise ValueError("Captured pins do not match")
    completed = _strings(document.get("completed"))
    completed[state] = digest(path)
    document["completed"] = completed
    document.pop("started", None)
    _save(PASS, document)


def finish() -> None:
    document = _object(PASS)
    states = document.get("states")
    if not isinstance(states, list) or not all(isinstance(state, str) for state in states):
        raise ValueError("Invalid capture states")
    completed = _strings(document.get("completed"))
    if (
        document.get("inputs") != inputs()
        or document.get("pins") != recorded.current_pins()
        or completed != _state_hashes(tuple(states))
    ):
        raise ValueError("Incomplete or stale capture pass; resume it before finalizing")
    source_manifest.write(
        capture={
            "capture_inputs": document["inputs"],
            "capture_pins": document["pins"],
            "capture_states": completed,
        }
    )


def main() -> int:
    args = sys.argv[1:]
    try:
        if not args:
            raise ValueError("A capture command is required")
        action, *values = args
        if action == "explain":
            manifest = _object(source_manifest.MANIFEST)
            previous = manifest.get("capture_inputs")
            current = inputs()
            old = _strings(previous) if previous is not None else {}
            document = {
                "required": plan(tuple(values) or recorded.stored()),
                "changed_inputs": sorted(
                    name
                    for name in old.keys() | current.keys()
                    if old.get(name) != current.get(name)
                ),
                "legacy_full_capture": previous is None,
                "pins_changed": manifest.get("capture_pins") != recorded.current_pins(),
                "audited_exclusion": audited_exclusion(),
            }
            print(json.dumps(document, indent=2))  # noqa: T201
        elif action in {"plan", "begin", "resume", "affected"}:
            states = tuple(values) or recorded.stored()
            selected = (
                plan(states)
                if action in {"plan", "affected"}
                else begin(states, resume=action == "resume", incremental=False)
            )
            print("\n".join(selected))  # noqa: T201
        elif action == "incremental":
            print("\n".join(begin(tuple(values), resume=False, incremental=True)))  # noqa: T201
        elif action == "start" and len(values) == 1:
            start(values[0])
        elif action == "complete" and len(values) == 1:
            complete(values[0])
        elif action == "finish" and not values:
            finish()
        else:
            raise ValueError("Invalid capture command")
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
