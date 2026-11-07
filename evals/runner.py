"""Run the small, pinned benchmark suite that measures a harness change (docs/agents/evals.md).

The runner does not call a model. It prepares an isolated worktree for one arm, then grades
the result after the operator or agent has run the case. Keeping the model invocation out of
the runner makes the setup honest: the same printed command works with any coding agent.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

REPOSITORY: Final = Path(__file__).resolve().parent.parent
DEFAULT_HOME: Final = Path.home() / ".local/share/barectl/evals"
DEFAULT_WORKTREES: Final = REPOSITORY.parent / "barectl-worktrees"
RESULT_KEYS: Final = (
    "wall_minutes",
    "oracle_failed",
    "must_fix",
    "judgement",
    "diff_lines",
    "checks_failed",
)


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    kind: str
    base: str
    oracle_ref: str
    oracle_tests: tuple[str, ...]
    checks: tuple[str, ...]
    budget_minutes: int
    prompt: Path
    ground_truth: tuple[str, ...]
    harness_skills: tuple[str, ...]


def _object(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{path} is not a JSON object.")
    return {str(key): item for key, item in value.items()}


def _text(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string.")
    return value


def _strings(document: dict[str, object], key: str) -> tuple[str, ...]:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings.")
    return tuple(value)


def _integer(document: dict[str, object], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int):
        raise ValueError(f"{key} must be an integer.")
    return value


def eval_home() -> Path:
    """Cases, prompts and results stay local; only this runner is tracked in git."""
    return Path(os.environ.get("BARECTL_EVAL_HOME", DEFAULT_HOME))


def load_case(identifier: str) -> Case:
    document = _object(eval_home() / "cases" / f"{identifier}.json")
    return Case(
        id=_text(document, "id"),
        title=_text(document, "title"),
        kind=_text(document, "kind"),
        base=_text(document, "base"),
        oracle_ref=_text(document, "oracle_ref"),
        oracle_tests=_strings(document, "oracle_tests"),
        checks=_strings(document, "checks"),
        budget_minutes=_integer(document, "budget_minutes"),
        prompt=eval_home() / _text(document, "prompt"),
        ground_truth=_strings(document, "ground_truth"),
        harness_skills=_strings(document, "harness_skills"),
    )


def case_ids() -> tuple[str, ...]:
    return tuple(sorted(path.stem for path in (eval_home() / "cases").glob("*.json")))


def _worktree(case: Case, arm: str) -> Path:
    root = Path(os.environ.get("BARECTL_EVAL_WORKTREES", DEFAULT_WORKTREES))
    return root / f"eval-{case.id}-{arm}"


def _results(case: Case) -> Path:
    root = eval_home() / "results"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{case.id}.jsonl"


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    # The case file owns the argv; it is not user input.
    return subprocess.run(  # noqa: S603
        command, cwd=cwd, check=False, capture_output=True, text=True
    )


def _ref(case: Case, arm: str, ref: str) -> str:
    if arm == "baseline":
        return case.base
    if ref:
        return ref
    return "HEAD"


def _append(case: Case, record: dict[str, object]) -> None:
    target = _results(case)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"Recorded {case.id} {record.get('arm')} in {target}")


def _install_harness(target: Path, harness: Path, skills: tuple[str, ...]) -> int:
    for skill in skills:
        source = harness / skill
        if not source.is_dir():
            print(f"{source} is not a skill directory.", file=sys.stderr)
            return 2
        destination = target / ".opencode" / "skills" / skill
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
    return 0


def prepare(case: Case, arm: str, ref: str, harness: Path | None) -> int:
    target = _worktree(case, arm)
    revision = _ref(case, arm, ref)
    if target.exists():
        print(f"{target} already exists; reusing it at {revision}.")
    else:
        result = _run(["git", "worktree", "add", "--detach", str(target), revision], cwd=REPOSITORY)
        if result.returncode != 0:
            print(result.stderr.strip(), file=sys.stderr)
            return result.returncode
        setup = _run(["scripts/worktree-setup.sh"], cwd=target)
        if setup.returncode != 0:
            print(setup.stdout[-4000:], file=sys.stderr)
            print(setup.stderr[-4000:], file=sys.stderr)
            return setup.returncode
    if harness is not None:
        installed = _install_harness(target, harness, case.harness_skills)
        if installed != 0:
            return installed
    shutil.copyfile(case.prompt, target / ".eval-prompt.md")
    (target / ".eval-start").write_text(datetime.now(UTC).isoformat(), encoding="utf-8")
    print(f"Worktree: {target}")
    print(f"Revision: {revision}")
    if case.harness_skills:
        source = harness if harness is not None else Path("the global skills")
        print(f"Harness: {source} ({', '.join(case.harness_skills)})")
    print("Run the case with your coding agent, from that worktree:")
    print()
    print(
        "  opencode run --format json --auto --title "
        f'"eval {case.id} {arm}" "$(cat .eval-prompt.md)"'
    )
    print()
    print("Then grade the result:")
    print()
    print(f"  uv run python -m evals.runner grade {case.id} --arm {arm} --must-fix N --judgement N")
    if case.ground_truth:
        print(
            f"  # review case: add --found {','.join(case.ground_truth[:2])},... "
            "and --false-positives N"
        )
    return 0


def _copy_oracle(case: Case, target: Path) -> int:
    for module in case.oracle_tests:
        relative = module.replace(".", "/") + ".py"
        result = _run(["git", "show", f"{case.oracle_ref}:{relative}"], cwd=REPOSITORY)
        if result.returncode != 0:
            print(f"Cannot read {relative} from {case.oracle_ref}.", file=sys.stderr)
            print(result.stderr.strip(), file=sys.stderr)
            return result.returncode
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.stdout, encoding="utf-8")
    return 0


def _diff_lines(target: Path) -> int:
    _run(["git", "add", "-A"], cwd=target)
    result = _run(["git", "diff", "--cached", "--numstat"], cwd=target)
    total = 0
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            total += int(parts[0]) + int(parts[1])
    return total


def _elapsed_minutes(target: Path, override: float | None) -> float:
    if override is not None:
        return override
    start = target / ".eval-start"
    if not start.exists():
        raise ValueError(f"{target} has no .eval-start; run prepare first.")
    started = datetime.fromisoformat(start.read_text(encoding="utf-8"))
    return round((datetime.now(UTC) - started).total_seconds() / 60, 1)


def grade(
    case: Case,
    arm: str,
    *,
    minutes: float | None,
    must_fix: int,
    judgement: int,
    found: tuple[str, ...],
    false_positives: int,
) -> int:
    target = _worktree(case, arm)
    if not target.exists():
        print(f"{target} does not exist; run prepare first.", file=sys.stderr)
        return 2
    elapsed = _elapsed_minutes(target, minutes)
    oracle_failed = 0
    checks_failed = 0
    if case.oracle_tests:
        copied = _copy_oracle(case, target)
        if copied != 0:
            return copied
        tests = _run(
            [
                "uv",
                "run",
                "--env-file",
                ".env",
                "python",
                "manage.py",
                "test",
                *case.oracle_tests,
                "--parallel",
            ],
            cwd=target,
        )
        oracle_failed = 0 if tests.returncode == 0 else 1
        if tests.returncode != 0:
            print(tests.stdout[-6000:], file=sys.stderr)
            print(tests.stderr[-2000:], file=sys.stderr)
    for command in case.checks:
        result = _run(command.split(), cwd=target)
        if result.returncode != 0:
            checks_failed += 1
            print(f"Check failed: {command}", file=sys.stderr)
            print(result.stdout[-2000:], file=sys.stderr)
    recall = None
    if found:
        hits = set(found) & set(case.ground_truth)
        recall = round(len(hits) / len(case.ground_truth), 3) if case.ground_truth else None
    record: dict[str, object] = {
        "case": case.id,
        "arm": arm,
        "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "wall_minutes": elapsed,
        "oracle_failed": oracle_failed,
        "must_fix": must_fix,
        "judgement": judgement,
        "diff_lines": _diff_lines(target),
        "checks_failed": checks_failed,
        "budget_minutes": case.budget_minutes,
    }
    if recall is not None:
        record["recall"] = recall
        record["false_positives"] = false_positives
    if elapsed > case.budget_minutes:
        record["over_budget"] = True
    _append(case, record)
    return 0 if oracle_failed == 0 and checks_failed == 0 else 1


def _latest(path: Path) -> dict[str, dict[str, object]]:
    latest: dict[str, dict[str, object]] = {}
    if not path.exists():
        return latest
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if isinstance(record, dict) and isinstance(record.get("arm"), str):
            latest[str(record["arm"])] = {str(key): value for key, value in record.items()}
    return latest


def compare(case: Case) -> int:
    latest = _latest(_results(case))
    if "baseline" not in latest or "candidate" not in latest:
        print("Record both a baseline and a candidate run first.")
        return 2
    baseline = latest["baseline"]
    candidate = latest["candidate"]
    print(f"# {case.id} {case.title}")
    print(f"baseline: {baseline.get('recorded_at')}  candidate: {candidate.get('recorded_at')}")
    print(f"{'metric':<20}{'baseline':>12}{'candidate':>12}{'delta':>10}")
    for key in (*RESULT_KEYS, "recall", "false_positives"):
        left = baseline.get(key)
        right = candidate.get(key)
        if left is None and right is None:
            continue
        delta = ""
        if isinstance(left, int | float) and isinstance(right, int | float):
            delta = f"{right - left:+.3g}"
        print(f"{key:<20}{left!s:>12}{right!s:>12}{delta:>10}")
    return 0


def listing() -> int:
    print(f"{'case':<12}{'kind':<15}{'base':<10}{'budget':>8}  title")
    for identifier in case_ids():
        case = load_case(identifier)
        print(f"{case.id:<12}{case.kind:<15}{case.base:<10}{case.budget_minutes:>7}m  {case.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m evals.runner")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("case")
    prepare_parser.add_argument("--arm", choices=("baseline", "candidate"), default="baseline")
    prepare_parser.add_argument("--ref", default="")
    prepare_parser.add_argument("--harness", type=Path)
    grade_parser = sub.add_parser("grade")
    grade_parser.add_argument("case")
    grade_parser.add_argument("--arm", choices=("baseline", "candidate"), default="candidate")
    grade_parser.add_argument("--minutes", type=float)
    grade_parser.add_argument("--must-fix", type=int, default=0)
    grade_parser.add_argument("--judgement", type=int, default=0)
    grade_parser.add_argument("--found", default="")
    grade_parser.add_argument("--false-positives", type=int, default=0)
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("case")
    arguments = parser.parse_args(argv)

    if arguments.command == "list":
        return listing()
    case = load_case(arguments.case)
    if arguments.command == "prepare":
        return prepare(case, arguments.arm, arguments.ref, arguments.harness)
    if arguments.command == "grade":
        found = tuple(item.strip() for item in arguments.found.split(",") if item.strip())
        return grade(
            case,
            arguments.arm,
            minutes=arguments.minutes,
            must_fix=arguments.must_fix,
            judgement=arguments.judgement,
            found=found,
            false_positives=arguments.false_positives,
        )
    return compare(case)


if __name__ == "__main__":
    raise SystemExit(main())
