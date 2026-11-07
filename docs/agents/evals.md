# Harness evals

Spec #507 showed that a retrospective can produce real harness fixes, but a fix is only an
improvement if a later run measurably does better. This document is the minimum loop that
answers that question without a new platform.

The unit is a **case**: a pinned task, two **arms** (baseline and candidate), and a small set
of **graders**. The **trace** is the agent's own JSON run plus its handoff. The **outcome**
is what the graders read, not the agent's summary.

## The loop

```text
past run / retro
      │
      ▼
candidate harness change
      │
      ├── prepare baseline worktree ──► run the case ──► grade
      │
      └── prepare candidate worktree ─► run the case ──► grade
                                                        │
                                                        ▼
                                              compare; keep or revert
```

A candidate is kept only when it improves its target metric and does not regress the other
cases. That rule is what makes the loop self-improving rather than self-flattering.

## Definitions

- **Case**: one pinned task. It names a base commit, a prompt, the oracle tests, the review
  ground truth (for a review case), and a wall-time budget.
- **Arm**: `baseline` (the harness before the change) or `candidate` (the harness with it).
  For a repository change, the arm is a git ref. For a skill change, the arm is a snapshot of
  the skill directory.
- **Grader**: deterministic first. The oracle test modules, `ruff`, `mypy`, and the
  repository's own fast gate. The LLM grader is the `code-review` skill or the local rubric
  at `$BARECTL_EVAL_HOME/judge.md`; it explains nuance and catches what tests cannot.
- **Trace**: `opencode run --format json` output plus the handoff note. Read selected traces;
  do not grade only the final summary.
- **Outcome**: the worktree state after the run, not what the agent says it did.

## What is tracked

The repository tracks only the runner (`evals/runner.py`) and this contract. Cases, prompts,
ground truth, results and traces stay local under `~/.local/share/barectl/evals/` by default;
set `BARECTL_EVAL_HOME` to choose another directory. A case is not committed because it names
a past ticket, a pinned commit and a local budget. A result is not committed because it is a
record of one machine's trial.

The workflow wrappers are tracked too: `.opencode/skills/barectl-implement-spec`,
`barectl-code-review` and `barectl-retro`. They call the global `implement-spec`, `code-review`
and `retro` skills and add the shared-seam, triage and eval rules for this repository. They
never edit the global skill files.

A case file is one JSON object:

```json
{
  "id": "example",
  "title": "one line",
  "kind": "implementation",
  "base": "<commit>",
  "oracle_ref": "<commit with the graded tests>",
  "oracle_tests": ["app.test_module"],
  "checks": ["uv run ruff check .", "uv run --env-file .env mypy"],
  "budget_minutes": 45,
  "prompt": "prompts/example.md",
  "ground_truth": [],
  "harness_skills": ["implement-spec"]
}
```

`oracle_tests` may be empty for a review case. `ground_truth` is a list of finding IDs for a
review case. `harness_skills` names the skill directories the arm installs into
`.opencode/skills`; leave it empty for a repository-only change.

The deterministic transcript-manifest case is
`discovery/test_source_manifest.py::ManifestMergeTests`, which runs in the fast gate; no
agent is involved.

## Running a case

Put the case and its prompt under `$BARECTL_EVAL_HOME/cases` and
`$BARECTL_EVAL_HOME/prompts`. Snapshot the current harness **before** applying a skill
change:

```bash
mkdir -p ~/.local/share/barectl/eval-harness/baseline
cp -R ~/.agents/skills/implement-spec ~/.agents/skills/code-review \
  ~/.local/share/barectl/eval-harness/baseline/
```

Prepare each arm. `prepare` creates an isolated worktree, copies the arm's skills into
`.opencode/skills` (project skills override global ones), writes `.eval-prompt.md` and starts
the clock:

```bash
uv run python -m evals.runner prepare <case> --arm baseline \
  --harness ~/.local/share/barectl/eval-harness/baseline
uv run python -m evals.runner prepare <case> --arm candidate \
  --harness ~/.agents/skills
```

Run the printed command from each worktree:

```bash
opencode run --format json --auto --title "eval <case> baseline" "$(cat .eval-prompt.md)"
```

Grade the result. The grader copies the oracle tests from the case's `oracle_ref`, overwriting
tests the agent wrote, then runs them and the static checks:

```bash
uv run python -m evals.runner grade <case> --arm baseline --must-fix N --judgement N
uv run python -m evals.runner grade <case> --arm candidate --must-fix N --judgement N
uv run python -m evals.runner compare <case>
```

For a review case, add the ground-truth findings the review actually found:

```bash
uv run python -m evals.runner grade <case> --arm candidate \
  --found <id>,<id> --false-positives 2 --must-fix 4 --judgement 6
```

Results are appended to `$BARECTL_EVAL_HOME/results/<case>.jsonl` (default
`~/.local/share/barectl/evals/results`). Set `BARECTL_EVAL_HOME` to move every local eval
artifact, and `BARECTL_EVAL_WORKTREES` to choose where worktrees are created. Nothing under
that directory is tracked in git.

## Metrics

| Metric | Better | Notes |
| --- | --- | --- |
| `oracle_failed` | 0 | 1 means the oracle suite failed; read its output |
| `checks_failed` | 0 | `ruff` and `mypy` on the candidate worktree |
| `must_fix` | lower | Actionable findings from the review, not every preference |
| `judgement` | lower | Reported separately so a noisy reviewer is visible |
| `recall` | higher | Review case only: share of ground-truth findings found |
| `false_positives` | lower | Review case only |
| `wall_minutes` | lower, within budget | The case names its budget |
| `diff_lines` | context only | A large diff is a cost signal, not a failure |

Use at least two trials per arm for a capability case. Report pass@1 (the first trial) and
pass^2 (both trials) rather than a single lucky run. Review cases are deterministic enough to
run once when the ground truth is fixed.

## Acceptance

A harness change ships when:

1. its target metric improves or stays equal with lower cost, and
2. every regression case still passes, and
3. a human has read at least one trace from each arm.

Otherwise revert it and record the negative result in the retro. A negative result is
information; deleting it makes the next retro repeat the experiment.

## What not to do

- Do not adopt a hosted eval platform before the case bank has 20 tasks. The repository's
  tests and `code-review` are the first graders.
- Do not evaluate the model in isolation. Evaluate the harness: skills, docs, tools and
  checks.
- Do not grade the exact tool path. Grade the outcome and read the trace where the path
  matters.
- Do not let a case saturate. When it always passes, move it to the regression set and add a
  harder case from a real failure.
- Do not let the LLM grader decide alone. Deterministic tests first; the judge explains and
  catches what tests cannot.

## Research

- Anthropic, [Demystifying evals for AI agents](https://www.anthropic.com/research/demystifying-evals-for-ai-agents):
  tasks, trials, graders, capability vs regression suites, pass@k and pass^k, 20-50 real
  failures are enough to start.
- Anthropic, [Claude Code best practices](https://www.anthropic.com/engineering/claude-code-best-practices):
  give the agent a check that returns pass/fail; enforce zero-exception rules in the harness,
  not in prose.
- OpenAI, [Harness engineering](https://openai.com/index/harness-engineering/): `AGENTS.md`
  as a map, docs as the system of record, custom linters and recurring cleanup.
- OpenAI, [Building self-improving tax agents](https://openai.com/index/building-self-improving-tax-agents-with-codex/):
  production corrections become structured findings, then scoped eval targets, then a Codex
  task with validation gates.
- Promptfoo, [Evaluate coding agents](https://www.promptfoo.dev/docs/guides/evaluate-coding-agents/):
  isolated workspaces, outcome and trace assertions, cost and latency thresholds, repeat
  runs.
