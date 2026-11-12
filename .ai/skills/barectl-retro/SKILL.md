---
name: barectl-retro
description: Run a Barectl retrospective with the global retro skill and turn accepted candidates into local eval cases.
disable-model-invocation: true
---

Read and follow the global `retro` skill first. Follow that skill in full, then apply these Barectl
rules on top of it.

- When a candidate is accepted, turn it into an **eval case** before implementing it. Name the
  case, the target metric, the regression cases and the rollback.
- Follow `docs/agents/evals.md`. Prepare a baseline arm and a candidate arm on the same pinned
  case, grade both, and keep the change only when the target metric improves and the
  regression cases hold.
- A candidate without a before/after measurement is a hypothesis, not an improvement.
- Record a negative result instead of deleting it.
- Cases, prompts, ground truth and results stay under `$BARECTL_EVAL_HOME` (default
  `~/.local/share/barectl/evals`). Never commit them.
