---
name: Barectl implement spec
description: Deliver a Barectl GitHub spec and its tickets end to end. Wraps the global implement-spec skill with this repo's shared-seam, review-triage and eval rules.
disable-model-invocation: true
---

Call the Skill tool with `implement-spec` first. Follow that skill in full, then apply these
Barectl rules on top of it.

## Shared seam

Before dispatching the ticket frontier, list every file, constant, registry and test helper
that more than one ready ticket will edit. The foundation ticket must land the whole shared
seam the parallel tickets will use, not only its own slice. Give each ticket an owned-file
list; serialize tickets that share a file. A later ticket that still needs a shared constant
adds it in its own area module instead of editing the shared seam.

When a ticket changes a module's interface or seam, call the Skill tool with
`codebase-design` for the deep-module vocabulary and record the chosen seam in the ticket.
Do not call it for every ticket; a ticket that only fills in an existing interface does not
need it.

## Review triage

When `code-review` returns, tag every finding **must-fix** or **judgement** before acting.
Resolve a judgement against the spec and the owning document first. A judgement that conflicts
with a documented recovery path is recorded with its rationale, not forced through. Send only
the resulting must-fix list to the fix implementer.

## Eval before merge

If this run changes the harness (skills, steering docs or checks), follow
`docs/agents/evals.md`: prepare a baseline and a candidate arm on the same pinned case, grade
both, and keep the change only when the target metric improves and the regression cases hold.
A missed target is recorded as a negative result, not hidden.

## Records

The repository tracks the runner and the contract, not the cases or results. Cases, prompts,
ground truth and runs stay under `$BARECTL_EVAL_HOME` (default
`~/.local/share/barectl/evals`). Never commit them.
