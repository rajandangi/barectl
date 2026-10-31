# Implementer brief

Use this shape for a subagent that owns one ticket phase. Keep it short: the ticket, the handoff note, the owning documents and the role. The orchestrator fills the first block; the implementer fills the handoff.

## Brief

- **Ticket and phase:** `<# number>`; implement, review/fix, or publish.
- **Branch and worktree:** `<path>` at `<integration head>`.
- **Read first:** the ticket, the parent spec, `<topic docs>`, `<ADR>`, and the previous phase's handoff note. Do not re-read the repository from scratch.
- **Ownership:** the files or seams this ticket owns. Name overlaps with parallel tickets and the shared file to change in one place.
- **Acceptance evidence:** every criterion and the exact command, test or native scenario that proves it. State which evidence is required and which may be deferred.
- **Completion bar:** focused tests, the local command set in `docs/quality.md#local-commands`, native scenarios when the ticket changes a native path, a merged integration tip, and a handoff note at `<path>`. Run your own scenario item through `docker/disposable-server/run-scenarios.sh` before pushing: the runner takes the host-wide native lock, so a parallel agent waits instead of sharing lanes. Deferring the native run to the orchestrator is how cross-ticket seams — a version parser, an S3 flag, a unit payload — reach the integration tip untested.

## Handoff

- Branch and head commit.
- What changed, with the smallest useful file map.
- The final full transcript recording pass, its head commit and the result of `scripts/record-all-transcripts.sh --check`.
- Acceptance criteria with literal evidence (test names, commands, results).
- The commands run and their results.
- What is unrun, unqualified or risky.
- The exact extension points the next ticket should use.

## Evidence rule

A required native test is never removed, skipped or weakened to fit an item limit or a time budget. Split the setup into a preparation scenario, or record the gap in the handoff and the qualification record. A missing test is not a pass.

Record shared transcripts on the integration tip once a shared read source changes, not repeatedly on a ticket branch that will merge other read changes later. See `docs/quality.md#recorded-transcripts`.
