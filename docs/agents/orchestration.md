# Orchestration brief

Reusable brief for an autonomous agent delivering a specification and its sub-issues end to end. Read it with the parent issue: the tracker is the live state, not this file. It names agent roles, never products or models, so it works in any coding agent.

## Setup

Fetch the parent issue, every sub-issue and their comments to the notes directory (`gh issue view <n> --json body --jq .body >"$NOTES/issue-<n>.md"`) and read or grep those files. Keeping the full bodies out of the working context avoids spending it on specification text you are not using in this turn. Read every issue's comments, labels and native blocking relationships before planning. Add every blocking edge with GitHub's native dependency API and record the resulting graph in the parent; the frontier is read from the tracker, not inferred from issue numbers. Work from the live tracker rather than remembered state. Then read `README.md`, `CONTRIBUTING.md`, `GLOSSARY.md`, the specification the parent names, and the ADRs and qualification records it links. `AGENTS.md` is already in context; do not read it again.

Follow the agreed phase order and the tracker's blocking edges, not issue-number order. Record consequential decisions, the alternatives checked and source links in the owning issue. Resolve routine product, architecture and implementation decisions yourself; do not interview the user or request repeated confirmation.

## Authority and boundaries

- Claim tickets, branch, commit, push, open pull requests and merge them once required checks and reviews pass. Preserve branch protection.
- Delegate bounded research, implementation and review to subagents with explicit ownership; prevent overlapping edits and keep architectural decisions and final verification.
- Use disposable environments for mutations. Live servers are read-only unless the issue explicitly authorizes otherwise.
- Keep the project boundaries in `AGENTS.md`: the managed server is the source of truth, native coordination, the one SSH execution boundary, and no new execution path, agent, or custom server-side record.
- Do not name the coding agent in branches, commits, pull requests, issues, comments or release notes. Fragments of a phrase (for example an agent's name alone) are as public as the full string.

## Agent roles

Each role runs on a capability tier. Map the tiers to models in your coding agent's own configuration, not in this repository.

| Role | Tier | Owns |
| --- | --- | --- |
| Orchestrator | planning | the task graph, architectural decisions, briefs, final verification and merges |
| Implementer | implementation | one ticket phase in its own worktree |
| Reviewer | implementation | a Standards or Spec review of one diff |
| Explorer | mechanical | read-only search and documentation lookups, returned as notes |
| Runner | mechanical | waiting on CI or native runs, merging the integration tip, resolving textual conflicts, merging an approved pull request |

A mechanical-tier agent that meets a design question stops and reports it to the orchestrator instead of deciding it.

## Execution

Maintain one persistent todo list for the whole run: every ticket, dependency, acceptance criterion, verification result and remaining gap. Keep a one-line-per-ticket status in `status.md` in the run's notes directory, outside the repository, and update it whenever a ticket changes phase, so a progress question is answered by reading that file. Complete tickets one at a time.

Every ticket passes through three phases, each run by a **fresh** subagent. A phase ends with a handoff note in the notes directory: the branch and head commit, what is done, what is left, and the evidence. The next phase's brief points to that note, the ticket and the documents its area owns, never to the previous agent's transcript. A subagent whose phase is done returns; it never continues into the next phase.

1. **Implement** (implementer). Read the acceptance criteria and find the existing behavior and test seams. Implement the smallest complete, independently demonstrable slice: permissions, empty, stale and inaccessible states, progress, failure, recovery and accessibility included. Run focused tests and affected native scenarios, then obtain preliminary independent Standards and Spec reviews of the candidate before freezing native sources or starting a full transcript recording pass. Resolve their findings, freeze command-affecting sources, record required states, and run the checks in `../quality.md#local-commands`. If a reviewed native source changes, repeat its affected proof and preliminary review before recording. Merge the integration tip into the branch, push, and write the handoff note.
2. **Review and fix** (reviewers, then an implementer). Obtain final independent Standards and Spec reviews of the exact pushed diff, including any changes since the preliminary review. A new implementer fixes the actionable findings from the handoff note and the review reports, reruns the affected checks, pushes, and updates the note.
3. **Publish** (runner). Open one focused pull request with truthful validation evidence from the note, wait for the required checks on its exact head commit, and report the result. The orchestrator merges, updates the current-behavior documentation and records completion evidence in the ticket. Close the sub-issue only when delivered and verified.

Briefs stay short: the ticket, the handoff note, the owning documents and the role. Name only the documents the ticket's area needs, found through the [module map](../architecture.md#module-map). Start from the [implementer brief](implementer-brief.md) shape and return the handoff in the same note.

## Verification and completion

Test observable behavior, real native effects, failure recovery, authorization, and reconstruction from a fresh controller. Missing or skipped required evidence is not a pass; never weaken an assertion or a requirement to hide a blocker. Finish each slice with the required code review before moving on.

Complete the run only when every sub-issue's acceptance criteria are met and the parent's integration criterion holds: audit the implementation against every requirement in the parent specification, resolve remaining gaps, then close the parent last with the merged pull requests, literal verification results and material limitations. Keep audit failures visible; the existing dependency exception does not authorize bypassing later gates.

## Long-running commands

Run long commands in one persistent tool execution. Use the foreground runner, return the tool's live session handle promptly, and resume that session until the runner exits:

```bash
docker/disposable-server/quiet-run.sh run "$NOTES/native.log" -- docker/disposable-server/run-scenarios.sh --env-file .env
```

The parent process stays alive until the command completes. A detached `start` call is only suitable for a host that guarantees detached child survival; returning from an execution tool can terminate its process group. An absent status file is not evidence that a job is running. Read the runner's liveness result before resuming or restarting it.

The runner takes the host-wide native lock itself (`disposable/locking.py`), so every caller — the orchestrator, an implementer proving one item, `build.sh` — waits for the lane owner instead of sharing lanes. `build.sh` holds the same lock once for its side-by-side validator and native stages.

`run` and `follow` wait until completion. The legacy bounded `wait` is an observation deadline, not a command deadline; its exit 124 must never be treated as a completed test. Keep the owning tool session alive when a command outlasts a bounded observation. The native harness owns test deadlines. Full recording passes can legitimately exceed nine minutes.

For CI, use `scripts/watch-checks.sh <pr> "$NOTES/pr-checks.log"` in a persistent tool session. One runner owns each command and its wait. Report a changed stage, failure or completion; avoid repeated full log reads while the state is unchanged. Consult the build's verification ledger before rerunning a gate already completed by another phase. Reuse evidence only when its recorded inputs still match and policy permits; pre-push hooks and exact-head required CI remain mandatory.

Never report the task done while a command is still running. If a stored dependency genuinely blocks safe progress, document exactly what it blocks and continue every independent authorized step; do not stop the run. Do not stop half-way; finish the specification and its sub-issues end to end.

Run one native suite per host at a time. Parallel implementers share Docker lanes and a package-manager, so a second full native run produces contended timings and false failures; the runner's host lock makes every caller wait, and an implementer proves its own item through it before pushing rather than deferring the run.
