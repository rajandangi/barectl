# Orchestration brief

Reusable brief for an autonomous agent delivering a specification and its sub-issues end to end. Read it with the parent issue: the tracker is the live state, not this file.

## Setup

Read the parent issue, every sub-issue and their comments, labels and native blocking relationships before planning. Work from the live tracker rather than remembered state. Then read `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `CONTEXT.md`, the specification the parent names, and the ADRs and qualification records it links.

Follow the agreed phase order and the tracker's blocking edges, not issue-number order. Record consequential decisions, the alternatives checked and source links in the owning issue. Resolve routine product, architecture and implementation decisions yourself; do not interview the user or request repeated confirmation.

## Authority and boundaries

- Claim tickets, branch, commit, push, open pull requests and merge them once required checks and reviews pass. Preserve branch protection.
- Delegate bounded research, implementation and review to subagents with explicit ownership; prevent overlapping edits and keep architectural decisions and final verification.
- Use disposable environments for mutations. Live servers are read-only unless the issue explicitly authorizes otherwise.
- Keep the project boundaries in `AGENTS.md`: the managed server is the source of truth, native coordination, the one SSH execution boundary, and no new execution path, agent, or custom server-side record.
- Do not name the coding agent in branches, commits, pull requests, issues, comments or release notes. Fragments of a phrase (for example an agent's name alone) are as public as the full string.

## Execution

Maintain one persistent todo list for the whole run: every ticket, dependency, acceptance criterion, verification result and remaining gap. Give concise updates that show completed work, evidence and the next action. Complete tickets one at a time.

For each ticket:

1. Read its acceptance criteria and find the existing behavior and test seams.
2. Implement the smallest complete, independently demonstrable slice: permissions, empty, stale and inaccessible states, progress, failure, recovery and accessibility included.
3. Run meaningful focused tests, then the checks in `../quality.md#local-commands`. For a native-affecting path, run the affected native tests locally before pushing ([native suites](../quality.md#native-suites)).
4. Obtain independent Standards and Spec reviews. Fix actionable findings and rerun affected checks.
5. Publish one focused pull request with truthful validation evidence. Verify the required checks on its exact head commit before merging.
6. Update the current-behavior documentation and record completion evidence in the ticket. Close the sub-issue only when delivered and verified.

## Verification and completion

Test observable behavior, real native effects, failure recovery, authorization, and reconstruction from a fresh controller. Missing or skipped required evidence is not a pass; never weaken an assertion or a requirement to hide a blocker. Finish each slice with the required code review before moving on.

Complete the run only when every sub-issue's acceptance criteria are met and the parent's integration criterion holds: audit the implementation against every requirement in the parent specification, resolve remaining gaps, then close the parent last with the merged pull requests, literal verification results and material limitations. Keep audit failures visible; the existing dependency exception does not authorize bypassing later gates.

## Long-running commands

A native suite run takes many minutes. When a run is in flight, poll it to completion before reporting status: read the per-release logs the runner writes under `~/.cache/barectl/native/logs/<release>/` ([native suites](../quality.md#native-suites)), or watch the command, rather than starting it in the background and returning. Never report the task done while a background command is still running. If a stored dependency genuinely blocks safe progress, document exactly what it blocks and continue every independent authorized step; do not stop the run. Do not stop half-way; finish the specification and its sub-issues end to end.
