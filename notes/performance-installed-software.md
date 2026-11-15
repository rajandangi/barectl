# Check installed software performance

Issue: [#554](https://github.com/rajandangi/barectl/issues/554).
Baseline: `a6a7ebfda36f8c4d3bc39970d2f6cfea9ffd4d68`.

## Finding and change

The software stage performs package, host-standing, foundation and runtime reads.
A real SSH profile on the prepared L1 server issued 84 remote commands, including
23 separate `command -v` lookups. Filesystem probes and the larger native readers
also contribute to its duration.

`discovery.observations.standing` now runs the fixed required-tool list in one shell
command. Each lookup still uses `command -v`, with the same classification rules:
successful non-whitespace output is present; successful empty output and exit 127
are missing; other exit statuses are unreadable. The response contains one fixed
token per tool rather than executable paths or command output.

A failed, truncated, incomplete, extra or invalid-token batch makes every required
tool unknown. Unknown checks do not become evidence that tools are installed. A
valid mixed response retains the individual present, missing and unknown results.
The SSH integration, host-key checks, permissions, command/session bounds and native
read locks remain unchanged. The checks are neither skipped nor cached across reads.

## Before and after

| Real SSH workload | Before median | After median | Reduction |
| --- | --- | --- | --- |
| L1, local forwarded connection | 0.790 s | 0.704 s | 11% |
| L1, 25 ms injected server egress delay | 6.714 s | 5.241 s | 22% |
| Software-stage remote commands | 84 | 62 | 26% |
| Required-tool remote commands | 23 | 1 | 96% |

These are software-stage timings, not complete Refresh server durations. A temporary
native lane booted the existing L1 image, used the existing verified pyinfra SSH
connection, and collected through the actual discovery code. `sites=False` omitted
later hosting reads while retaining the same software-stage reads as full discovery.
The profile did not persist worker progress to the application database.

Three samples per implementation and network condition alternated execution order.
The original host-standing collector was loaded directly from the baseline commit.
The delayed condition used `tc netem` inside the disposable server only; no network
configuration on an operator's server or the controller was changed. The lane and
temporary credentials were removed afterward.

Every sample compared the old individual tool classifications with the new batch,
and compared standing, reasons, warnings, foundation states and runtime profiles.
Those values matched. Volatile capacity evidence was not compared between sequential
reads. Absolute timings vary with the host and network.

## Reuse and review

pyinfra's documented [server.Which](https://docs.pyinfra.com/en/3.x/facts/server.html#server-which)
checks one command at a time. The installed 3.10.0 implementation uses
`command -v ... || true`, which does not provide the required per-tool exit-status
classification for a bounded batch. The change retains the standard shell lookup
and the existing `RemoteShell.run` boundary. The requirement, alternatives and reason
for the limited wrapper were recorded in #554 before implementation.

Independent preliminary Standards and Spec reviews found no must-fix or judgement
findings before the command source was frozen for the full transcript recording pass.

## Regression checks

The collection-level regression failed against the original real transcript with
`23 != 1`. A shell-execution test covers successful nonempty output, successful
whitespace output, missing commands, non-executable commands and other failures.
The parser tests cover nonzero batch exit, truncation, empty output, a missing row,
an extra row and invalid tokens, asserting exact unknown results.

Changing the command requires the real-server transcript recording workflow. Existing
recorded output is never translated into a synthetic batch fixture.

## Validation

- The full recording workflow completed all 32 states, each with a real-server capture
  receipt. `scripts/record-all-transcripts.sh --check` passed afterward.
- The fake uses the pristine recording for this fixed command and allows only the exact
  command in its read-only check; synthetic individual lookup responses were removed.
- Controller suite: 2,790 tests in 27.277 s, passed with the existing platform skip.
- Browser suite: all 110 tests passed in 91.326 s.
- Native suite: all 93 scenarios passed in 239 s, within the 300 s target. No residue
  warnings were reported in this run.
- Ruff lint and formatting, strict mypy, Vulture, module-map and provider-setup checks,
  frontend checks including Knip, production asset build, template checks, Django system
  and migration checks, dependency audit policies, and `git diff --check` passed.
- Both independent reviews also checked the fake and performance note and found no
  must-fix or judgement findings.
