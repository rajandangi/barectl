# Security and backup refresh performance

Issue: [#555](https://github.com/rajandangi/barectl/issues/555).
Baseline: `99cb6fe959bb02b3f2067b78c823797b11c2d6d9`.

## Finding and change

A normal refresh through the application worker took 99.462 seconds and 182 SSH
reads. Software collection took 59.259 seconds and security/backups took about
36 seconds. Median time between completed reads was 0.527 seconds; the longest
read took 2.388 seconds. The progress timer measures the whole operation, rather
than time spent in the current stage.

Each fixed root read previously checked identity in a separate SSH call and, for
non-root connections, listed sudo authorization in another call. The fixed-read
adapter now checks identity, checks the exact sudo argv when needed, and executes
the read in one SSH call. It reuses the native authorization and execution builders.
It checks permissions afresh for every read and discards authorization output.

The payload is quoted once and passed as one argument to both sudo commands. This
avoids exceeding Linux's argument limit on large native readers. Failed identity,
oversized identity output and denied sudo authorization refuse the read. The
existing SSH output, command and session bounds still apply. The worker transport
boundary and observation parsers remain the same.

## Before and after

The controlled comparison used the prepared L2 disposable server and the real SSH
adapter. Three samples alternated baseline and candidate for each network condition.
The baseline function was loaded from the commit above. Added delay used `tc netem`
inside the disposable server, which was removed afterward.

| Security and backup collection | Before median | After median | Reduction |
| --- | --- | --- | --- |
| Local forwarded SSH connection | 0.502 s | 0.445 s | 11% |
| 25 ms added server egress delay | 5.549 s | 3.191 s | 42% |
| Remote reads | 70 | 37 | 47% |
| Full discovery remote reads on L2 | 150 | 106 | 29% |

Every sample compared the complete security and backup observations, including
outcomes, sources, warnings and parsed values. They matched. Package-list age used
one controller time for both arms; volatile capacity values were not compared.
The controlled profile does not include worker progress database updates.

The final normal refresh through the existing application worker succeeded with
these timings on the registered remote server:

| Live application refresh | Before | After |
| --- | --- | --- |
| Security and backups | about 36.1 s | 19.098 s |
| Software | 59.259 s | 59.023 s |
| Full refresh | 99.462 s | 81.987 s |
| Remote reads | 182 | 148 |

These are individual live samples, not medians, and differ from L2 in configuration
and network latency. Stage boundaries came from local progress timestamps observed
through a read-only connection to the application database. The final run used the
signed-in agent-browser session to submit the ordinary Refresh server form. The
software stage remains the largest part of this server's refresh.

## Reuse and regression checks

The reuse review is recorded in #555. pyinfra's supported
[_sudo argument](https://docs.pyinfra.com/en/3.x/arguments.html) does not implement
Barectl's fresh root-or-exact-sudo-list admission. The existing native builders
retain Ubuntu's [noninteractive sudo behavior](https://manpages.ubuntu.com/manpages/resolute/man8/sudo-rs.8.html).
No new transport, package or persistent server helper was added.

The regression first failed because a root read and a sudo read made five SSH
calls rather than two. Shell-execution tests verify exact sudo argv, quoted payloads,
nonzero read exit status, large authorization output, denied/revoked authorization,
failed identity, read truncation and identity output at the accepted and rejected
byte boundaries. A second regression caught oversized identity output incorrectly
allowing a read before the bound was restored.

Independent Standards and Spec reviews were resolved before freezing the command
sources. The native passwordless-sudo discovery scenario also exercises successful,
password-required and unavailable sudo against the real server.

## Validation

- All 32 transcript states were captured from real servers with verified receipts;
  `scripts/record-all-transcripts.sh --check` passed. The test-adapter-only update
  then passed the command-neutral manifest refresh and its 56 replay tests.
- Controller suite: 2,790 tests passed in 35.601 seconds, with one existing skip.
- Browser suite: 110 tests passed in 128.687 seconds.
- Native lifecycle: all 93 scenarios passed in 284 seconds, below the 300-second target.
- Native validators: all six groups passed in 34 seconds.
- Python lint, formatting, strict typing, dead-code checks, templates, frontend checks
  and build, dependency audits, Django checks and migration checks passed.
- Independent final working-tree Standards and Spec reviews had no findings.
