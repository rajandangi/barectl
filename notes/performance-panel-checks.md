# Hosting-panel path checks (#564)

The eleven fixed hosting-panel paths now use one read through the existing pyinfra SSH
connection. The command tests each path with `test -e`, then walks its ancestors in the
original `test -x`, `test -e` order. A failed, truncated, malformed, or wrong-count reply
leaves all eleven states unknown. No privileged read or server-side helper is involved.

## Same-server comparison

The comparison used one disposable Ubuntu 26.04 L0 server and the same SSH connection for
alternating baseline and candidate measurements. The baseline functions `_test`,
`_path_missing`, and `_path_state` were loaded from integration commit
`45da65e6916904e474f2f8c1f5695ebb92a07893` in an external script. Each network condition
had three samples of each arm, alternating old/new and new/old. The delayed condition added
25 ms of server egress latency with `tc netem`; the script removed it in `finally` and
removed the disposable lane. Counts are calls to `RemoteShell.run`, including the fixed
reads inside collection.

| Workload, median | Local old | Local new | 25 ms old | 25 ms new | Reads old → new |
| --- | ---: | ---: | ---: | ---: | ---: |
| Panel checks | 0.0659 s | 0.0026 s | 1.7048 s | 0.0737 s | 24 → 1 |
| Software stage | 0.2933 s | 0.2431 s | 6.8297 s | 5.2305 s | 95 → 72 |
| `collect(..., sites=False)` | 0.3084 s | 0.2585 s | 7.1988 s | 5.5856 s | 100 → 77 |

All eleven path classifications matched in every pair. Every noncapacity snapshot field
and the standing, reasons, warnings, foundation, profiles, and noncapacity standing evidence
also matched. Sequential memory and free-disk readings can change between arms, so only
those capacity values were excluded from the equality assertion. On this pristine server,
all panel paths were missing and the standing was Fresh host with no reasons or warnings.
The times cover SSH collection, not worker progress writes or dashboard and CLI response time.

The script and raw samples are in `/tmp/barectl-refresh-cli/panel_compare.py` and
`/tmp/barectl-refresh-cli/panel-comparison.json`; the complete runner log is
`/tmp/barectl-refresh-cli/panel-compare.log`. These are local evidence artifacts, not
repository sources.

## Verification

The public collector tests cover one panel read, present and hidden paths, and whole-batch
unknown results for failed, truncated, missing, extra, and invalid replies. The FakeServer
contract compares the fixed command with a real temporary filesystem, including a dead
link and an unsearchable ancestor. `disposable.test_l0_discovery.PlainL0Discovery` and
`disposable.test_foundation.FoundationSudoDiscovery` passed through real SSH. The shared
refresh/CLI tests passed through the existing worker and operation interfaces. The complete
recorded-transcript pass is owned by the #562 integration run after preliminary reviews.
