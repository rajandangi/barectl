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
| Panel checks | 0.0716 s | 0.0029 s | 1.7939 s | 0.0724 s | 24 → 1 |
| Software stage | 0.3300 s | 0.2644 s | 6.8837 s | 5.4661 s | 95 → 72 |
| `collect(..., sites=False)` | 0.3457 s | 0.2812 s | 7.2731 s | 5.8272 s | 100 → 77 |

All eleven path classifications matched in every pair. Every snapshot field except
`memory_bytes`, `filesystem`, and `standing` matched. All standing fields except `evidence`
matched, as did all evidence entries except those named Free disk and Available memory.
Those capacity observations were retained in the raw samples but excluded from equality
because sequential native readings can vary. In one delayed pair, Available memory was
13.7 GiB in the old arm and 13.8 GiB in the new arm; exact capacity equality is not claimed.
On this pristine server, all panel paths were missing and the standing was Fresh host with
no reasons or warnings.
The times cover SSH collection, not worker progress writes or dashboard and CLI response time.

The script and raw samples are in `/tmp/barectl-refresh-cli/panel_compare.py` and
`/tmp/barectl-refresh-cli/panel-comparison.json`; the complete runner log is
`/tmp/barectl-refresh-cli/564-fix-panel-compare.log`. The earlier samples, script, and log
are preserved under `*-initial-544944bb.*` names. These are local evidence artifacts,
not repository sources.

## Verification

The public collector tests cover one panel read, present and hidden paths, and whole-batch
unknown results for failed, truncated, missing, extra, invalid, and malformed line-framing
replies. The FakeServer contract compares the fixed command with a real temporary filesystem,
including a dead link and an unsearchable ancestor. The focused L0 and FoundationSudo
scenarios passed through real SSH. The shared
refresh/CLI tests passed through the existing worker and operation interfaces. The complete
recorded-transcript pass is owned by the #562 integration run after preliminary reviews.
