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

The twelve measurements below are in execution order. Seconds are rounded to six decimal
places; the median table above rounds to four. To repeat an equivalent comparison, use
the baseline functions at the pinned commit and the current batch on one prepared
disposable L0 server. Count each `RemoteShell.run` call and time the panel checks,
software stage, and `collect(..., sites=False)` separately through the same SSH adapter.
Alternate arm order for each sample, repeat with 25 ms server egress delay, then remove
the delay. Compare panel states, standing fields, and the collection snapshot with the
variable capacity values excluded as described above. Issue [#564](https://github.com/rajandangi/barectl/issues/564)
records the baseline-only measurement and reuse decision.

| Delay (ms) | Sample | Arm | Panel reads | Panel (s) | Software reads | Software (s) | Collection reads | Collection (s) |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 1 | old | 24 | 0.077067 | 95 | 0.335354 | 100 | 0.348542 |
| 0 | 1 | new | 1 | 0.002796 | 72 | 0.269183 | 77 | 0.284313 |
| 0 | 2 | new | 1 | 0.002878 | 72 | 0.264412 | 77 | 0.281233 |
| 0 | 2 | old | 24 | 0.071577 | 95 | 0.321936 | 100 | 0.338710 |
| 0 | 3 | old | 24 | 0.070790 | 95 | 0.330041 | 100 | 0.345730 |
| 0 | 3 | new | 1 | 0.003155 | 72 | 0.261032 | 77 | 0.279152 |
| 25 | 1 | old | 24 | 1.789495 | 95 | 7.176570 | 100 | 7.550915 |
| 25 | 1 | new | 1 | 0.070186 | 72 | 5.511562 | 77 | 5.871149 |
| 25 | 2 | new | 1 | 0.078365 | 72 | 5.466072 | 77 | 5.827163 |
| 25 | 2 | old | 24 | 1.793871 | 95 | 6.845910 | 100 | 7.232277 |
| 25 | 3 | old | 24 | 1.859465 | 95 | 6.883741 | 100 | 7.273082 |
| 25 | 3 | new | 1 | 0.072406 | 72 | 4.992254 | 77 | 5.361078 |

## Verification

The public collector tests cover one panel read, present and hidden paths, and whole-batch
unknown results for failed, truncated, missing, extra, invalid, and malformed line-framing
replies. The FakeServer contract compares the fixed command with a real temporary filesystem,
including a dead link and an unsearchable ancestor. The focused L0 and FoundationSudo
scenarios passed through real SSH. The shared
refresh/CLI tests passed through the existing worker and operation interfaces. The complete
recorded-transcript pass is owned by the #562 integration run after preliminary reviews.
