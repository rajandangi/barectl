# Test budget qualification

[#479](https://github.com/rajandangi/barectl/issues/479) brought the snapshot-backed merge workflow within the targets; [#481](https://github.com/rajandangi/barectl/issues/481) owns the remaining cold-cache qualification. The targets in [quality](quality.md#test-time-budget) remain 60 seconds for the joint fast stage, 90 seconds for controller-fast, 180 seconds per native item, and 300 seconds for a full local build, the shared hosted snapshot preparation phase, or a complete hosted shard, with the 900-second hard limit. Revision `e655e6be` passed all 31 fresh native captures, the 289-second strict local build, and all eleven hosted native phase targets with exact-key snapshots in run 41351088130, attempt 2. This qualifies the snapshot-backed merge workflow. The historical all-cache-miss result and the special-image first-fill misses remained unqualified setup measurements; the [cold-cache work](#cold-cache-qualification) below supersedes that limitation. Required checks on the merge head repeat these budgets.

## Local measurements

The controller has 14 logical CPUs and 64 GiB memory. Docker retains the same 14 CPUs and 15.66 GiB allocation throughout. No hardware allocation was increased. Measurements are from 2026-11-02 on arm64. The candidate includes the stronger WordPress cron proof with a second automatic timer tick after every SSH connection closes.

| Run | Controller | Validators | Browser | Native | Full wall | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Initial strict diagnostic, 8 native lanes | 77 s | 161 s | 171 s | 487 s | 487 s | Tests passed; joint and full targets missed |
| Concurrent build, 16 native lanes | 49 s | 86 s | 122 s | 296 s | 296 s | Joint target missed; seven stale recording/audit failures |
| Fast gates before native, 16 lanes and measured local ordering | 28 s | 41 s | 104 s | 258 s | 299 s | Timing targets met; seven stale recording/audit failures |

The two candidate builds are diagnostics, not green qualification. They ran all 87 native items and 102 browser tests successfully; the six validator classes retained all 25 tests. The controller failures require actual fresh recordings and an explicit re-audit of the narrow unsupported-host dependency exclusion. The initial full-build input revision is `34c8bae`; the candidate source is still uncommitted at this point.

The exact controller-fast gate took 23.4 seconds without other build stages, with the same default 14 workers. Its seven stale recording/audit failures were retained. This falsified the hypothesis that an intrinsically slow SSH test class or password hashing caused the 74-second concurrent baseline. No test class, password hasher or controller coverage was changed for that hypothesis.

## Native capacity and scheduling

All capacity trials used the same Docker allocation and original item limits. The 8/12 pair kept identical runtime sources and layer keys. The 16-lane run added the stronger cron scenario and measured longest-first ordering; its only unrelated input change during execution was a controller-only workflow test, not an executed native source.

| Native lanes | Items passed | Phase | Longest item | Observed OOM events |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 87/87 | 362 s | 117.5 s | 0 |
| 12 | 86/87 | 287 s | 122.2 s | 0 |
| 16 | 87/87 | 263 s | Under 180 s | 0 |

The 20-lane trial executed no native items because Docker exhausted its predefined network address pools during lane startup. Eight older attached harness networks were inspected and preserved. That attempt provides no throughput evidence and did not justify a default change or daemon configuration change. The 18-lane trial used the available pool without altering those fixtures. It passed 86 of 87 native items in 264 seconds and took 306 seconds overall, missing the unchanged target. OffsiteCopy refused its site-database preparation after site creation because foundation standing was not Target stack. Its exact failed standing reason was not captured; no cause is asserted and no readiness wait or retry was added. The 18-lane capacity was rejected.

The 12-lane trial failed its first Laravel queue-worker foundation admission. Its retained diagnostics do not establish the precise standing reason, so it does not qualify. A temporary diagnostic collector on the 16-lane trial retained the actual foundation judgments and observed only Target stack. This does not retrospectively explain the failure.

The 16-lane trial sampled a peak of 6.27 GiB Docker guest memory and 11.24 CPU equivalents, within the unchanged allocation. Controller-process memory peaked at 3.36 GiB on the 64 GiB host. Early guest samples are missing for part of the 8-lane trial; its controller samples are complete. The default is now bounded by `min(16, floor(CPUs / 0.875), floor(Docker VM GiB / 0.5))`. The cap prevents extrapolation beyond the measured 16-lane capacity. The measured two-lane hosted baseline is recorded below; the current candidate tests three lanes on the same standard runner.

`disposable/local_times.json` contains actual per-item measurements from the successful 16-lane trial, its source and artifact digests, and allocation. It orders only unsharded local native work. Hosted scheduling retains its separate `disposable/shard_times.json`; local times do not replace hosted measurements. `disposable/validator_times.json` retains actual validator measurements. In a controlled two-lane comparison, weighted validator packing reduced 43 seconds to 33 seconds, with all classes and assertions retained.

The build starts controller-fast, validators and browser tests together, then native work after both fast gates finish. Delaying browser startup until the native phase was rejected after a 351-second diagnostic, with a 42-second joint stage and all 87 native items passing. That trial also included broader observation instrumentation, so its difference is not attributed solely to ordering. Its original wall clock includes the wait. The native command receives only the remainder of the original 900-second deadline. Each fixed build gate also runs under GNU/BSD `timeout` for its remaining original deadline. Expired gates record failure without launching setup; a positive remainder interrupts real setup and reaps its child in the regression proof. The general foreground runner remains unbounded for long transcript passes. No required stage is moved out of the build.

## Work removed and coverage retained

- Cron and PHP-fence scenarios reuse the existing product-created WordPress/database snapshot. They still configure and verify real HTTPS. The fence setup starts the existing cron service after the ordinary enable body reaches its tick stage, then waits for the real result and verification. The cron scenario separately proves initial and further automatic timer ticks with SSH closed. All five fence cases and its real nondraining deadline remain.
- Cold consumers that do not select the complete S1 journey use minimal foundation preparation through the same existing foundation and two runtime kinds, real verification and fresh reconstruction. It took 19.5 seconds, and a cold foundation-validator consumer took 35 seconds overall. Nineteen canonical files matched the retained full-S1 image in content hash, ownership, mode and link count; seven profile targets and runtime generations/configuration matched. Only volatile `installed_at` was excluded from the runtime-row comparison. The complete ordinary S1 journey then passed all original assertions in 30 seconds. Its required coverage is retained.
- A cold hosted run prepares each missing snapshot once in the required shared preparation job instead of once per shard. Foundation preparation completes first; L2, L3 and L5 share one wave across the measured three lanes, and L4 follows L3 on the same lane. One builder thread prepares both special images within that lane capacity. A fully archived run loads no images. The exact-key archives are shared with every shard, and the preparation phase is measured against the same unchanged target and limit as a shard. All 87 items, all 25 validators and the egress control remain.
- A cold WordPress snapshot follows its actual L1 parent instead of unnecessarily preparing L2. Genuine L2 consumers still prepare and test L2. A successful cold HostFoundation preparation counts once only when its entire Scenario equals the originally selected required scenario; cached paths still run the ordinary HostFoundation scenario. Failed, missing or mismatched preparation results cannot receive credit.
- A cached descendant avoids unnecessary ancestor loads. Actual image restore, build, preparation, archive and cleanup remain timed. L5 archives are now saved rather than being silently omitted.
- Every hosted shard receives one run's shared fixture CA. Its certificate remains in every image key. Leaf certificates follow CA identity and use the existing native file-lock primitive during concurrent first creation. Main pushes can populate default-branch caches; PR-only artifacts are not promoted to main.

The unchanged PHP-fence profile attributed only 3.526 seconds of 120.4 seconds to ten full collects, so standing-read batching was rejected. Poll pacing reduced controller CPU in an eight-case experiment but changed 120.565 seconds to 119.785 seconds, within noise; no production polling change was retained.

## Further local controls

The original staged order with broader external instrumentation took 332 seconds; removing the external hooks and collectors reduced it to 317 seconds. All 87 native items, 102 browser tests and 25 validators passed. The joint stage was 42 seconds and controller-fast 30 seconds. These controls still missed the 300-second target. Instrumentation accounted for part of the difference; other run-to-run differences were not assigned a cause.

Using the retained full-S1 physical parent instead of the semantically equivalent minimal L1 took 373 seconds and passed 86 of 87 items. The minimum parent was restored. The PHP serving fixture failure exposed a sufficient OPcache race: a backdated file may still return cached content until timestamp revalidation. A checked restart of only the fixture site's FPM now makes its edited script visible before the unchanged route assertions. Isolation and serving then passed 2/2 in 39 seconds. This proof does not establish the historical failure's exact cause.

## Native read composition

A profile of the existing two-site read observed 34 proxy-process checks, 12 API accesses and 75 child processes. HAProxy 3.3 supports semicolon-separated commands with blank-line response framing. The candidate uses one existing guarded API access for the three fixed read-only status commands, strictly validates exactly three blocks, and preserves the original semantic parsers, socket and peer checks, output bound, deadline and outer process-generation checks. The corresponding profile observed 18 process checks, four accesses and 43 child processes, with parsed JSON equal except uptime. The five cache cases passed in 31.7 seconds after preparation on frozen source. A real native fault injects a proxy restart only after all three response blocks arrive and proves that the read refuses the changed process generation.

Other reader experiments were rejected. Combining privilege-check transport removed 328 SSH requests but saved only about 0.8 seconds in the five-case cache class. Exact-input Caddy adaptation reuse saved about one second in that class at the cost of a new binary-freshness reuse rule. A systemd GetAll probe saved about 2.2 milliseconds per process check but had no end-to-end proof and returned unrelated properties. None of those changes was adopted.

Guidance for the adopted composition is HAProxy's official 3.3 management guide, https://docs.haproxy.org/3.3/management.html. This combines supported commands through the existing adapter and adds no cache, native client or remote execution path.

## Latest candidate diagnostic

The HAProxy candidate passed all 87 native items in 294 seconds, or 295 seconds for its build stage. Controller-fast took 28 seconds, validators 40 seconds and browser tests 119 seconds. The complete build took 335 seconds and missed the unchanged target. Native time included missing L2 preparation at 5.4 seconds and L5 preparation at 31.1 seconds, plus their real lane setup and cleanup. Those costs are not removed from the measurement. Controller replay reported 98 failures and browser replay reported five failures against stale shared-read transcripts. This is not green qualification. All 31 real transcript captures and another strict full build are required.

## Strict local qualification

After all 31 real state captures and a successful recorder `--check`, the uninstrumented strict build passed in **292 seconds**, with unchanged source identity recorded by the verification runner. It used the keyed snapshots prepared in the preceding diagnostic and capture runs. It does not replace the recorded 335-second missing-layer result with a cold-pass claim.

| Stage | Measured | Result |
| --- | ---: | --- |
| Controller-fast | 30 s | 2,090 tests passed, existing one skip |
| Fast validators | 42 s | Six classes, all 25 tests passed |
| Joint fast stage | 42 s | Below 60 s |
| Browser | 105 s | All 102 tests passed |
| Native build stage | 250 s | All 87 items passed; runner 247 s |
| Complete strict build | 292 s | Below 300 s |

Ruff, strict mypy on 619 files, Vulture, template formatting/lint, shell checks, Django checks, migration consistency, frontend checks, production asset build and dependency audits passed. No required test was removed. The later qualification below records the independent final reviews and exact-head required CI.

## Hosted budget coverage

Legacy cold hosted run [41308365324](https://github.com/rajandangi/barectl/actions/runs/41308365324), shard 3, spent about 882 seconds in its native step. About 81.5 seconds preceded the old runner timer, missing-layer preparation took about 364.5 seconds of wall time, scenario execution about 413.2 seconds, and post-summary archives about 22.8 seconds. The new clock includes those actual native costs. That legacy cold result is a target miss, not qualified evidence, and warm reuse must not be described as proof of a cold 300-second phase.

The complete hosted phase now charges actual shared CA preparation, image work, missing-layer setup, validators and egress control on shard 1, scenarios and cleanup to the unchanged target. Boundary tests execute the actual workflow shell and prove 299/300 seconds pass, 301 seconds fails, previous failure statuses survive, invalid preparation durations fail, and a real child is interrupted at its remaining hard deadline.

The snapshot-backed qualification below records actual complete phases and cache identities. It does not claim that the historical all-cache-miss setup met 300 seconds.

## Hosted measurements at `7c14bed`

The first hosted attempt passed all 87 required native items. Every complete cold phase missed 300 seconds. The same-head repeat restored fixture and L1–L5, but still rebuilt L0. It passed 86 of 87 items; the 15-method runtime class reached its unchanged 180-second limit after 14 methods passed. Its first-attempt duration was 166.3 seconds. The retained logs do not identify a hung call.

| Shard | Cold complete phase | Cold items passed |
| ---: | ---: | ---: |
| 1 | 304 s | 6/6 |
| 2 | 571 s | 8/8 |
| 3 | 745 s | 8/8 |
| 4 | 522 s | 8/8 |
| 5 | 357 s | 9/9 |
| 6 | 549 s | 8/8 |
| 7 | 411 s | 8/8 |
| 8 | 645 s | 8/8 |
| 9 | 597 s | 8/8 |
| 10 | 732 s | 8/8 |
| 11 | 551 s | 8/8 |

The second attempt hit the same fixture CA and L1–L5 keys. L0 and mirror misses persisted because the combined cache action saves only on job success, and all first-attempt jobs failed their targets. The sole successful second-attempt shard finally saved those caches. [The version-matched action definition](https://github.com/actions/cache/blob/v6.1.0/action.yml) uses `post-if: success()`. The candidate now uses split restore/save steps with `always()`, requires a complete L0 archive, and saves a missed mirror only after successful fetch. Native preparation and Docker archive creation remain inside the existing timer. Hosted qualification remains incomplete.

The unchanged Integrity A/B/B/A fixture comparison passed all four runs but saved only 0.7 seconds on average, within noise. No fixture selection change was adopted from that warm result.

## Follow-up candidate

The fully restored two-lane run at `63205bd` had complete phases of 207, 347, 439, 269, 243, 340, 264, 369, 356, 431 and 298 seconds. Five met target. All cache layers hit, so the six remaining misses cannot be attributed to missing snapshots. RuntimeNativeBehavior passed, but PHPFence rejected a populated slice after restoration, producing one failed item among 87.

A controlled counterexample showed a legitimate new PHP85 cron invocation beginning 1.256692 seconds after timer restoration, populating the canonical slice and failing the old instantaneous idle assertion. It does not establish the historical failure's precise cause. The candidate places both empty-slice assertions around the native mask checks inside the actual fence: a held source-PHP HTTP request keeps the exact switch unit at its drain stage while the test proves both automation units runtime-masked, inactive and refusing manual starts, with an empty slice. It then releases the request, waits for the real result and verification, and retains serving, proxy identity, target wrapper, timer and result assertions. At final source `5a480aec`, all five cases passed in 60.3 seconds. A second complete run passed in 67.5 seconds with positively identified PHP84 cron work active before the fence and new PHP85 work after restoration. Both empty-slice reads saw the old process gone during the held fence. A stopped oneshot may retain failed state after its termination signal; the test requires PID zero, the masks and an empty slice, then starts the canonical service after restoration and requires a fresh successful completion. The real nondraining refusal remains 43 seconds. Setup failure cleanup is registered before fixture creation.

Five runtime-only reads in three methods now use the existing `collect(sites=False)` path. The same standing and runtime readers still run. Both recorded-state reads, passive-safety cases, direct unbound reload and constrained-host discovery remain full reads. All 15 native tests passed before and after, at 30.9 and 27.9 seconds locally. This is a modest paired observation, not hosted qualification.

The `d5186fb` candidate used three lanes on each of the same eleven standard runners. [GitHub specifies four CPUs and 16 GB for this public repository's standard runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories); no hardware or matrix capacity was added. Its 87 item weights came from the successful first hosted attempt at `7c14bed`, with explicit sources; the final refresh below replaces them with measured three-lane times. First-shard stage weights use the measured 104-second validator and 8-second egress commands from the fully restored `63205bd` run. The existing 90-second measured scheduling allowance remains unchanged. Predictions do not replace complete-phase and per-item qualification on the new head. After final source freeze, all 31 real states were freshly captured again and recorder `--check` passed. The frozen candidate then passed the strict local build in 293 seconds: controller-fast 30 seconds with all 2,091 tests and the existing one skip, all 25 validators in a 42-second joint stage, all 102 browser tests in 106 seconds, and all 87 native items in a 251-second native stage, 249 seconds in its runner. The updated five-case PHP fence took 79.4 seconds under the full build load; the 15-case runtime item took 58.8 seconds. Verification recorded unchanged source identity. The exact-head hosted result on the three-lane candidate follows below.

## Hosted qualification at `d5186fb`

[Native run 41343892143](https://github.com/rajandangi/barectl/actions/runs/41343892143) passed all eleven complete phase targets and all 87 required items, with no duplicate or omitted item names. The CA preparation charge was one second on each phase. Every shard used three lanes on the same standard runner and restored the same mirror, fixture and L0–L5 exact keys. This is a snapshot-hit run, not a cold setup result.

| Shard | Complete phase | Items passed |
| ---: | ---: | ---: |
| 1 | 270 s | 6/6 |
| 2 | 300 s | 9/9 |
| 3 | 247 s | 9/9 |
| 4 | 288 s | 8/8 |
| 5 | 217 s | 7/7 |
| 6 | 237 s | 7/7 |
| 7 | 263 s | 9/9 |
| 8 | 246 s | 7/7 |
| 9 | 274 s | 7/7 |
| 10 | 230 s | 9/9 |
| 11 | 252 s | 9/9 |

The longest item was FirewallLifecycle at 178.6 seconds, below the unchanged 180-second limit. RuntimeNativeBehavior passed all 15 tests in a 170.3-second item; PHPFence passed all five in 101.3 seconds. Shard 1 retained all six validator classes and 25 tests and its expected egress-refusal control. Controller, browser, frontend and dependency checks passed. Fresh independent Standards and Spec reviews found no actionable source issue.

The final `disposable/shard_times.json` refresh uses these 87 successful three-lane measurements, each tied to this run and revision. The earlier measured 104-second validator and 8-second egress stage weights and the 90-second scheduling allowance remain. The refreshed packing predicts a maximum 284 seconds; prediction is not qualification. Required checks must pass on the resulting head before merge.

## Final-head cache follow-up

[Run 41345661736](https://github.com/rajandangi/barectl/actions/runs/41345661736) at `9ffe12b` passed all 87 required items, with no duplicates or omissions. Its complete phases were 225, 257, 241, 287, 258, 293, 309, 257, 278, 288 and 261 seconds. Shard 7 alone missed the unchanged 300-second target. Its seven items passed, and the longest item across the run was SiteObjectCache at 170.8 seconds. Controller, browser, frontend and dependency checks passed. This head does not qualify for merge.

Shard 7's final NginxStanding server replacement took 52.751 seconds, including image ensure/load and server boot; its test took 18.275 seconds. The immutable shared L0 cache had been saved by a shard that did not require either special standing image. It therefore omitted `standing-26.04.tar` and `l0-24.04.tar`; subsequent ordinary L0 hits could not add those archives. The follow-up gives each special layer its own exact-key restore and save through the existing version-matched Actions cache operations. Legacy copies from the shared directory are discarded before the independent restores so an unrelated base-cache hit cannot authorize a stale special archive. The ordinary L0 cache remains compatible. Actual Docker load, missing-image build, archive creation and cleanup remain in the complete phase clock. No scenario weights, allocation, targets or limits change. The first consumer of a missing special archive must still build it and pay its real cost. Both independent delta reviews found no issues. After another complete real 31-state capture pass and successful receipt check, the frozen follow-up passed the strict local build in 292 seconds with unchanged source identity: controller-fast 30 seconds, all 2,092 tests with the existing one skip; all 25 validators in a 41-second joint stage; all 102 browser tests in 104 seconds; and all 87 native items in a 251-second native stage, 249 seconds in its runner. Exact-head hosted qualification of this follow-up remains pending.

### Cache-key boundary correction

[Run 41348484150](https://github.com/rajandangi/barectl/actions/runs/41348484150) at `fec31f23` passed all 87 unique required items, but shards 6 and 7 missed the complete-phase target at 304 and 301 seconds. Its longest item was FirewallLifecycle at 177.6 seconds. Logs exposed a defect in the special-cache implementation: the existing image-key CLI did not accept either special layer name. `echo` masked the failed command substitutions and published empty key suffixes. All special restores missed; two consumers saved under those empty-suffix keys. This run is not valid digest-keyed cache qualification. The ordinary keyed snapshots and all native assertions remained intact.

The correction exposes the two existing image layers through the CLI's accepted choices and assigns each CLI result before publishing it, allowing the workflow shell to stop on any CLI error. A regression executes the actual nine-key workflow block with real CLI calls and requires the exact special keys with their hash suffixes. Another executes the same block with CLI failures at both special layers and proves exit propagation without publishing the failed key. All 42 mirror tests passed in 8.371 seconds. The empty-suffix caches have different keys from the corrected digest-keyed entries and cannot be selected by the corrected workflow. After another complete real 31-state capture pass and successful receipt validation, the frozen correction passed the strict local build in 289 seconds with unchanged source identity. Controller-fast took 30 seconds for 2,094 tests with the existing one skip, all 25 validators passed in a 41-second joint stage, all 102 browser tests passed in 105 seconds, and all 87 native items passed in a 248-second native stage, 246 seconds in its runner. Exact-head hosted qualification remains required before merge.

### Corrected special-cache first fill

[Run 41351088130, attempt 1](https://github.com/rajandangi/barectl/actions/runs/41351088130/attempts/1) at `e655e6be` used valid special keys on every shard: `native-standing-Linux-X64-standing-26.04-bd8119581d7b` and `native-ubuntu24-Linux-X64-l0-24.04-672540d00402`. Both were initial misses on all eleven runners. Shards 10 and 2 respectively saved the completed standing and Ubuntu 24.04 archives under those keys. Its complete phases were 198, 256, 257, 301, 269, 304, 283, 263, 253, 250 and 252 seconds. All 87 unique items passed, with WordPressServerCron longest at 177.8 seconds. Shards 4 and 6 missed the phase target. Their standing-image server replacements took 65.265 and 52.359 seconds; that stage includes image ensure/load/build and container startup. First-fill work remains inside the clock, and this run does not qualify as a cold or target-compliant pass.

A controlled same-head run tests the newly saved exact keys separately. It does not replace or reinterpret the first-fill result. The following snapshot-backed qualification must retain this cache scope; no target, limit, scenario, allocation or timing weight changed between attempts.

### Snapshot-backed qualification at `e655e6be`

[Run 41351088130, attempt 2](https://github.com/rajandangi/barectl/actions/runs/41351088130/attempts/2) passed all eleven complete native phase targets on the unchanged source. Every runner restored both exact special-image keys recorded above, with 11/11 hits for each. The ordinary keyed snapshots remained in use. No timing weight, clock, target, limit, matrix size or lane allocation changed between attempts. These are complete phase measurements, including actual Docker image loading and cleanup, rather than job durations or predictions.

| Shard | Complete phase |
| ---: | ---: |
| 1 | 229 s |
| 2 | 235 s |
| 3 | 266 s |
| 4 | 257 s |
| 5 | 260 s |
| 6 | 235 s |
| 7 | 249 s |
| 8 | 264 s |
| 9 | 238 s |
| 10 | 224 s |
| 11 | 252 s |

All 87 unique required items passed, with no duplicates or omissions. The longest item was FirewallLifecycle at 177.0 seconds, below the unchanged 180-second limit. The five special-layer server replacements took 5.691–7.914 seconds after restore, compared with 36.155–65.265 seconds during first fill. Those stage observations include server replacement and image work; they do not isolate a Docker component or remove run-to-run variation. Controller, browser, frontend and dependency checks passed on this head. Final independent Standards and Spec reviews found no issues, including the actual CLI execution and failure-propagation regressions, the re-audited narrow future transcript exclusion, and the new real capture receipts. The final documentation-only publication retains this qualified source and remains subject to required checks before merge.

A separate external host-only preparation-read experiment passed its semantic guard and five unchanged cache cases but improved 32.0 to 28.6 seconds in one pair, below its adoption threshold. No product collector or observation contract was changed.

## Guidance and decisions

The project follows [Django's class-level parallel test guidance](https://docs.djangoproject.com/en/6.1/ref/django-admin/#cmdoption-test-parallel). Snapshot reuse uses existing [Actions cache scoping and exact keys](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching), [same-run artifact sharing](https://docs.github.com/en/actions/tutorials/store-and-share-data#passing-data-between-jobs-in-a-workflow) and [explicit cache save](https://github.com/actions/cache/tree/main/save#always-save-cache). Leaf coordination reuses [Python 3.14 flock](https://docs.python.org/3.14/library/fcntl.html#fcntl.flock), and build command deadlines use [BSD timeout](https://man.freebsd.org/cgi/man.cgi?query=timeout&sektion=1&format=html) and [GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html). No new package, certificate client, execution path or scheduler was added.
