# Test budget qualification

[#479](https://github.com/rajandangi/barectl/issues/479) owns this work. The targets in [quality](quality.md#test-time-budget) remain 60 seconds for the joint fast stage, 90 seconds for controller-fast, 180 seconds per native item, and 300 seconds for a full local build or complete hosted shard, with the 900-second build hard limit. This record is in progress. All 31 native transcript states were freshly captured successfully after preliminary review and source freeze. The strict local build passed as recorded below. Exact-head hosted qualification remains required.

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

The 16-lane trial sampled a peak of 6.27 GiB Docker guest memory and 11.24 CPU equivalents, within the unchanged allocation. Controller-process memory peaked at 3.36 GiB on the 64 GiB host. Early guest samples are missing for part of the 8-lane trial; its controller samples are complete. The default is now bounded by `min(16, floor(CPUs / 0.875), floor(Docker VM GiB / 0.5))`. The cap prevents extrapolation beyond the measured 16-lane capacity. Hosted shards retain their explicit two lanes pending hosted evidence.

`disposable/local_times.json` contains actual per-item measurements from the successful 16-lane trial, its source and artifact digests, and allocation. It orders only unsharded local native work. Hosted scheduling retains its separate `disposable/shard_times.json`; local times do not replace hosted measurements. `disposable/validator_times.json` retains actual validator measurements. In a controlled two-lane comparison, weighted validator packing reduced 43 seconds to 33 seconds, with all classes and assertions retained.

The build starts controller-fast, validators and browser tests together, then native work after both fast gates finish. Delaying browser startup until the native phase was rejected after a 351-second diagnostic, with a 42-second joint stage and all 87 native items passing. That trial also included broader observation instrumentation, so its difference is not attributed solely to ordering. Its original wall clock includes the wait. The native command receives only the remainder of the original 900-second deadline. Each fixed build gate also runs under GNU/BSD `timeout` for its remaining original deadline. Expired gates record failure without launching setup; a positive remainder interrupts real setup and reaps its child in the regression proof. The general foreground runner remains unbounded for long transcript passes. No required stage is moved out of the build.

## Work removed and coverage retained

- Cron and PHP-fence scenarios reuse the existing product-created WordPress/database snapshot. They still configure and verify real HTTPS. The fence setup starts the existing cron service after the ordinary enable body reaches its tick stage, then waits for the real result and verification. The cron scenario separately proves initial and further automatic timer ticks with SSH closed. All five fence cases and its real nondraining deadline remain.
- Cold consumers that do not select the complete S1 journey use minimal foundation preparation through the same existing foundation and two runtime kinds, real verification and fresh reconstruction. It took 19.5 seconds, and a cold foundation-validator consumer took 35 seconds overall. Nineteen canonical files matched the retained full-S1 image in content hash, ownership, mode and link count; seven profile targets and runtime generations/configuration matched. Only volatile `installed_at` was excluded from the runtime-row comparison. The complete ordinary S1 journey then passed all original assertions in 30 seconds. Its required coverage is retained.
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

Ruff, strict mypy on 619 files, Vulture, template formatting/lint, shell checks, Django checks, migration consistency, frontend checks, production asset build and dependency audits passed. No required test was removed. Independent final reviews and exact-head required CI remain to be recorded.

## Hosted qualification still required

Legacy cold hosted run [41308365324](https://github.com/rajandangi/barectl/actions/runs/41308365324), shard 3, spent about 882 seconds in its native step. About 81.5 seconds preceded the old runner timer, missing-layer preparation took about 364.5 seconds of wall time, scenario execution about 413.2 seconds, and post-summary archives about 22.8 seconds. The new clock includes those actual native costs. That legacy cold result is a target miss, not qualified evidence, and warm reuse must not be described as proof of a cold 300-second phase.

The complete hosted phase now charges actual shared CA preparation, image work, missing-layer setup, validators and egress control on shard 1, scenarios and cleanup to the unchanged target. Boundary tests execute the actual workflow shell and prove 299/300 seconds pass, 301 seconds fails, previous failure statuses survive, invalid preparation durations fail, and a real child is interrupted at its remaining hard deadline.

Exact-head hosted cold and reused-snapshot results, cache identities, final strict local results, independent reviews and the merged revision will be added before completion.

## Guidance and decisions

The project follows [Django's class-level parallel test guidance](https://docs.djangoproject.com/en/6.1/ref/django-admin/#cmdoption-test-parallel). Snapshot reuse uses existing [Actions cache scoping and exact keys](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching), [same-run artifact sharing](https://docs.github.com/en/actions/tutorials/store-and-share-data#passing-data-between-jobs-in-a-workflow) and [explicit cache save](https://github.com/actions/cache/tree/main/save#always-save-cache). Leaf coordination reuses [Python 3.14 flock](https://docs.python.org/3.14/library/fcntl.html#fcntl.flock), and build command deadlines use [BSD timeout](https://man.freebsd.org/cgi/man.cgi?query=timeout&sektion=1&format=html) and [GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html). No new package, certificate client, execution path or scheduler was added.
