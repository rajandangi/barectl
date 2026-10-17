# Phase A qualification record

This record lists the evidence for the Phase A exit of specification [#325](https://github.com/rajandangi/barectl/issues/325), gathered on 2026-10-17 for [#341](https://github.com/rajandangi/barectl/issues/341). It names the revision tested, what ran on each architecture, the measured times against the budget of [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), and what is not qualified. Anything this record does not list as passing is not qualified. Phase A is not released.

The last revision with the old stack, before its deletion, is tagged [`v0.3-old-stack-final`](https://github.com/rajandangi/barectl/tree/v0.3-old-stack-final).

## Revisions

Every number below belongs to one code revision, `dc48218` on `upgrade/341-review-fixes` ([PR #354](https://github.com/rajandangi/barectl/pull/354)), the integration head `56b0f1f` plus the review fixes of #340 and #341 and all transcripts re-recorded on it. Later commits on that branch change documentation only.

| Evidence | Where |
| --- | --- |
| Full local build, arm64, L1 prepared through S1 inside the build | `dc48218` |
| Hosted Checks and Native (4 shards), amd64 | `dc48218` on PR #354: Checks run [38986645951](https://github.com/rajandangi/barectl/actions/runs/38986645951), Native run [38986646193](https://github.com/rajandangi/barectl/actions/runs/38986646193). The Runtime catalog workflow does not run, because the catalog files are unchanged. |

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Local full build | arm64 | Apple M4 Pro, 14 CPUs, 64 GiB, macOS 27.2; OrbStack 7.2.9 with Docker Engine 29.8.2, 14 CPUs and 15.7 GiB for the VM; 8 lanes by the lane formula | Ubuntu 26.04.1 LTS by the digest in `docker/disposable-server/pins.json`, systemd 259.5-0ubuntu3.4, the kernel shared with OrbStack's VM |
| Hosted Native | amd64 | GitHub's `ubuntu-26.04` runners, 4 shards of 2 lanes | The same image |

Both use the catalog lock at nixpkgs `7c8764b7c7b09b34f632464276218ef9090eaa11` and Nix 2.35.2. The L1 snapshot runs Caddy 2.11.7, PHP 8.4.26, PHP 8.5.11 and HAProxy 3.3.11. The controller runs Python 3.14 and Django 6.1.1.

## Build budget

`docker/disposable-server/build.sh` on `dc48218`, cold: the keyed L1 image was deleted first, so the native and validator stages each prepared L1 through the real S1 flow inside the build.

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Full build, wall time | 159 s | 600 s | 900 s | Meets the target |
| Native lifecycle scenarios, 48 of 48 passed, including S1 | 159 s | | | |
| Longest scenario | 40.7 s (`SitePHPLongDrain`) | | 180 s | Within the item limit |
| Controller fast tests, 647 tests with `--parallel` | 22 s | 90 s ([fast gate](quality.md#before-every-push)) | | Meets the target |
| Fast snapshot validators, 3 items, including S1 (42.1 s) | 88 s | | | |
| Joint fast stage | 88 s | 60 s | | Misses the target while it prepares L1; with L1 present the validator items take about 35 s |
| Browser tests | 42 s | | | |

Hosted Native on `dc48218`, amd64, run [38986646193](https://github.com/rajandangi/barectl/actions/runs/38986646193). The L1 key changed with this revision, so every shard missed the L1 cache and prepared L1 through S1 inside its 900 s stop:

| Shard | Job wall time | Reported by the runner |
| --- | --- | --- |
| 1 of 4 | 8 min 25 s | Fast validators 3 of 3 in 214 s, including S1; egress control; lifecycle scenarios 12 of 12 in 219 s |
| 2 of 4 | 7 min 43 s | 12 of 12 in 412 s, including S1 |
| 3 of 4 | 6 min 33 s | 12 of 12 in 341 s, including S1 |
| 4 of 4 | 6 min 15 s | 12 of 12 in 316 s, including S1 |
| Required `native` check | Passed | |

The longest shard reported 412 s of scenario time, within the 600 s target; the longest item was `HostFoundation` at 117.7 s. Hosted Checks passed: `check` in 1 min 45 s and `browser` in 1 min 39 s.

The 900 s build stop is enforced by the runner and has harness tests (`disposable.test_scenarios.BuildStopTests`): an item still running at the limit is interrupted and the runner reports the limit reached, and the time spent preparing L1 through S1 is taken from the same limit before the remaining scenarios start. In CI, each shard computes one deadline 900 s after the shard's native step starts and passes what remains to each stage as `--time-limit`. No run has reached the stop.

The fast-layer times come from these changes, in order of effect:

- Every native probe of the runtime and site readers ran under `/usr/bin/timeout`, which on Ubuntu 26.04 is uutils coreutils 0.8.0; its wait loop polls every 100 ms. One site read runs about 94 probes and took about 10 s, of which about 9.5 s was spent in `timeout`. The readers now keep each probe's bound themselves ([bounds](ssh-connections.md#bounds-and-read-only-commands)); the decision and alternatives are recorded on #341. This also shortens the same reads on real servers.
- The in-process SSH server of the fast tests waited a fixed 50 ms before answering each command. It now answers once paramiko has sent the request's acknowledgement, and after the client has ended its input.
- The seven transport workflow tests were one class, which Django's parallel runner keeps on one worker, and took 37 s there. They are now three classes.
- The three Node validator cases each prepared the same runtime and site. They now share one prepared site in one item.

Faster probes exposed a race in site creation: systemd reports a `Type=simple` unit running as soon as it forks, and creation read the new proxy before haproxy had executed. Creation now waits for the proxy to be ready. S10 had relied on the first run still holding the lock when the second controller applied; it now freezes the winning run's unit while the second applies.

## Scenarios S1 to S10

Each row lists the scenario classes that carry the specification's scenario and the time each took: the local column is the build above, the amd64 column the hosted run, each item's longest time.

| Scenario | Classes | Local arm64 | amd64 |
| --- | --- | --- | --- |
| S1 Fresh host to two runtimes | `HostFoundation`, `RuntimeNativeBehavior` | 39.6 s, 29.3 s | 117.7 s, 117.1 s |
| S2 Admission refusals | `FoundationAdmission`, `AptDailyActive` | 3.9 s, 2.2 s | 11.6 s, 8.7 s |
| S3 Lost controller | `HttpSiteControllerRecovery`, `SitePHPControllerRecovery` | 10.9 s, 16.6 s | 25.5 s, 43.1 s |
| S4 Plain PHP site over HTTP | `HttpSiteNativeBehavior`, `HttpSiteSecurityBehavior` | 15.2 s, 25.1 s | 42.9 s, 37.8 s |
| S5 Shared-runtime isolation and reconstruction | `SitePHPIsolation`, `FreshControllerReconstruction`, `HttpSiteReconstruction` | 19.4 s, 33.7 s, 11.6 s | 48.1 s, 93.4 s, 25.9 s |
| S6 Switch without gap | `SitePHPServing`, `SitePHPQueuedDrain`, `SitePHPLongDrain`, `SitePHPDetachedDrain` | 14.9 s, 22.9 s, 40.7 s, 23.4 s | 33.9 s, 42.4 s, 53.6 s, 41.7 s |
| S7 Server defaults | `ServerRuntimeDefaults`, `SiteNodeSelection` | 17.5 s, 21.1 s | 43.8 s, 56.8 s |
| S8 Failed Caddy reload | `HttpSiteTransactions` | 24.0 s | 24.3 s |
| S9 Judge by shape | `JudgeByShape` | 17.0 s | 45.3 s |
| S10 Two controllers race | `TwoControllerNativeLock` | 19.3 s | 47.7 s |

S5's three classes together took 64.7 s on arm64 and 167.4 s on amd64, within the specification's 3-minute scenario limit. Every other native class in the set, such as the host-standing, validator, Node and qualification cases, also passed.

What these classes assert:

- S1 sets up the foundation through a saved connection with fingerprint confirmation, adds php84 and php85, and a fresh controller reviews no changes.
- S2 refuses with `apt_active` while apt-daily or its lingering children run and with `lock_busy` while the native lock is held, and creates no `/nix` or `/etc/caddy`.
- S3 kills the worker while a site creation runs; a second database finds the run succeeded and the site managed. A separate scenario kills a PHP change's unit and a fresh controller finishes or reverses it from native evidence.
- S4 checks that the public TCP listeners are 22 and 80 only, and that a site account cannot open Caddy's admin socket or reach the Nix daemon.
- S5 runs two sites on one runtime and a third on the other. From one site's PHP worker, `opcache_get_status`, `opcache_reset`, a listing of another site's session directory, another site's file, sockets and cached script all fail. Two controllers with empty databases, key-file connections and their own fingerprint confirmation observe the same state, including a Node default and a site's Node selection, and propose no changes. The fast replay of its checkpoint recognizes the foundation, runtimes and their masters, both defaults, every Caddy site file and pool, and the site's Node command links.
- S6 switches a site's runtime in both directions while fixed sets of in-flight and queued requests all return 200, effects run once, and requests longer than 30 s are not cut off.
- S7 sets PHP and Node defaults, runs them through the plain commands, and leaves existing sites unchanged.
- S8 makes a validated candidate fail to load; the old file is restored and the old configuration keeps serving.
- S9 adopts supported hand edits and scopes an unsupported one to its site. Fast tests render the Stack, overview and site pages from its recorded checkpoint: the unsupported pool is reported once, and only the adopted sites offer a fresh PHP review.
- S10 lets two controllers race one change; one run succeeds and the other is refused with `lock_busy`. A fast test checks a run against the refused unit's recorded evidence and renders its run page: refused before any change, with a new review needed.

## Qualification items

| Item | Result |
| --- | --- |
| OPcache protections block cross-pool access | Proven by S5. From one site's PHP worker, `opcache_get_status` and `opcache_reset` fail. Beta and gamma run the same php84 build in their own masters: a script requested from beta is listed among beta master's cached scripts and not among gamma's, read through each master's diagnostic pool by a root-owned script in the OPcache API directory, and gamma's worker can neither include it nor compile it with `opcache_compile_file`. |
| Per-pool sessions are private | Proven by S5's session directory listing, with a positive control on the site's own sessions. |
| Profile switch atomicity of `nix-env --set` under `max-jobs 0` | Proven by `ProfileSwitchAtomicity`. With `max-jobs = 0` in effect from `nix.conf`, `nix-env --set` creates a profile from the php84 build and then switches it 40 times between the php84 and php85 builds, as the add-runtime body calls it. A reader polling the profile for the whole run never finds it missing once it exists and never resolves it to anything but one of the two builds, each with its `bin` directory. Each call adds exactly one generation, prints no build, download or copy, and leaves the store's path list unchanged. Nix replaces the profile link by renaming a new link over it ([`replaceSymlink`](https://github.com/NixOS/nix/blob/2.35.2/src/libutil/file-system.cc)); polling cannot see a window shorter than one read, which that rename does not have. |
| Composer under another runtime's PHP | Proven through the server-wide default wrappers: for php84 and php85, Composer reports the selected runtime's `PHP_BINARY`. Not proven through a site's own `bin/composer`. |
| `caddy validate` as `caddy` binds no ports and orders nothing | Proven by `HttpSiteValidators`. The production whole-tree validation, run as `caddy`, succeeds inside a systemd sandbox that allows only Unix sockets and makes `bind` and `listen` fail with `EPERM`, so it opens no network socket, binds nothing and can place no certificate order. Two controls in the same sandbox show the denial works: an IPv4 socket fails with `EAFNOSUPPORT`, a Unix `bind` with `EPERM`, and `caddy respond --listen 127.0.0.1:0` exits with an error instead of serving. Listening sockets and the files under `/etc/caddy` and `/var/lib/caddy` are unchanged afterwards. |
| Reload refusal window of a master restart | Measured by `SitePHPMasterRestart` on one site with a request held for 2 s and a client sending one request every 20 ms: `systemctl restart php-fpm-site-php84@<id>` lets the held request finish with 200 and its effect recorded once, then starts the new master. Every refused request, 502 or 503, falls inside the restart and every later request returns 200. In the build below 2 of 59 requests were refused, over a window of 2.13 s within a 2.30 s restart: the 2 s the held request still ran plus about 0.15 s for the new master to start. Requests that arrive while the old master waits fail when it exits. FPM's default `process_control_timeout = 0` would end running requests as soon as a site master stops, so site masters set `process_control_timeout = 300s`, the longest `request_terminate_timeout` a pool may have, and their unit stops within 310 s ([site conventions](site-conventions.md)); the scenario reads both bounds from the running unit and configuration. A stop or restart therefore holds the native lock for at most about five minutes, within an apply's 30-minute limit. |
| In-flight requests across a pool reload | Answered by `SitePHPMasterRestart`: they do not reliably survive. A request already running in a runtime master's diagnostic pool when `systemctl reload php-fpm@php84` runs usually returns nothing, while the same request without a reload completes; FPM's default `process_control_timeout = 0` ends it. In the final runs 24 of 24 sampled reloads ended the running request; in an earlier run one reload of six let it finish, so the scenario asserts only that a reload can end one. The same reload leaves a site's in-flight and following requests at 200 and its master's PID and invocation unchanged, because application pools run only in per-site masters ([ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md)), which have no reload. Each site's pools run only in that site's own masters, so a change to a site's pool affects that site alone. |

## Operator recovery

`SitePHPMasterRestart` follows the [recovery guide](recovery.md) on an S1 server with one site: it runs each command of the inspecting and restarting sections exactly as written, as root, with the site's identifier in place of `<id>`, then reads the site's FPM journal, HAProxy journal, Caddy journal and access log as its table names them. Each command exits 0; the profile listing shows php84, the site's error log holds the warning a request wrote, the access log holds that request, every restarted service is active again and the site serves. Two commands failed as first written and the guide is corrected: `nix-env` is not on `sudo`'s path or a non-login root shell's, so it is called by its full path, and the HAProxy API read used `socat`, which an Ubuntu server does not have, so it uses `python3`. The guide's restart note now says what the restart measurement above shows.

## Memory and disk

Measured on the local arm64 build. No minimum host size is claimed.

| Measure | Value | Source |
| --- | --- | --- |
| Whole server after the foundation and two runtimes, under a 1 GiB memory limit | 68.5 MiB current, 110 MiB peak (cgroup `memory.current` and `memory.peak`) | `RuntimeSmallHost` |
| Each runtime's diagnostic master with its one static worker | 11.3 MiB (php84) and 11.5 MiB (php85), systemd `MemoryCurrent` | `RuntimeSmallHost` |
| Whole S5 server with three sites, after one site's PHP switch | 158 MiB current, 206 MiB peak (container cgroup `memory.current` and `memory.peak`) | `SitePHPIsolation` |
| Three sites' HAProxy and PHP-FPM serving processes | 81,104 KiB (79 MiB) PSS in total | `SitePHPIsolation` |
| Disk of the three-site S5 server | 909 MiB root filesystem, of which 651 MiB `/nix`; `/var/www` and `/etc/php-fpm/sites` under 1 MiB each (`du -sxm`) | `SitePHPIsolation` |
| Root filesystem growth from L0 to L1 | 233 MiB to 892 MiB | `du -sxm /` in each image |

The memory and PSS figures above for one host are from different scenarios and are not additive. The 1 GiB figures predate this revision.

## Not qualified

- **Recovery guide followed once by hand.** Open: the numbered steps after a stopped change depend on Barectl's run page and need the maintainer to follow them once on a real server. `SitePHPMasterRestart` runs the guide's inspecting and restarting commands only.
- **The joint fast stage misses its 60 s target** when it must prepare L1 through S1, as in the cold build above.
- **One arm64 CI run.** The weekly arm64 job has passed once, by dispatch on #353, before this revision; no scheduled Sunday run from `main` exists yet.
- **Scenario points not asserted.** S6 uses fixed request sets, not a continuous request loop counting refused requests. S3's site-creation case confirms the outcome by discovery from a second database; only the PHP change case finishes a run from native evidence.
- **A request running past 300 s at a master stop.** The 300 s and 310 s bounds are read from the running unit; no scenario holds a request that long, which would exceed the 180 s item limit.
- **Other hosts.** No real VM, cloud image or provider host was tested, no real kernel reboot, and nothing on 1, 2 or 4 GiB hosts beyond the 1 GiB memory limit of `RuntimeSmallHost`.
