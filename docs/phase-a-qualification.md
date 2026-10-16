# Phase A qualification record

This record lists the evidence for the Phase A exit of specification [#325](https://github.com/rajandangi/barectl/issues/325), gathered on 2026-10-17 for [#341](https://github.com/rajandangi/barectl/issues/341). It names the revisions tested, what ran on each architecture, the measured times against the budget of [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), and what is not qualified. Anything this record does not list as passing is not qualified. Phase A is not released.

## Revisions

| Evidence | Revision |
| --- | --- |
| Full local build, arm64 | `1b97ed6` on `upgrade/341-qualification`, the integration head `47ddea8` plus this issue's leftover-code fixes and re-recorded transcripts |
| Hosted Checks, Native and Runtime catalog, amd64 | `47ddea8`, head of `upgrade/325-foundation-integration` ([PR #352](https://github.com/rajandangi/barectl/pull/352)) |
| Weekly arm64 job | No run yet; the job runs on Sundays from `main` |

The difference between the two revisions is the removal of two old operation kinds from a database constraint, one site name length rule, the overview's setup guidance and some interface text. No hosted Native run exists for `1b97ed6`.

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Local full build | arm64 | Apple M4 Pro, 14 CPUs, 64 GiB, macOS 27.2; OrbStack 7.2.9 with Docker Engine 29.8.2, 14 CPUs and 15.7 GiB for the VM; 8 lanes by the lane formula | Ubuntu 26.04.1 LTS by the digest in `docker/disposable-server/pins.json`, systemd 259.5-0ubuntu3.4, the kernel shared with OrbStack's VM |
| Hosted Native | amd64 | GitHub's `ubuntu-26.04` runners, 2 shards | The same image |

Both use the catalog lock at nixpkgs `7c8764b7c7b09b34f632464276218ef9090eaa11` and Nix 2.35.2. The L1 snapshot runs Caddy 2.11.7, PHP 8.4.26, PHP 8.5.11 and HAProxy 3.3.11. The controller runs Python 3.14 and Django 6.1.1.

## Build budget

`docker/disposable-server/build.sh` on `1b97ed6`, with the keyed L1 snapshot already built by S1 earlier on the same host:

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Full build, wall time | 312 s | 600 s | 900 s | Meets the target |
| Native lifecycle scenarios, 46 of 46 passed | 312 s | | | |
| Longest scenario | 127.5 s (`SitePHPIsolation`) | | 180 s | Within the item limit |
| Controller fast tests, 633 tests with `--parallel` | 157 s | 90 s ([fast gate](quality.md#before-every-push)) | | Misses the target |
| Fast snapshot validators | 177 s | | | |
| Joint fast stage | 177 s | 60 s | | Misses the target |
| Browser tests | 43 s | | | |

Hosted Native on `47ddea8`, amd64:

| Job | Wall time | Reported by the runner |
| --- | --- | --- |
| Shard 1 | 15 min 48 s | Fast validators 5 of 5 in 356 s, including preparing L1 through S1; lifecycle scenarios 23 of 23 in 566 s |
| Shard 2 | 16 min 30 s | Lifecycle scenarios 23 of 23 in 967 s, including preparing L1 through S1 |
| Required `native` check | Passed | |

Hosted Checks passed in 223 s and Runtime catalog in 36 s on the same head. The last daily drift job passed on `main` on 2026-10-16.

## Scenarios S1 to S10

Each row lists the scenario classes that carry the specification's scenario and the longest time each took. The local column is the full build above; the amd64 column is the hosted run on `47ddea8`.

| Scenario | Classes | Local arm64 | amd64 |
| --- | --- | --- | --- |
| S1 Fresh host to two runtimes | `HostFoundation`, `RuntimeNativeBehavior` | 58.0 s, 52.1 s | 135.9 s, 142.0 s |
| S2 Admission refusals | `FoundationAdmission`, `AptDailyActive` | 4.3 s, 2.3 s | 9.7 s, 7.4 s |
| S3 Lost controller | `HttpSiteControllerRecovery`, `SitePHPControllerRecovery` | 30.8 s, 96.6 s | 40.2 s, 124.2 s |
| S4 Plain PHP site over HTTP | `HttpSiteNativeBehavior`, `HttpSiteSecurityBehavior` | 76.0 s, 50.0 s | 106.3 s, 62.6 s |
| S5 Shared-runtime isolation and reconstruction | `SitePHPIsolation`, `FreshControllerReconstruction`, `HttpSiteReconstruction` | 127.5 s, 117.1 s, 64.9 s | 150.9 s, 139.2 s, 81.0 s |
| S6 Switch without gap | `SitePHPServing`, `SitePHPQueuedDrain`, `SitePHPLongDrain`, `SitePHPDetachedDrain` | 102.0 s, 91.3 s, 94.2 s, 91.2 s | 113.1 s, 102.6 s, 111.5 s, 102.4 s |
| S7 Server defaults | `ServerRuntimeDefaults`, `SiteNodeSelection` | 42.1 s, 117.1 s | 73.6 s, 142.1 s |
| S8 Failed Caddy reload | `HttpSiteTransactions` | 24.0 s | 23.4 s |
| S9 Judge by shape | `JudgeByShape` | 113.4 s | 140.2 s |
| S10 Two controllers race | `TwoControllerNativeLock` | 54.6 s | 86.6 s |

The per-scenario maximum is 127.5 s on arm64 and 150.9 s on amd64, both `SitePHPIsolation` and both under the 180 s item limit. Every other native class in the set, such as the host-standing, validator and Node cases, also passed on both architectures.

What these classes assert:

- S1 sets up the foundation through a saved connection with fingerprint confirmation, adds php84 and php85, and a fresh controller reviews no changes.
- S2 refuses with `apt_active` while apt-daily or its lingering children run and with `lock_busy` while the native lock is held, and creates no `/nix` or `/etc/caddy`.
- S3 kills the worker while a site creation runs; a second database finds the run succeeded and the site managed. A separate scenario kills a PHP change's unit and a fresh controller finishes or reverses it from native evidence.
- S4 checks that the public TCP listeners are 22 and 80 only, and that a site account cannot open Caddy's admin socket or reach the Nix daemon.
- S5 runs two sites on one runtime and a third on the other. From one site's PHP worker, `opcache_get_status`, `opcache_reset` and a listing of another site's session directory fail. Two controllers with empty databases, key-file connections and their own fingerprint confirmation observe the same state and propose no changes.
- S6 switches a site's runtime in both directions while fixed sets of in-flight and queued requests all return 200, effects run once, and requests longer than 30 s are not cut off.
- S7 sets PHP and Node defaults, runs them through the plain commands, and leaves existing sites unchanged.
- S8 makes a validated candidate fail to load; the old file is restored and the old configuration keeps serving.
- S9 adopts supported hand edits and scopes an unsupported one to its site.
- S10 lets two controllers race one change; one run succeeds and the other is refused with `lock_busy`.

## Qualification items

| Item | Result |
| --- | --- |
| OPcache protections block cross-pool access | Partly proven. `opcache_get_status` and `opcache_reset` fail from another site's worker. No scenario reads another pool's cached script. |
| Per-pool sessions are private | Proven by S5's session directory listing, with a positive control on the site's own sessions. |
| Profile switch atomicity of `nix-env --set` under `max-jobs 0` | Proven by `ProfileSwitchAtomicity`. With `max-jobs = 0` in effect from `nix.conf`, `nix-env --set` creates a profile from the php84 build and then switches it 40 times between the php84 and php85 builds, as the add-runtime body calls it. A reader polling the profile for the whole run never finds it missing once it exists and never resolves it to anything but one of the two builds, each with its `bin` directory. Each call adds exactly one generation, prints no build, download or copy, and leaves the store's path list unchanged. Nix replaces the profile link by renaming a new link over it ([`replaceSymlink`](https://github.com/NixOS/nix/blob/2.35.2/src/libutil/file-system.cc)); polling cannot see a window shorter than one read, which that rename does not have. |
| Composer under another runtime's PHP | Proven through the server-wide default wrappers: for php84 and php85, Composer reports the selected runtime's `PHP_BINARY`. Not proven through a site's own `bin/composer`. |
| `caddy validate` as `caddy` binds no ports and orders nothing | Proven by `HttpSiteValidators`. The production whole-tree validation, run as `caddy`, succeeds inside a systemd sandbox that allows only Unix sockets and makes `bind` and `listen` fail with `EPERM`, so it opens no network socket, binds nothing and can place no certificate order. Two controls in the same sandbox show the denial works: an IPv4 socket fails with `EAFNOSUPPORT`, a Unix `bind` with `EPERM`, and `caddy respond --listen 127.0.0.1:0` exits with an error instead of serving. Listening sockets and the files under `/etc/caddy` and `/var/lib/caddy` are unchanged afterwards. |
| Reload refusal window of a master restart | Measured by `SitePHPMasterRestart` on one site with a request held for 2 s and a client sending one request every 20 ms: `systemctl restart php-fpm-site-php84@<id>` lets the held request finish with 200 and its effect recorded once, then starts the new master. Every refused request, 502 or 503, falls inside the restart and every later request returns 200. In each of three measured runs 2 of 58 requests were refused, over a window of 2.14 to 2.15 s within a 2.32 to 2.33 s restart: the 2 s the held request still ran plus about 0.15 s for the new master to start. Requests that arrive while the old master waits fail when it exits. This needed a fix: FPM's default `process_control_timeout = 0` ended running requests as soon as a site master stopped, so the restart finished in well under 2 s and cut the held request. Site masters now set `process_control_timeout = 1d` ([site conventions](site-conventions.md)). |
| In-flight requests across a pool reload | Answered by `SitePHPMasterRestart`: they do not survive. A request running in a runtime master's diagnostic pool when `systemctl reload php-fpm@php84` runs returns nothing, while the same request without a reload completes; FPM's default `process_control_timeout = 0` ends it. The same reload leaves a site's in-flight and following requests at 200 and its master's PID and invocation unchanged, because application pools run only in per-site masters ([ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md)), which have no reload. Pool changes on a shared master therefore keep Shared consent. |

## Operator recovery

`SitePHPMasterRestart` follows the [recovery guide](recovery.md) on an S1 server with one site: it runs each command of the inspecting and restarting sections exactly as written, as root, with the site's identifier in place of `<id>`, then reads the site's FPM journal, HAProxy journal, Caddy journal and access log as its table names them. Each command exits 0; the profile listing shows php84, the site's error log holds the warning a request wrote, the access log holds that request, every restarted service is active again and the site serves. Two commands failed as first written and the guide is corrected: `nix-env` is not on `sudo`'s path or a non-login root shell's, so it is called by its full path, and the HAProxy API read used `socat`, which an Ubuntu server does not have, so it uses `python3`. The guide's restart note now says what the restart measurement above shows.

## Memory and disk

Measured on the local arm64 build. No minimum host size is claimed.

| Measure | Value | Source |
| --- | --- | --- |
| Whole server after the foundation and two runtimes, under a 1 GiB memory limit | 68.5 MiB current, 110 MiB peak (cgroup `memory.current` and `memory.peak`) | `RuntimeSmallHost` |
| Each runtime's diagnostic master with its one static worker | 11.3 MiB (php84) and 11.5 MiB (php85), systemd `MemoryCurrent` | `RuntimeSmallHost` |
| Three sites' HAProxy and PHP-FPM serving processes | 79,097 KiB (77 MiB) PSS in total | `SitePHPIsolation` |
| `/nix` after the foundation and two runtimes | 651 MiB | `du -sxm` in the L1 image |
| Root filesystem growth from L0 to L1 | 233 MiB to 892 MiB | `du -sxm /` in each image |

The disk used by three sites and the memory of the whole server with three sites were not measured.

## Not qualified

- **The fast layer misses its targets.** The controller fast tests take 157 s against the 90 s fast-gate target, and the joint fast stage 177 s against 60 s.
- **Hosted Native exceeds the build limit.** Each amd64 shard ran for about 16 minutes. Shard 2 reported 967 s of scenario time, over the 900 s limit, and the runner did not stop it. Both shards prepared L1 through S1 instead of restoring it from cache. CI runs 2 shards, where the specification names 4.
- **No arm64 CI evidence.** The weekly arm64 job has not run yet. The arm64 evidence is the local build only.
- **The local build reused L1.** The 312 s build started with the keyed L1 snapshot already built on the host. A build that must first prepare L1 through S1 was not timed on `1b97ed6`.
- **Not run on the hosted runners at `1b97ed6`.** The amd64 results belong to `47ddea8`.
- **Scenario points not asserted.** S5 does not read another pool's cached script. S6 uses fixed request sets, not a continuous request loop counting refused requests. S3's site-creation case confirms the outcome by discovery from a second database; only the PHP change case finishes a run from native evidence.
- **Recovery after a stopped change.** `SitePHPMasterRestart` runs every command in the [recovery guide](recovery.md)'s inspecting and restarting sections, as written, as root on an S1 server with one site, plus the site's journal, HAProxy and access-log reads from its table. The numbered steps after a stopped change depend on Barectl's run page and were not followed by hand.
- **Other hosts.** No real VM, cloud image or provider host was tested, no real kernel reboot, and nothing on 1, 2 or 4 GiB hosts beyond the 1 GiB memory limit of `RuntimeSmallHost`.
