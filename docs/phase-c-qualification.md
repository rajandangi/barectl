# Phase C qualification record

This record lists the evidence for the Phase C exit of specification
[#357](https://github.com/rajandangi/barectl/issues/357), gathered on 2026-10-26 for
[#398](https://github.com/rajandangi/barectl/issues/398). It audits the exit criterion item by
item, names the revision tested, records the measured times against the budget of
[ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), lists every new native field
and the file that carries it, and states what is not qualified. Anything this record does not
list as passing is not qualified. Phase C is not released.

## Revisions

The local numbers in [Build budget](#build-budget) and [Scenarios](#scenarios) belong to the
head of `feat/357-398` named under [Handoff](#handoff). The hosted figures belong to the
revisions named under [Hosted runs](#hosted-runs); this branch has no hosted run of its own.

| Evidence | Where |
| --- | --- |
| Local fast suite, fast validators, browser suite and native lifecycle scenarios, arm64 | `feat/357-398` head, named in [Handoff](#handoff) |
| Scheduled breadth job, arm64 (dispatched locally) | The same head; the workflow has no hosted run yet |
| Hosted Checks and Native (8 shards), amd64 | Integration `bfe2339` (green) and `bcaf565` (failed, fixed here), named under [Hosted runs](#hosted-runs) |

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Local full build | arm64 | Apple M4 Pro, 14 CPUs, 16 GiB Docker VM; 8 lanes by the lane formula | Ubuntu 26.04.1 LTS by the digest in `docker/disposable-server/pins.json`; systemd 259.5; the kernel shared with the Docker VM |
| Scheduled breadth job | arm64 local, amd64 in the workflow | The same host; one container per breadth item | The same image; the memory classes cap the container's cgroup at 1, 2 or 4 GiB |
| Hosted Native | amd64 | GitHub's `ubuntu-26.04` runners, 8 shards of 2 lanes | The same image |

The controller runs Python 3.14 and Django 6.1.1. Every server is offline: the lane serves the
pinned Ubuntu snapshot, the Nix binary cache, the WordPress core and plugin archives, the
Composer distributions and the fixture Git host and ACME server.

## Build budget

`docker/disposable-server/build.sh --env-file .env` at the tested head; the controller-fast,
fast-validator, browser and native stages run concurrently and each is timed.

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Controller fast tests, 1561 tests with `--parallel` | 42 s in the build | 90 s | | Meets the target |
| Fast snapshot validators, 6 classes | 77 s | (the joint stage) | | The validators have no separate target |
| Joint fast stage, as the build measures it | 77 s | 60 s | | **Missed by 17 s**; the next action is below |
| Browser tests | 83 s | | | |
| Native lifecycle scenarios, 72 of 72 passed, 8 lanes | 261 s | 300 s | 900 s | Meets the target |
| Longest native item | 94.0 s (`PHPFence`) | | 180 s | Within the item limit |
| Full local build, wall time | 261 s | 300 s | 900 s | Meets the target |

The joint fast stage misses its 60 s target because the validator stage now runs six classes
(the Phase C automation, journal, rotation, node and HTTP-site validators) in 77 s. The target
is not raised: the next action is to consolidate the validator classes onto one prepared
server and one real rotation, as the Phase A record did for its three Node cases, and to
re-measure the joint stage. The 90 s fast-gate target is met with room.

The breadth job is outside this budget. Its literal item times on this head are in
[Breadth scenarios](#breadth-scenarios). It is never a required check and adds no time to a
merge build.

## Scenarios

Phase C adds the C1, C2 and C3 scenario sets and the log and cache scenarios. Each row names
the class and the item time this build took; a class that holds several test methods runs them
in one exclusive item against one prepared server.

| Scenario | Class | Local arm64 |
| --- | --- | --- |
| C1 WordPress server cron | `WordPressServerCron` | 83.0 s |
| C1 WordPress object cache | `SiteObjectCache` | 50.8 s |
| C1 Valkey install and mask | `ValkeyInstall` | 27.7 s |
| C2 Laravel scheduler | `LaravelScheduler` | 24.5 s |
| C2 Laravel database queue workers | `LaravelQueueWorkers` | 66.6 s |
| C2 Laravel object cache | `LaravelObjectCache` | 23.5 s |
| C2 Deploy and Roll back with the gate | `LaravelDeployMariaDB` | 51.7 s |
| C2 Deploy refusals and a failed migration | `LaravelDeployOutcomes` | 45.5 s |
| C3 PHP switch with automation | `PHPFence` | 94.0 s |

The C2 gate's own items are in [Breadth scenarios](#breadth-scenarios); the merge build does
not run a reboot, a long tick or a memory class. Logs have no lifecycle class: the log reader
and rotation conventions are proved by the fast layer and the validator stage
(`LogRotationValidators`, `JournalLogValidators`), because the image carries no `logrotate`
package and installing one would change the host standing the create review reads.

## Breadth scenarios

`docker/disposable-server/run-scenarios.sh --env-file .env -- --breadth`, two lanes, on this
head. Each item starts from L5 and is selected only by `--breadth`; the merge build never
runs them.

| Class | Item time | Result |
| --- | --- | --- |
<!-- BREADTH TABLE -->

## Exit criterion

The criterion in the specification's own words: on one target-stack server, a WordPress site
with server cron and object cache and a Laravel site with scheduler, database queue workers and
object cache run their background work with every controller closed; a Laravel deployment and a
PHP switch fence and restore that work; failed, skipped and unknown outcomes are shown
honestly; a fresh controller reconstructs all of it and repeated reviews propose nothing;
memory per Valkey instance and per worker is measured on 1, 2 and 4 GiB hosts; and the full
local build stays within 15 minutes (target 10).

| Clause | Evidence |
| --- | --- |
| A WordPress site runs server cron and its object cache with every controller closed | `WordPressServerCron` turns the timer on through the reviewed change, proves a due event does not run on a page load once `DISABLE_WP_CRON` is set, that the timer stays armed and that a fresh controller reads `succeeded`; `SiteObjectCache` proves the plugin reports Connected through phpredis and that another site cannot reach the socket or the configuration. The harness holds no controller connection while the timer runs. |
| A Laravel site runs its scheduler, database queue workers and object cache with every controller closed | `LaravelScheduler` arms the timer and reads a completed tick that started after the change with no controller connection; `LaravelQueueWorkers` dispatches jobs with the controller absent, proves both processes consume them, a crash restarts, a crash loop stops at the start limit and a graceful restart finishes the in-flight job; `LaravelObjectCache` points the store at the site's own socket and reads the value back out of band. |
| A Laravel deployment fences and restores that work | `RebootGateFence` turns the scheduler on, pushes a release with a pending migration whose migration sleeps four seconds, and reads the site while the maintenance gate answers 503: the timer and both worker services refuse a manual start, the slice is empty, boot activation is off and `current` is still the previous release. After `/up` and the reopened site, the Deploy restores exactly the reviewed scheduler and workers on the new `current`; **Run now** then starts the scheduler service on that release. A **Roll back** to the previous release succeeds and restores the same work. A second test deploys a broken `/up`, keeps the gate, and proves the fence holds across a container boot. The ordering inside the run (fence before `gate`, restore only after `/up` and the reopened file) is pinned by `automation/test_fence_body.py` and the execution tests in `automation/test_fence_callers.py`. |
| A PHP switch fences and restores that work | `PHPFence` switches a WordPress site's PHP with server cron on and proves the timer is masked, stopped and not started during the change, then active on the target runtime, with the site serving throughout. `automation/test_fence_callers.py` pins every fenced kind's body and its payload. |
| Failed, skipped and unknown outcomes are shown honestly | The one projection distinguishes Off, On and waiting, Running, Last run succeeded, Last run failed, Timed out, Skipped, Stopped after repeated crashes, Paused by an unfinished change, Off during maintenance and Could not confirm (`automation/test_status.py`, `automation/test_scheduler.py`, `automation/test_worker_status.py`). `LongSchedulerTick` proves natively that a run spanning a calendar elapse is followed by the next calendar elapse rather than an immediate second start. A worker crash loop reads `Stopped after repeated crashes` natively in `LaravelQueueWorkers`. The recorded transcripts prove a missing read never becomes a success. |
| A fresh controller reconstructs all of it and repeated reviews propose nothing | The recorded states `automation-wordpress-26.04`, `automation-laravel-26.04`, `automation-laravel-workers-26.04`, `object-cache-26.04`, `object-cache-edited-26.04`, `object-cache-laravel-26.04` and `fence-wordpress-26.04` replay through `collect()` and each area's review proposes no effects (`automation/test_recorded.py`, `automation/test_worker_recorded.py`, `cache/test_recorded.py`, `sites/test_node_recorded.py`). Each native scenario's checkpoint also runs the same collect and review on the live server. |
| Memory per cache instance and per worker on 1, 2 and 4 GiB hosts | [Memory](#memory): three memory-cgroup classes. **Not a whole-host measurement**; see [Not qualified](#not-qualified). |
| The full local build stays within 15 minutes (target 10) | [Build budget](#build-budget): TBD |

## Fences and restores

The fence is one step owned by `automation/`, called from the body of every change that alters
a site's code, schema, runtime, settings or files. The review records the plan once, the body
runtime-masks every reviewed timer and service, stops the timers, their services and the slice,
and proves the slice empty within the budget. A change that enters a persistent gate also
removes boot activation for every reviewed unit. Restore unmasks and starts exactly the
reviewed resume set after the change verifies; a failed or unknown change never reaches it.

The native proof is `PHPFence`, `RebootGateFence` and the Deploy/Roll back bodies in
`LaravelDeployMariaDB`. Fast tests pin the body order, the gate's boot-activation removal, the
partial restore, removal that never restores, and every fenced kind's staged program.

**Two defects this qualification found and fixed.** The kinds that rebuild a closed payload
(`deploy_laravel_site`, `rollback_laravel_site`, `edit_laravel_environment`,
`edit_wordpress_settings`, `set_site_object_cache`) filtered `automation_fence` out of the
document they stage, so their bodies read "nothing to pause" and did nothing. The unit tests
passed because they called the staged body with a hand-made document. `RebootGateFence` found
it on a real server; every affected body now carries the validated plan and
`automation/test_fence_callers.py::PayloadTests` pins the assembly. The native Deploy harness
also bypassed the engine's plan (`disposable/test_laravel_deploy.py::apply`), so no Phase B
Deploy scenario had exercised a fence; it now applies the same planned review the worker does.
Once the plan reached the cache body, a second defect appeared: it restarted the site's
workers while the fence had them masked, so a Laravel cache-on ended `partial/laravel_worker`.
A fenced cache change now leaves the workers to the fence's restore, which starts the reviewed
set on the new environment; `cache/test_laravel_cache.py` pins both the order and the skip.

## Memory

Measured on the local arm64 build in the [scheduled breadth job](#the-scheduled-breadth-job),
one container per class capped at 1, 2 and 4 GiB. Each class starts from L5, turns the site's
object cache on, requests the page once and waits two seconds before reading cgroup
`memory.current`/`memory.peak`, the instance's own unit cgroup and each worker's unit cgroup.

| Class | Container limit | Cache instance | Worker 1 | Worker 2 | Whole container current / peak |
| --- | --- | --- | --- | --- | --- |
| `MemoryOneGiB` | 1 GiB | 4.2 MiB (4,415,488 B) | 33.2 MiB (34,783,232 B) | 33.6 MiB (35,201,024 B) | 355.6 / 374.9 MiB |
| `MemoryTwoGiB` | 2 GiB | 4.4 MiB (4,599,808 B) | 33.0 MiB (34,648,064 B) | 33.3 MiB (34,930,688 B) | 363.5 / 383.1 MiB |
| `MemoryFourGiB` | 4 GiB | 8.0 MiB (8,368,128 B) | 33.3 MiB (34,865,152 B) | 33.0 MiB (34,635,776 B) | 521.5 / 545.0 MiB |


The instance's configured `maxmemory` is 64 MiB in every class, and the measured instance
memory stays far below it because the site's cache is nearly empty. The workers carry a PHP
process each and dominate the per-site cost; the whole-container figure is mostly the
prepared stack and page cache and moves with what the class had run before. The whole-container figure includes page cache
and the prepared stack (MariaDB, Caddy, the Nix store on disk), so it is not additive with the
per-unit figures.

The per-site owner decision is one instance per site, confirmed on #323. These figures do not
show a 1 GiB host running out of memory for one cached site and two workers, so they do not
trigger a new owner decision; [Not qualified](#not-qualified) states what a real 1 GiB host
would still need to prove.

## New native fields and where they live

Nothing in this table is a Barectl marker or inventory file: each is the native configuration
or state the owning tool already reads.

| Field or file | Carrier |
| --- | --- |
| Automation slice, services and timers | `/etc/systemd/system/barectl-site-<id>.slice`, `barectl-site-<id>-<role>.service`, `barectl-site-<id>-<role>.timer` |
| The role's account, runtime, release and bound | The unit file: `User=`/`Group=`, `WorkingDirectory=current`, `ExecStart` through `/var/www/<id>/bin/php` or `bin/wp`, `TimeoutStartSec`, `KillMode=control-group` |
| Timer schedule and catch-up policy | The timer file: `OnCalendar`, `AccuracySec`, `RandomizedDelaySec`, `Persistent=false`, `DeferReactivation=yes` |
| Worker definition | The `queue<N>.service` files: the queue list, `--timeout`, `Restart=always`, `RestartSec`, `StartLimitIntervalSec`, `StartLimitBurst`, `TimeoutStopSec` |
| Fence state | A runtime mask symlink to `/dev/null` and `/run/systemd/system/<unit>.d/50-barectl-fence.conf` (`RefuseManualStart=yes`); boot activation is the unit-file enablement and `*.wants` symlinks |
| WordPress server cron switch | `define( 'DISABLE_WP_CRON', 'true' )` in `/var/www/<id>/private/wp-config.php` |
| WordPress cache wiring | `WP_REDIS_SCHEME`, `WP_REDIS_PATH`, `WP_REDIS_PREFIX` in the same private file; the pinned plugin under the site's `wp-content/plugins/redis-cache` and its `object-cache.php` drop-in |
| Laravel retry interval and cache wiring | `DB_QUEUE_RETRY_AFTER`, `CACHE_STORE`, `REDIS_HOST`, `REDIS_PORT` in `/var/www/<id>/private/laravel.env` (discovery reads the key names and digests, never the values) |
| Cache instance | `/etc/valkey/<id>.conf` (`port 0`, `unixsocket`, `unixsocketperm`, `save ""`, `appendonly no`, `maxmemory`, `maxmemory-policy`, the default-user ACL) |
| Cache unit override | `/etc/systemd/system/valkey-server@<id>.service.d/barectl.conf` (`User=`, `ExecStart`, `PIDFile`, `RuntimeDirectory`) |
| Cache socket and data | `/run/valkey/<id>/valkey.sock` (`0600`, site-owned) and `/var/lib/valkey/<id>` (`0700`, site-owned) |
| Cache boot activation | `multi-user.target.wants/valkey-server@<id>.service` |
| Site log files | `/var/www/<id>/logs/` (Caddy access JSON, PHP error and slow logs, Laravel application log) |
| Log rotation | `/etc/logrotate.d/barectl-site-<id>` |
| Duplicate-scheduler evidence | The site account's crontab, root's crontab, `/etc/crontab`, `/etc/cron.d`, Supervisor program files and foreign units running in the site's identity |
| Status evidence | `systemctl show` fields per unit: `ActiveState`, `SubState`, `Result`, `ExecMainStatus`, `ExecMainStartTimestamp`, `ExecMainExitTimestamp`, `LastTriggerUSec`, `NextElapseUSecRealtime`, `UnitFileState`, `LoadState`, `RefuseManualStart`, `ControlGroup`, `NRestarts`; the slice's `cgroup.events` `populated` flag |

**Lost with the controller.** The review and run that made each change, and therefore who
changed it and which work the review declared to resume; the applied-review record that lets a
Laravel cache turn-off restore the previous `CACHE_STORE` (a fresh controller refuses rather
than guessing); the stored log pages (24 hours at most, deleted on the next read of the same
log); and any private audit of a controller that has been lost. Discovery reconstructs the
setting, the definition and the last result from the table above, and never guesses what was on
before an interrupted change.

## Known limitations

- **Logrotate omits `su`.** The per-site file rotates as root with `create 0640 s<id> s<id>`,
  not with `su s<id> s<id>`. The site's log directory is `caddy:site 0750`, so the site account
  cannot perform the rename and create inside it. The file's header says why, and
  `LogRotationValidators` runs the real `logrotate --debug` and a real rotation against that
  text. An ACL for the site account would allow `su` but adds an unobserved permission and a
  package; it is not taken.
- **Rotation runs as root.** The same deviation: the rotation is a root-owned system artifact,
  not a site-user process. A compromised site account cannot rewrite its own rotation policy,
  which is the safer half; the site account also cannot trigger it.
- **The WordPress plugin and its mirror pin.** Redis Object Cache is the one plugin Barectl
  manages, pinned to `3.0.0` (archive size `730620`, SHA-256
  `7a03342d3defbe94cac8d0470b42dc1a1c34331b19c47205df20ceccd3c8f54a`). The archive is in the
  drift job's mirror manifest and is refreshed by the same CI watch as the WordPress core
  archive; there is no separate plugin bump issue, so a plugin release reaches servers only
  when Barectl ships a new pin.
- **The Roll back's mid-run window is not sampled.** `RebootGateFence` reads the fence while a
  four-second migration holds a Deploy's gate open, and it proves the Roll back's end state and
  restored work; the Roll back's own gate window is too short to sample without a fixture
  delay, so its stage order rests on the fast body tests.
- **The cache client is phpredis in the site's own master.** Enabling it restarts that site's
  master; the measured window is 3.59 s with 2 refused requests of 210 over 0.17 s. The
  qualification does not claim zero refusals.
- **Laravel cache turn-off needs the controller that turned it on.** Without the applied
  on-review, the change refuses rather than guessing the previous `CACHE_STORE`; an operator
  must restore the store through ordinary administration first.
- **Logs.** The live view polls only while the tab reports itself visible; a headless browser
  reports every page visible, so the hidden-tab path is asserted at the trigger, not in a
  browser. Journald owns journal rotation and retention; Phase E owns retention settings.
- **Phase D and E remain.** Backups, capture, restore, restic repositories and the Jobs view
  are out of scope here; the status projection this phase delivers is the input the Jobs view
  (#284, Phase E) reuses.

## Not qualified

- **A real 1, 2 or 4 GiB host.** The memory classes are containers whose cgroup is capped at
  those sizes; the kernel and page cache are the Docker VM's. No cloud instance or real small
  VPS ran this revision.
- **A real kernel reboot.** The breadth job restarts the container's init (a userspace
  reboot). The kernel, and therefore the kernel boot ID, is shared with the Docker VM. Unit
  enablement, timers and slice parenting are re-exercised; a kernel panic or power-loss path is
  not.
- **Hosted runs of this branch.** The final branch has no pull request and no hosted checks.
  The named hosted runs are the integration tip's; the two failures they found are fixed here
  and are proven locally.
- **The local browser suite on this host.** It fails at sign-in with a 500 (a missing or
  unusable Vite manifest in this worktree) before any journey runs, so its local 425 s is not
  a suite measurement. The two focused journeys the integration fixes target pass in CI and
  locally on the integration tree; CI is the browser authority for this record.
- **The scheduled breadth workflow in CI.** It is defined and runs locally by
  `run-scenarios.sh -- --breadth`; no hosted dispatch of it exists yet, so the amd64 breadth
  numbers, and the workflow's artifact/summary path, are unproven in CI.
- **The hosted shard target.** The last green hosted run (`bfe2339`) reported 220 s to 451 s
  per shard, and the next one (`bcaf565`) timed out `LaravelDeployMariaDB` on shard 2 at 180 s.
  Splitting the scheduler out and recording the new item times addresses the cause; a hosted
  run at this head must confirm the 300 s target. This record does not claim it.
- **WordPress self-updates, the Generate password button, the database engine's site count and
  the WordPress interrupted install** remain as the Phase B record lists them; Phase C does
  not change those claims.
- **A second real server.** No public DNS name, no provider host and no certificate from a
  public authority; the lane's ACME server and fixture names stand in.

## Hosted runs

`Native` run [40191609433](https://github.com/rajandangi/barectl/actions/runs/40191609433) at
integration `bfe2339`, amd64, eight shards of two lanes, all passed:

| Shard | Stages | Result |
| --- | --- | --- |
| 1 of 8 | Fast validators 6 of 6 in 115 s; egress control; lifecycle 6 of 6 in 101 s | Passed |
| 2 of 8 | Lifecycle 9 of 9 in 297 s; `LaravelDeployMariaDB` 179.8 s | Passed at the item limit |
| 3 of 8 | Lifecycle 9 of 9 in 255 s | Passed |
| 4 of 8 | Lifecycle 9 of 9 in 291 s | Passed |
| 5 of 8 | Lifecycle 9 of 9 in 220 s | Passed |
| 6 of 8 | Lifecycle 9 of 9 in 286 s | Passed |
| 7 of 8 | Lifecycle 9 of 9 in 262 s | Passed |
| 8 of 8 | Lifecycle 9 of 9 in 451 s | Passed, over the 300 s target |

`Checks` run [40201880042](https://github.com/rajandangi/barectl/actions/runs/40201880042) at
`bcaf565` failed `browser` on two defects this branch fixes: `automation.test_browser` found
the native terms `evidence` and `review` on the site Overview, and `sites.test_node_browser`
prepared a fenced Node change through a replay that did not answer the fence read. Its `check`
job passed. `Native` run
[40201880046](https://github.com/rajandangi/barectl/actions/runs/40201880046) at `bcaf565`
failed shard 2: `LaravelDeployMariaDB` reported `0 tests, 180.0 s — over 3 minutes`, after the
class had reached 179.8 s at the previous tip. This branch splits the scheduler method into
`LaravelScheduler` on the prepared L5 state, so each item is far inside the limit.

## Handoff

The branch is `feat/357-398`; the tested head and the exact commands are in
`notes/handoff-398.md` for the orchestration run, and the pull request that merges it carries
the same numbers. Phase C is not released.
