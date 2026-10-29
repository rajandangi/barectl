# Phase D qualification record

This record lists the evidence for the Phase D exit of specification
[#358](https://github.com/rajandangi/barectl/issues/358), gathered on 2026-10-30 for
[#410](https://github.com/rajandangi/barectl/issues/410). It audits the specification's
qualification requirement and the ticket's acceptance criteria item by item, names the
revision tested, records the measured times against the budget of
[ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), names the restic and engine
versions, the provider evidence, and states what is not qualified. Anything this record does
not list as passing is not qualified. Phase D is not released.

## Revisions

The scenario times on the left of [Scenarios](#scenarios), the module time and the
[Build budget](#build-budget) belong to `41ade30`, the integration tip of
`feat/358-phase-d-protection`. The right-hand scenario column, the failure item and the
build in [Build budget](#build-budget) belong to the `feat/410-qualification` head that
merged that tip and added #410's test and documentation changes; [Handoff](#handoff) names
the final head. No hosted run of the #410 head exists.

| Evidence | Where |
| --- | --- |
| Native backup scenarios, arm64, nine items in one run, 135 s for the module | `41ade30` |
| Full local build: fast gate, fast validators, browser, 82 native items, arm64 | `41ade30` plus #410's changes |
| Safe-failure coverage, `BackupFailure` | the same #410 build |
| Offsite provider behaviour | the lane's local S3-compatible fixture, never the internet |
| Hosted amd64 | none at either revision |

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Native backup scenarios | arm64 | Apple M4 Pro, 14 CPUs, 16 GiB Docker VM; 8 lanes by the lane formula | Ubuntu 26.04.1 LTS by the digest in `docker/disposable-server/pins.json`; systemd 259.5; the kernel shared with the Docker VM |
| Full local build | arm64 | The same host; 8 lanes | The same image |

The controller runs Python 3.14 and Django 6.1.1. Every server is offline: the lane serves the
pinned Ubuntu snapshot, the Nix binary cache, the WordPress core and Composer archives, the
fixture Git host and ACME server, and the S3-compatible fixture.

### Supply and engine versions

| Part | Version | Carrier |
| --- | --- | --- |
| restic | 0.18.1 | The pinned catalog lock; the profile `/nix/var/nix/profiles/barectl/restic` |
| MariaDB | 11.8 | The server's one engine; every native backup item ran on it |
| PostgreSQL | 18 | Supported by the review, the dump and the restore compatibility check; **no native backup item ran on it** |

## Build budget

`docker/disposable-server/build.sh --env-file .env` at the #410 head, with the four stages
concurrently, as [the test time budget](quality.md#test-time-budget) defines it.

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Controller fast tests, 1861 tests with `--parallel` | 40 s | 90 s | | Meets the target |
| Fast snapshot validators | 68 s | (the joint stage) | | The validators have no separate target |
| Joint fast stage, as the build measures it | 68 s | 60 s | | **Missed by 8 s**; see below |
| Browser tests | 93 s | | | |
| Native lifecycle scenarios, 82 of 82 passed, 8 lanes | 360 s | 300 s | 900 s | **Missed by 60 s** |
| Longest native item | 115.3 s (`BackupLifecycle`) | | 180 s | Within the item limit |
| Full local build, wall time | 360 s | 300 s | 900 s | **Missed by 60 s** |

The integration tip `41ade30` measured 365 s of wall time, with the native stage at 365 s,
browser at 99 s, fast validators at 70 s and controller-fast at 41 s. #410 measures 360 s:
inside run-to-run noise of that baseline, and still a **measured target miss**. The wall is
the native stage; every other stage finishes inside it.

**The schedule is not the lever.** #410 measured the hypothesis that overlapping the browser
stage with the native stage inflates the native stage: starting `controller-fast`,
`fast-validators` and `browser` together and the native stage when the browser stage ended
measured browser 79 s plus native 335 s, **414 s of wall time against 365 s** for the
concurrent build. The native stage took 330 to 360 s alone in every run, so serializing the
two heavy stages only adds the browser time. The concurrent schedule is kept, and
`docker/disposable-server/build.sh` now names this measurement in its header comment and
[the test time budget](quality.md#test-time-budget).

The native stage is 82 exclusive-or-shared items whose measured times sum to 2275 s over 8
lanes, a 284 s floor before any container boot or scheduling tail. The next action is to
consolidate the native items and let the exclusive backup items share a lane server, which
removes repeated container boots and shortens the tail; the earlier 10-lane trial at 310 s
failed three scenarios from contention, so lanes are not raised. The joint fast stage misses
by 8 s under the same contention, which is the miss the [Phase C record](phase-c-qualification.md#build-budget)
already names; the target is not raised.

#410's own addition is measured: `BackupFailure` joins `disposable/test_backups.py` (no new
suite) and took **55.4 s** in the build, with its server boot inside the scenario time. The
five backup items that used to repeat the APT refresh, the database engine install and the
site creation in every item now start from the prepared L5 snapshot and create only the site
they prove; the item times move by less than the run-to-run spread because each item is
dominated by its own captures and restores.

## Scenarios

| Scenario | Class | `41ade30` | #410 head |
| --- | --- | --- | --- |
| Backup and restore lifecycle | `BackupLifecycle` | 108.7 s | 115.3 s |
| Full site restore: files only, then the whole site | `FullSiteRestore` | 71.0 s | 67.3 s |
| WordPress full restore, data and readiness | `WordPressFullRestore` | 54.0 s | 57.6 s |
| Laravel full restore, shared state and readiness | `LaravelFullRestore` | 58.8 s | 61.4 s |
| Scheduled live capture with the controller gone | `ScheduledCapture` | 84.3 s | 94.9 s |
| Retention, Keep and foreign snapshots | `Retention` | 127.9 s | 109.5 s |
| Weekly integrity check and read-back | `Integrity` | 88.8 s | 79.3 s |
| Disaster recovery across servers | `DisasterRecovery` | 93.0 s | 98.8 s |
| Offline recovery with plain restic | `OfflineRecovery` | 38.7 s | 36.4 s |
| Safe failures: dump, disk, killed capture | `BackupFailure` | — | 55.4 s |

The nine items on `41ade30` ran in one pass with a 135 s module wall time. A class that holds
one test method runs as one exclusive item against one prepared server; its measured time
includes the container boot.

What the items prove:

- **`BackupLifecycle`** enables backups through the reviewed change with the passphrase typed
  as a confidential input, checks the private key and config modes, and proves plain restic
  opens the repository with the passphrase alone. It takes a Database only point with an
  offsite copy, proves a failed copy keeps the onsite point and says **Saved here, offsite
  copy failed**, repairs it with **Copy offsite again**, and proves removing offsite storage
  leaves every copy in the bucket. It reconstructs the same state from a controller with no
  local change history, proves the journal holds no passphrase, and proves a failed dump
  leaves no point. A paused Full site point writes both parts under one identifier and
  reopens the site only after both are present; a Database only restore takes and lists its
  safety point and imports as the site principal.
- **`FullSiteRestore`** restores Files only from a full point with the warning that files and
  database then come from different points, and then restores the whole site; both restored
  releases are site-owned, keep the convention's permissions, and leave the previous release
  retained.
- **`WordPressFullRestore`** restores uploads, the private configuration and the database of a
  real WordPress site, keeps the target's own database settings, re-applies the WordPress
  permissions and reads both HTTPS readiness answers.
- **`LaravelFullRestore`** restores a Laravel release with `vendor/`, the shared `.env`,
  `storage/` and `bootstrap/cache`, proves the `/up` readiness answer, counts the restored
  release toward Deploy's retention, offers **Back up first** on a Deploy with pending
  migrations, and proves **Remove site** keeps the repository and lists it as a removed site.
- **`ScheduledCapture`** installs the one reviewed schedule, waits for the real timer to fire
  a live capture with no controller connected, reads the live point, reconstructs the
  schedule on a fresh controller and turns it off.
- **`Retention`** creates backdated points, proves the newest-verified rule keeps a group
  when its newest point does not read back, honours `keep`, never touches a foreign snapshot,
  skips on an unsynchronized clock, and computes onsite and offsite independently.
- **`Integrity`** runs `restic check` with its rotating subset and reads the newest point back;
  a corrupted pack is its own failure, the capture result is unchanged, and a held lock is a
  skip.
- **`DisasterRecovery`** boots a second server from the same layer, connects the same
  S3-compatible storage with the kit facts, passphrase and keys, and restores the source
  point into a matching site under another identifier and domain.
- **`OfflineRecovery`** recovers the source database with plain `restic` and the passphrase
  alone, from the path the printed kit names, with no controller and no Barectl change.
- **`BackupFailure`** is described under [Safe failures](#safe-failures).

## Capture and restore times

The table above times whole scenarios, not single operations: a scenario's boot, its captures,
its restores and its verification are one measurement. What the record can state from them:

- A paused Full site capture of the plain-PHP fixture, with its safety point, its
  files-only restore and its full restore, fits inside `FullSiteRestore`'s 67 to 71 s,
  including the container boot and the site creation.
- A WordPress full restore, from a paused full point through uploads, private configuration,
  database import and both readiness answers, fits inside `WordPressFullRestore`'s 54 to 58 s
  on the prepared layer.
- A Laravel full restore with shared `.env`, `storage/` and `bootstrap/cache`, readiness and
  the Deploy/Remove site checks fits inside `LaravelFullRestore`'s 59 to 61 s.
- A live scheduled capture fired by the real timer, with the controller absent, fits inside
  `ScheduledCapture`'s 84 to 95 s, including the wait for the timer's minute.
- Cross-server disaster recovery, including the second server's boot and its connected
  storage, fits inside `DisasterRecovery`'s 93 to 99 s.

No scenario measures one capture or one restore in isolation, and the record does not claim a
per-operation time. A single operation's time is therefore not qualified here; the item times
are the evidence that the operator journeys fit the item limit.

## Safe failures

`BackupFailure` proves the specification's failure scenario on a real server, in one item:

- **A failed dump leaves no recovery point.** With `mariadb-dump` removed, **Back up now**
  ends refused with `backup_dump`; the repository lists no point before or after it.
- **A short disk refuses the capture and deletes nothing.** The item mounts a 700 MiB tmpfs
  on the repository root, below the 1 GiB headroom the body keeps. The review still sees the
  root filesystem's space, so the change is eligible; the capture body refuses with
  `backup_disk`, the saved point is unchanged, and the repository is restored afterwards from
  the moved original.
- **A killed capture stays gated with Journey 7's one sentence and one action.** A paused full
  capture of a 256 MiB fixture is killed after it starts the files part. The site answers 503,
  its Caddy file holds the maintenance form, discovery reads the interim `partial` /
  `backup_paused` line, and the Backups view offers **Reopen site** with the sentence
  "This stopped after pausing the site for a full backup. Nothing after it ran." exactly once.
  Applying **Reopen site** serves the site again.
- The rendered sentence and the single action are asserted by rendering
  `templates/backups/_site_backups.html` with the observed view; the browser journey is
  `backups/test_browser.py::BackupsBrowserTests::test_a_gated_site_offers_one_reopen_action`
  and `test_a_gated_restore_offers_the_same_one_reopen_action`.

**Defects this qualification found and fixed.** `LaravelFullRestore` failed twice with
`AssertionError: None is not true` after a restore that had already succeeded: the restore's
verification read ran while the transient unit was still exiting, so the read either met the
unit's exclusive native lock or lost its command bound, and `verify` honestly answered "could
not read". The harness now waits for the unit to end before it verifies, as the worker closes
a run from the ended unit's evidence, and retries one unanswered verification read; a false
answer still fails. The 82-item build then passed every item.

## Memory and disk

**Method, and what it is not.** The [scheduled breadth job](quality.md#the-scheduled-breadth-job)
caps one container per class at 1, 2 and 4 GiB and reads `memory.current` and `memory.peak`
from the container's cgroup and each unit's own cgroup — the method of `MemoryOneGiB`,
`MemoryTwoGiB` and `MemoryFourGiB` in the [Phase C record](phase-c-qualification.md#memory).
Those are **cgroup limits on this host, not whole 1, 2 or 4 GiB machines**: the kernel and
the page cache belong to the Docker VM.

Phase D adds no memory class. No backup capture has been measured under those caps, so the
record makes no claim about a 1, 2 or 4 GiB host running restic, a dump and a full capture.
What is qualified about disk is the refusal boundary:

- the review refuses a full capture when the server's root filesystem has less than the 1 GiB
  headroom (fast layer);
- the capture body refuses a capture when the repository's filesystem has less than the same
  headroom, and deletes nothing (`BackupFailure`, on a 700 MiB tmpfs mounted over the
  repository root);
- the full-point fixture copies 256 MiB of random data, and the repository holds two parts
  under one point.

The next action is one breadth class that caps a backup capture at each of 1, 2 and 4 GiB and
records the peak of the capture's unit cgroup, so the next phase can state the memory a
capture needs rather than a lower bound.

## Provider evidence

No live Amazon S3 or Cloudflare R2 bucket was provisioned for this record and no credentials
exist for one. **That is a named gate, not a pass**: the acceptance criterion "missing live
credentials are a named gate, not a pass" is met by stating it here and in
[Not qualified](#not-qualified), not by a substituted result.

What the lane proves instead, through a local S3-compatible fixture in its own container (not
on the server, so host standing is unchanged) with the fixture CA and path-style addressing:

- **Set up offsite storage** writes the capture keys to a root-only `0600` environment file,
  checks the bucket by writing and listing, initialises each backed-up site's offsite
  repository with restic's copied chunker parameters, and adds the recovery passphrase as a
  key;
- a capture copies its onsite point offsite after the site is safe, and the offsite listing
  shows the same point identifier and a complete point;
- a capture whose copy credential is rejected keeps the onsite point and reads **Saved here,
  offsite copy failed**; **Copy offsite again** repairs the copy without a new capture;
- **Remove offsite storage** removes the setting and keys and leaves every object in the
  bucket;
- a second server restores a point from the connected storage into a matching site
  (`DisasterRecovery`), and plain `restic` recovers the database from the onsite path with the
  passphrase alone (`OfflineRecovery`).

The fixture is not evidence about real provider behaviour: latency, egress cost, S3 Object
Lock, R2 bucket locks, R2's token model and an S3 pruning key's inability to delete are not
measured here. The reviews state those provider facts, and the fast layer pins that wording.

## Repositories, tags and what the controller loses

The onsite repository is `/var/lib/barectl-backups/<id>/onsite` (root `0700`), the server key
`/etc/barectl/backups/<id>.key` (root `0600`), and the offsite location and keys are root-only
files under `/etc/barectl/backups/offsite/`. There is no catalog file, marker, latest pointer
or manifest on the server.

**Lost with the controller.** The reviews and runs that made each change and who approved
them; the confirmation that the operator stored the passphrase and kit; the passphrase itself,
which is never stored; the previous `CACHE_STORE`-style applied records other areas keep; and
the export staging directory, which expires. Passive discovery reconstructs enablement, the
schedule, the retention and integrity units, the non-secret offsite fields, the last safe
results and integrity findings from native evidence. A repository listing is only an explicit
**Check backups** read, and a stale listing never authorizes a restore.

## Acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Missing live credentials are a named gate, not a pass | [Provider evidence](#provider-evidence) and [Not qualified](#not-qualified): no live S3 or R2 bucket exists for this record |
| The local full build meets the 300 s target with all Phase D scenarios | **Not met**: 360 s against 300 s and 900 s ([Build budget](#build-budget)); named as a defect with its next action |
| The backup requirement documents are reduced to pointers to #358 | `docs/v0.6.md`, `docs/backup-retention.md`, `docs/backups-native-design.md` and `docs/backups-competitor-analysis.md` were deleted in `e330fe8` and their surviving behaviour lives in `docs/backups.md`; [the target architecture's Backups section](target-architecture.md#backups) now describes current behaviour, and the [glossary](../GLOSSARY.md) holds the Phase D terms |
| Every new native check joins one of #358's four shared native scenarios, no new suite, and the ticket records the measured addition | `BackupFailure` joins the existing `disposable/test_backups.py` module (the backup and restore lifecycle scenario's suite); measured 55.4 s; the build stays inside the 900 s limit and misses the 300 s target as above |
| Default paths follow #179's journeys and the banned-terms check; snapshot IDs, repositories, units and journal lines appear only under Logs or Advanced | The [backup browser suite](backups.md) passes 22 tests in 12.7 s with its banned-terms check; `BackupFailure` renders the operator sentence and one **Reopen site** action, and the snapshot identifiers stay under Advanced in the recovery-point table |

## Not qualified

- **Live Amazon S3 and Cloudflare R2 buckets.** The named gate above. No real bucket, no
  provider latency, egress, lifecycle or immutability behaviour, and no live credential
  rotation.
- **A hosted run of this revision.** No `Native` run exists for the #410 head, so the amd64
  item times and shard balance rest on the hosted record from `98aee59` and the local
  measurements in [Scenarios](#scenarios).
- **PostgreSQL 18 backups and restores.** Every native backup item ran on MariaDB 11.8. The
  PostgreSQL dump/import and the same-engine-major refusal are fast-layer evidence only.
- **Memory and disk on 1, 2 and 4 GiB hosts for a capture.** No Phase D memory class exists;
  the method and the disk refusal boundary are described under [Memory and disk](#memory-and-disk).
- **A real kernel reboot during a capture.** `RebootedFullBackup` is a breadth item and not
  part of the merge build; a container stop and start is not a kernel reboot.
- **Replace recovery passphrase, schedule-overlap warnings and the Export transfer.** These
  are fast-layer and browser evidence; no native item exercises them. Export's native
  assertions remain the gap #409 recorded.
- **The build target and the joint fast stage.** 360 s against 300 s and 68 s against 60 s at
  this head; the next actions are item consolidation and the validator consolidation the
  Phase C record already names.
- **Single capture and restore times.** The record times whole scenarios, not one operation;
  see [Capture and restore times](#capture-and-restore-times).
- **A second real provider host or a real DNS name.** The lane's fixture provider, ACME server
  and names stand in, as the Phase A and B records state.

## Handoff

The tested head, the exact commands and what remains unrun are in the orchestration run's
`handoff-410.md`. Phase D is not released.
