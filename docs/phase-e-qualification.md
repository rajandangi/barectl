# Phase E qualification record

This record lists the evidence for the Phase E exit of specification
[#301](https://github.com/rajandangi/barectl/issues/301), gathered for
[#415](https://github.com/rajandangi/barectl/issues/415). It names the revision tested, the
environments, the measured times against the budget of
[ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), the native scenarios that
walk the Security section, and what is not qualified. Anything this record does not list as
passing is not qualified.

## Revisions

The integration branch is `feat/301-phase-e-security`. It merged #305 at `4969b7ea` and #414
at `5b1c9dfc`; the qualification code and documents are the `security/415-qualification`
head that follows `92cc9229`. The local measurements below belong to that branch. The
hosted amd64 run belongs to the pull request whose checks are recorded in [Handoff](#handoff).

| Evidence | Revision |
| --- | --- |
| Restart kind, engine reboot outcome, fast and native regression | `4969b7ea` (#305) |
| Cloud-image VM lane, pinned image, workflow | `5b1c9dfc` (#414) |
| Qualification documents and VM restart item | `92cc9229` (#415) |
| Hosted amd64 Native workflow | PR #484 head `67719d9f` |
| Hosted amd64 VM lane | `main` at `0a4703b2` |

## Environments

| Environment | Architecture | Host | Server |
| --- | --- | --- | --- |
| Container security scenarios | arm64 | Apple M4 Pro, 14 CPUs, 64 GiB host memory; 8 lanes | Ubuntu 26.04.1 LTS by the digest in `docker/disposable-server/pins.json`; systemd 259.5; the kernel shared with the Docker VM |
| Cloud-image VM lane | arm64 | The same host; QEMU 11.1.3 with HVF | The official `resolute-server-cloudimg-arm64.img`, SHA-256 `8eb876c2…63da24`, 940,373,504 bytes |
| Full local build | arm64 | The same host; 8 lanes | The same container image |
| Hosted Native workflow | amd64 | GitHub `ubuntu-26.04` runner | The same container image |
| Hosted VM lane | amd64 | GitHub `ubuntu-26.04` runner; KVM when its device is accessible, TCG otherwise | The official `resolute-server-cloudimg-amd64.img`, SHA-256 `5645d031…b7eb5`, 859,090,944 bytes |

The controller runs Python 3.14 and Django 6.1.1. Container servers are offline: the lane
serves the pinned Ubuntu snapshot, the Nix binary cache and the other fixture upstreams. The
cloud-image guest is offline except for the image download: QEMU user networking runs with
`restrict=on`, and the guest reaches only the NoCloud seed and the same mirror through
`guestfwd` proxies.

### Supply versions

| Part | Version | Carrier |
| --- | --- | --- |
| UFW | 0.36.2 | The Ubuntu archive |
| OpenSSH | 10.2p1 | The Ubuntu archive |
| unattended-upgrades | 2.12 | The Ubuntu archive |
| needrestart | 3.11 | The Ubuntu archive |
| APT / dpkg / systemd | 3.2 / 1.23 / 259 | The Ubuntu 26.04 archive and image |
| Caddy / HAProxy / PHP | The pinned catalog lock | `runtimes/catalog_lock.json` |
| QEMU | 11.1.3 | The local VM lane host; the hosted runner installs `qemu-system-x86` |

## Build budget

`docker/disposable-server/build.sh --env-file .env` at `1ac5c273`, the qualification tip
after the foundation body was left unchanged, with the four stages as [the test time
budget](quality.md#test-time-budget) defines them.

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Controller fast tests, 2145 tests with `--parallel` | 46 s | 90 s | | Meets the target |
| Fast snapshot validators | 56 s | (the joint stage) | | The validators have no separate target |
| Joint fast stage, as the build measures it | 56 s | 60 s | | Meets the target |
| Browser tests | 126 s | | | |
| Native lifecycle scenarios, 87 of 87 passed, 8 lanes | 256 s | 300 s | 900 s | Meets the target |
| Longest native item | 130.8 s (`Retention`) | | 180 s | Within the item limit |
| Full local build, wall time | 312 s | 300 s | 900 s | **Missed by 12 s**, inside run-to-run noise of the recorded Phase D baseline |

#415 adds one `vm`-tagged class and fast configuration tests only. The VM class is excluded
from every ordinary native selection and from the merge build; its lane is outside the
[test time budget](quality.md#test-time-budget). The standalone fast gate moved from 2128 to
2145 tests and ran in 30 s on the qualification branch; the build stage above includes its
own startup and measured 46 s. The wall target miss is 12 s with native at 256 s and browser
at 126 s on a loaded host, not a raised target.

The Server Jobs slices measured the same stages on the integration branch after #286: the
fast gate ran 2293 tests in 25.6 s (wall 27.4 s), the browser stage 104 tests in 20.2 s (wall
22.0 s), and the Phase D scheduled-capture native item 97.8 s (107 s lane) against the 180 s
item limit. On the #413 head the fast gate ran 2295 tests in 23.5 s (wall 25.3 s) and the
browser stage 104 tests in 20.8 s, inside the #286 figures and the targets. The full-build table above remains
the #415 build; no new full build was run for #413. The new `JobsSurvivingEvidence` breadth
item is outside this budget and measured 38.6 s (44 s lane).

## Security lifecycle

The section's lifecycle is proven by the target-stack scenarios below, each on a set-up
server with sites, plus the cloud-image restart item. The container scenarios ran together
in one arm64 pass: **4 of 4 passed in 49 s**.

| Scenario | Class | arm64 | What it proves |
| --- | --- | --- | --- |
| Security checks | `SecurityChecks` | 13.4 s | Every check is read from ordinary discovery, the default view shows tasks without native terms, and a fresh controller reconstructs the checks after equivalent and conflicting ordinary changes. |
| SSH sign-in | `SignInLifecycle` | 18.1 s | Require key-only sign-in, the confirm-or-revert window, account disclosure and recovery. |
| Ubuntu updates | `SecurityUpdates` | 31.2 s | Check for updates, install an exact reviewed security update from the dated snapshot, and refuse a stale review, unreviewed dependency, hold and modified conffile. |
| Firewall | `FirewallLifecycle` | 38.1 s | Turn on the standard, add and remove operator ports, keep and put back the window, a second controller refusing, a held lock, and a rule that blocks the new connection. |
| Restart, real kernel | `VmReboot` | 14.5 s | A real kernel reboot changes `/proc/sys/kernel/random/boot_id` and SSH returns; the guest reaches the mirror and no external address. |
| Restart body and verification | `VmRestart` | 40.8 s | The restart body writes its result, the guest restarts, a fresh connection reports a new boot, and verification passes. |

The VM lane ran both classes and the mirror proof in **55.5 s of tests**; the complete lane,
including boot and cloud-init, took **222 s** on the local arm64 host. On the hosted amd64
lane the same three tests passed in **57.1 s** (`VmRestart` 43.7 s, `VmReboot` 12.9 s,
mirror 0.4 s) and the complete lane took **232 s**. The mirror fetch is best-effort: a
missing snapshot cache skips the mirror check, while the real reboot and restart body still
run; the native mirror scenario owns package serving. The smoke run before
the final lane changes passed the same reboot path in 37.3 s. The final lane's exit was 0.

`VmRestart` submits the restart body with a reviewed document naming one reboot-required
package and `ssh.service`. The review, consent and refusal path are covered by the fast
layer and the container scenarios; the lane exists to prove the native body, the real kernel
reboot and the fresh-connection verification. Preparing the whole foundation on a cloud image
is not part of this lane because the cloud image's auxiliary daemons and virtual network make
that a different, longer qualification (see [Not qualified](#not-qualified)).

## What the section proves

- **Checks.** Every check is ordinary discovery through the fixed root read; opening the
  section reads only the stored snapshot and makes no SSH connection. Each row says what was
  seen, why it matters, when it was read and at most one next action. Unreadable evidence is
  "Could not check" with its reason, and there is no score. A rule, setting or manager outside
  the supported shape is reported once and blocks only the action that depends on it.
- **Firewall.** The standard is UFW active at boot, IPv6, deny incoming, allow outgoing, deny
  routed and logging low, with each effective SSH port, 80/tcp, 443/tcp and 443/udp. Operator
  ports are added and removed in the supported grammar. Docker, firewalld, a foreign nftables
  or iptables ruleset, an edited rule file or an unsupported UFW rule refuses firewall actions
  only. The review says a provider firewall is outside what Barectl can see.
- **SSH sign-in.** The fixed `00-barectl-sign-in.conf` drop-in disables passwords and
  keyboard-interactive sign-in and limits root to keys, or refuses root when the verified
  connection is not root. The review lists login accounts without readable keys. A later
  setting or `Match` block that overrides the policy is detected, and `sshd -t` runs before a
  reload.
- **Confirm-or-revert.** Firewall and SSH changes save a root-only preimage, arm a 300-second
  timer, apply and validate, then confirm over a **new** verified connection. The result is
  Kept, Put back or Not known from native evidence. Every other change refuses while a window
  is open or a put-back failed. A restart inside the window keeps the new configuration.
- **Automatic security updates.** The check reads Ubuntu's own effective settings, timers,
  conffile digest and newest log. Turn on and Turn off use the package's debconf setting and
  `dpkg-reconfigure`; they never add a second scheduler, never enable automatic reboot, and
  leave customized origins, blacklists and disabled timers alone.
- **Ubuntu updates.** Waiting updates are listed from current lists with their age, security
  first, and phased, held and blocked updates marked. Check for updates refreshes the lists.
  Install updates names every package, version and new dependency and admits only that exact
  transaction; removals, downgrades, holds, pending dpkg states and modified conffiles refuse.
  The review names the services and sites a restart may pause. Verification reads installed
  versions, `dpkg --audit`, profile units, Caddy routing and site readiness.
- **Restart.** The review names `/run/reboot-required.pkgs`, sites, services, downtime and the
  scheduled-task disclosure. The body refuses while managed work runs, writes its result and
  reboots. Success is a new boot ID on a fresh connection with services and sites answering.
  No connection in ten minutes is outcome unknown with provider-console guidance, never a
  retry.
- **Permissions, audit and accessibility.** Viewing uses the existing view permissions and
  preparing uses the existing prepare permissions plus Shared consent; there is no
  security-specific permission. A viewer or site operator sees no control and a forged POST
  is refused. Security records live only in the Barectl database. The Security default view
  passes the #179 banned-terms check, and the restart and updates controls work by keyboard at
  320 px.

## Server Jobs

Server Jobs is specified by [#284](https://github.com/rajandangi/barectl/issues/284) and
delivered by [#412](https://github.com/rajandangi/barectl/issues/412),
[#285](https://github.com/rajandangi/barectl/issues/285),
[#291](https://github.com/rajandangi/barectl/issues/291),
[#289](https://github.com/rajandangi/barectl/issues/289) and
[#286](https://github.com/rajandangi/barectl/issues/286); this record is
[#413](https://github.com/rajandangi/barectl/issues/413).

| Evidence | Revision |
| --- | --- |
| Change result line carries its kind and sites (#412) | `7d536b3f` |
| Jobs reads Barectl changes from any controller (#285) | `7e0bac4a` |
| Recent-result ranges, filters and viewer time zones (#291) | `b361305d` |
| Automatic work from Phase C's projection (#289) | `3c356baf` |
| Backup runs and schedules from Phase D's observation (#286) | `50df7d5c` |
| Qualification code and documents (#413) | The `jobs/413-qualification` head that follows `50df7d5c` |
| Review fixes and the native-read cost fix | `88f7848f` (integration head) |

**Environments.** The measurements below are local arm64: an Apple M4 Pro with 14 CPUs and
64 GiB host memory; the Docker VM exposes 14 CPUs and 15.7 GiB. The server image is the
current L5 snapshot from `docker/disposable-server/pins.json`, Ubuntu 26.04.1 LTS, systemd
259.9-0ubuntu0.1 (`barectl-disposable-l0:26.04-329707f95c4f`). The controller runs Python
3.14 and Django 6.1.1. No hosted amd64 run was made for this section; see
[Not qualified](#not-qualified).

**Journal-read cap and Check now.** The literal cap remains `HISTORY_LINES = 90`. Each
measurement rotated and vacuumed the image's journal, then wrote 60 real transient
`barectl-apply-*` units with one stage and one result line each (120 lines), so the read
returns 91 lines and reports truncation. `Check now` was measured from
`request_discovery` through the batch worker returning and publishing a newer snapshot,
three times on each freshly booted L5 container capped with `--memory=N --memory-swap=N`.
The fixed journal command and the full `jobs.observation.read` were timed over the same SSH
connection.

| Measurement | 1 GiB | 2 GiB | 4 GiB |
| --- | --- | --- | --- |
| Check now, median of three | 1.994 s | 1.993 s | 2.008 s |
| Check now runs | 2.028, 1.994, 1.951 s | 1.993, 1.974, 1.993 s | 2.008, 2.054, 2.000 s |
| Journal read, fixed command | 0.013 s | 0.011 s | 0.011 s |
| Lines returned / bytes | 91 / 49,954 | 91 / 49,951 | 91 / 49,953 |
| Full Jobs read | 0.048 s | 0.044 s | 0.046 s |
| Rows from 90 retained lines | 45 | 45 | 45 |

The L5 fixture enabled all three provider families in the same read: one scheduled task,
one queue worker, one cache observation and one backup observation, plus the change rows.
These Check now figures were taken before the final `88f7848f` read change described below,
so they are conservative: that change removed work from every discovery.
The journal read is line-capped, not byte-capped; the 91-line answer stayed at about 50 KiB,
well inside the 64 KiB SSH answer bound.

**Native-read cost.** The first delivered read priced the Running group with the retained
unit state of all `barectl-apply-*` units and read the journal twice. At the 100-unit
retention cap that cost about 2.6 s per discovery on the 1 GiB lane, and the hosted Native
shards missed their 300 s target. `88f7848f` filters the running read to units systemd
reports as `running` or `activating` (4 ms at the cap) and reads the oldest retained time
and the bounded history in one authorized command instead of two. The full retained
inventory read remains cleanup's, which needs it; a retained unit that printed no stage or
result line is therefore not listed, while the journal still supplies every run that
reached the server.

**Breadth: rotation and boot.** `JobsSurvivingEvidence` is a new `breadth`-tagged scenario,
never in the merge build. It starts from L5, performs a real scheduled-tasks change and
confirms Jobs shows it, seals the journal with `journalctl --rotate`, waits two seconds,
vacuums with `journalctl --vacuum-time=1s` and confirms no `barectl-result` line remains, then
performs a real queue-workers change and boots the container with `stop_for(20)`. After
rediscovery it asserts the surviving queue-workers change is shown, the removed
scheduled-tasks change is absent, the **The server's retained change history starts** notice
is present with a time after the surviving run, and no notice says the server has no evidence.
The local arm64 item passed in **38.6 s** (44 s lane), against the 180 s item limit and the
300 s lane target, with `docker/disposable-server/run-scenarios.sh --env-file .env --
--breadth disposable.test_breadth.JobsSurvivingEvidence`.

**Second-controller reconstruction.** Every provider is read from server evidence, never from
another controller's database. The change provider is proved by two scenarios that start
controllers with their own database, account, saved connection and host trust: S3
`HttpSiteControllerRecovery` (a second SQLite database and host trust after the first worker is
killed) and S5 `FreshControllerReconstruction` (two controllers, each with its own database,
key and known-hosts file). Both assert the second controller's Jobs shows the first
controller's **Create PHP site** run as Finished, with its kind and site. Phase C's
`WordPressServerCron` and `LaravelQueueWorkers` each rebuild a `Snapshot` from a fresh
discovery and assert the Jobs automatic row (a succeeded scheduled task with a next run; a
running queue worker). Phase D's `ScheduledCapture` rebuilds the stored snapshot and asserts
the Jobs backup row with its onsite and offsite findings and the backup timer On. No provider
row reads the first controller's local run record; the optional run link is the only join. On
this head the two second-controller scenarios passed together in 41 s (S3 13.4 s, S5 31.3 s).

## Acceptance criteria

- **#411.** The update guard watches only `apt-daily.service` and
  `apt-daily-upgrade.service`; `unattended-upgrades.service` is the shutdown helper and is
  active on a 26.04 host. The S2 refusal scenario and the fast probe tests pass, and the
  container image now carries the cloud image's packages.
- **#302.** The six checks, their stored snapshot rows, the no-SSH GET path, the freshness
  notice, the out-of-shape report and the fresh-controller reconstruction are proven by
  `SecurityChecks` and the fast section tests.
- **#306.** The UFW standard, operator ports, the confirm-or-revert window, the second
  controller's refusal, the held lock and the blocking-rule put-back are proven by
  `FirewallLifecycle` on both architectures in the required/weekly Native jobs.
- **#308.** The fixed drop-in, root policy, account disclosure, `sshd -t`, reload and window
  recovery are proven by `SignInLifecycle`.
- **#303.** Automatic updates on and off, the package's debconf path, the customized-settings
  refusal and the native history read are proven by the automatic-updates tests and the
  scenario's fresh discovery.
- **#304.** Check for updates and Install updates are proven by `SecurityUpdates`, including
  the exact transaction, the stale review, the unreviewed dependency, the hold and the edited
  conffile.
- **#414.** The scheduled and dispatchable `Native VM` workflow boots the pinned cloud image
  under QEMU, waits for cloud-init, runs the `vm` tag over SSH, uploads logs and opens or
  comments on `Native VM lane failed` on failure. It never runs on a pull request and adds no
  merge time. The arm64 lane passed locally; the hosted amd64 run is recorded in
  [Handoff](#handoff).
- **#305.** Review details, the body's refusals, the new-boot success rule, the ten-minute
  unknown outcome and the no-retry rule are proven by the fast engine and restart tests, the
  body's shellcheck and `VmRestart`. The section's control, permission refusal, CSRF,
  banned-terms and 320 px checks are proven by the Django and browser tests.
- **#415.** This record, the rewritten current-behavior documents, the amended ADRs and the
  updated glossary are the qualification artifacts. The full local build and the four
  security scenarios are recorded above; the hosted runs and any gap are below.
- **#413.** The Server Jobs section above names the revisions, environment, systemd version,
  enabled providers, the 90-line cap and the Check now times on 1, 2 and 4 GiB containers,
  the rotation-and-boot breadth item and the second-controller reconstruction claim.
  `docs/server-jobs.md` now covers the saved-read path, permissions, legacy result lines,
  retained-history wording and the certificate non-provider; the remaining gaps are below.

## Not qualified

- **The cloud-image foundation** was exercised locally and reached the foundation body, but
  preparing the full foundation on the cloud image is not qualified. The image's auxiliary
  daemons, virtual DHCP and abrupt teardown make it a separate lane; the container scenarios
  remain the foundation qualification. The lane's smoke and restart body are qualified without
  it.
- **Restart outcome unknown and refusal under active work** on a real VM are fast-layer and
  container-engine evidence, not VM-lane evidence. The VM lane proves the successful reboot
  and verification; it does not stop a guest and wait ten minutes.
- **Two-controller exclusion across every security change** is proven at the engine's shared
  preamble and in the firewall and sign-in scenarios. Each kind inherits the same preamble;
  there is no separate two-controller run for every kind.
- **Automatic-update restarts of MariaDB, PostgreSQL or Valkey** are disclosed by the reviews
  and covered by the update scenario's services list. A Deploy or capture that loses its
  database connection to such a restart is Phase B/D evidence, not this record.
- **Cloud and provider firewalls, Docker hosts, fail2ban/CrowdSec, CIS/Lynis scores, Ubuntu
  Pro, release upgrades, scheduled restarts and fleet-wide patching** are outside Phase E and
  are not qualified here.
- **Evidence the server no longer retains.** The rotation-and-boot breadth item proves that a
  real journald vacuum removes an older change and that Jobs shows the survivor and the start
  of the retained history without claiming nothing ran. It does not prove recovery of rows the
  server removed, a journal on separate storage lost with a host, or a power loss.
- **A real kernel reboot.** The breadth item restarts the container's init, a userspace reboot.
  The kernel and boot ID are shared with the Docker VM; unit enablement, timers and journal
  files are re-exercised, but a kernel panic, a power loss or a full host reboot is not.
- **A real 1, 2 or 4 GiB host.** The Check now figures are containers capped with
  `--memory`; the kernel, page cache and Docker VM are shared, so they are not whole-host
  measurements. The 60-unit journal used for the cap is synthetic evidence, not 30 days of
  real changes; the cap is a line bound and journal retention remains native policy.
- **Runs written before the result line carried kind and sites** stay **A Barectl change** with
  no site. The fast layer covers those lines; the native scenarios do not manufacture one.
- **No copy timer.** Phase D's scheduled capture performs the offsite copy, so Jobs shows copy
  **runs** when their result lines exist but has no invented copy timer. A copy scheduled
  independently of a capture is not a supported convention.
- **A separate second-controller database and host trust for Automatic work and Backups.** S3
  and S5 provide that for the change rows. Phase C's and Phase D's provider assertions rebuild
  the Jobs rows from a fresh discovery in their lifecycle scenarios, as #284's Testing
  Decisions chose; they do not start a second controller process with its own database.
- **Hosted amd64 and the breadth workflow.** All Server Jobs native and breadth evidence here
  is local arm64. No hosted amd64 run of the new breadth item, the 1/2/4 GiB measurements or a
  full hosted Server Jobs build was made for #413; the required merge checks and any hosted
  breadth dispatch belong to the pull request that follows this record.

## Handoff

The integration branch merged as pull request
[#483](https://github.com/rajandangi/barectl/pull/483) at `95500402`. The required `Native`
check on the PR head `cd503bbe` passed all 11 amd64 shards in run
[41414796825](https://github.com/rajandangi/barectl/actions/runs/41414796825); `browser`,
`check`, `frontend`, `dependency-audit` and `paths` passed in the same run pair.

The review follow-up is pull request
[#484](https://github.com/rajandangi/barectl/pull/484), merged at `0a4703b2`. Its hosted
`Native` run and the final `main` `Native VM` dispatch
[41538241820](https://github.com/rajandangi/barectl/actions/runs/41538241820) passed on
amd64; the VM job took 4 m 52 s, ran all three tests in 57.1 s and uploaded its console,
QEMU, mirror and test logs. The local arm64 build, the four container scenarios and the
arm64 VM lane are evidence above, not substitutes for the hosted required checks.
