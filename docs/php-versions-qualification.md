# Per-site PHP qualification

The accepted specification is [per-site PHP versions](php-versions.md), tracked in [#236](https://github.com/rajandangi/barectl/issues/236). [ADR 0016](adr/0016-limit-third-party-php-supply.md) accepts the source policy. Acceptance does not qualify any third-party runtime.

The source-policy documents are committed locally as `fab31d2`. The [2026-10-07 metadata preflight](php-source-preflight.md) authenticated both release indexes on arm64, tested the source-specific seven-day expiry limit, checked effective preferences and simulated all eligible profiles. It did not install packages or test a Barectl source-setup payload.

## Qualification matrix

| Ubuntu | Architecture | PHP 8.3 | PHP 8.4 | PHP 8.5 |
| --- | --- | --- | --- | --- |
| 24.04 | amd64 | Unqualified | Unqualified | Unqualified |
| 24.04 | arm64 | Native journey tested; qualification pending | Native journey tested; qualification pending | Native journey tested; qualification pending |
| 26.04 | amd64 | Unqualified | Unqualified | Unqualified |
| 26.04 | arm64 | Native journey tested; qualification pending | Native journey tested; qualification pending | Native journey tested; qualification pending |

A combination remains unavailable for new unified-source package or site plans until its required qualification evidence and delivery gates are complete. Existing qualified Ubuntu-default workflows keep their previous qualification. Reported native sites do not imply that their source or branch is admitted for a new change.

## Recorded implementation checks

The selected-site database-driver and challenge modules passed all 16 tests on each supported Ubuntu release, arm64, using the disposable runner on 2026-10-07. Selected revision-4 native cases additionally passed for driver installation/reload, MariaDB and PostgreSQL binding probes, challenge routes, real Certbot issuance, HTTPS and redirect. A changed site digest refused driver installation before packages changed. A new native site was reconstructed by a second controller with an empty database and its missing pool was finished without changing the Nginx bytes. These checks cover the existing Ubuntu-default supply. Source-backed non-default branches remain unqualified. The implementation remains local pending the delivery gates below.

Source setup additionally needs the distribution's `gpg` command. The disposable base images include `gpgv` but lack `gpg`; the source preparation correctly refuses that missing prerequisite. Native source tests must provision it explicitly as an administrator, without adding an implicit package installation to source setup.

The source module passed its original eight native tests on each supported release, arm64, after a stable-inventory rerun. Four additional focused source tests also passed on both releases. They cover guarded publication without metadata/package changes, matching administrator setup, Finish preserving existing resources, source/preference drift, missing CA trust, unsigned appended metadata and signed-index age. The compact fence additionally proves key permissions, global trust drift, seven-day expiry and restored digest equality. The added fault matrix refuses wrong or extra signing-key bytes, publisher keys in global trust, target-release priority interference and missing own-release or package indexes. A failed first source refresh also refused subsequent installation with unchanged package state. A generated signing-key fixture proved valid, expired and revoked signatures through native `gpgv` and the complete source collector. Its temporary expected identity belongs only to the fixture; it does not replace the approved publisher identity.

An acknowledged real-source PHP 8.4 installation survived SSH loss while its native process was running. Public reconciliation retained the same invocation, completed verification and did not resubmit; the native runtime cache was removed.

The native source runtime test also completed explicit refresh and installed PHP 8.4, 8.3 and 8.5 together on both arm64 releases. Each branch passed CLI, OPcache and FPM verification, preserved the previously installed branch's configuration and cleaned its private archive cache. A further native run installed both MySQL and PostgreSQL drivers through the public preparation/apply workflow for every branch on each release. This test temporarily admits the combinations in the fixture; it does not enable them in the public qualification gate.

Nine acquisition tests passed on each arm64 release using Ubuntu's authenticated `hello` package and APT 2.8.3/3.2.0. They prove that a same-size poisoned shared archive stays unchanged and is ignored, freshly corrupted and partial downloads are rejected before executable hooks, verified acquisition precedes hooks and the exact guard, `_apt` sandbox ownership and empty root cache admission hold, lock contention and exact-guard failures refuse, SIGKILL and timeout clean native runtime state, and oversize payloads refuse before unit creation. This qualifies the shared acquisition engine on those releases; it is not source-backed PHP journey or amd64 proof.

An official amd64 Ubuntu container could be downloaded locally, but execution failed with `exec format error`: the current Docker daemon has no x86 emulation. No amd64 result is inferred from arm64.

The integrated source-backed public workflow passed on both arm64 releases. It set up and refreshed the source, installed PHP 8.3 and 8.4, created revision-4 sites, then installed PHP 8.5 and created a third site, checked real branch/user execution and encoded 0600 sockets, installed branch-specific PostgreSQL drivers for all three branches and the 8.4 MySQL driver, bound PostgreSQL databases on 8.3 and 8.5 and MariaDB on 8.4, then issued through Certbot and enabled HTTPS/redirect for all three sites. It preserved the other site's bytes, reconstructed all three sites using an empty controller database and both engines through fresh privileged catalog inspection. Before its HTTPS stage, a fresh controller finished only the missing 8.4 pool and temporary probe. A branch-switch request refused. The fixture temporarily admits the public qualification gate; trust, acquisition, SSH and native execution remain real. This is native/public-view proof, not a Chromium source journey.

All 47 local production/development browser tests passed. The four affected native browser journeys passed on both arm64 releases for Ubuntu-default supply. Standards and specification review findings were repaired and rechecked with zero remaining actionable findings. The expanded source browser journey also passed in production and development asset modes on both arm64 releases: Ubuntu 24.04 took 181.5 and 177.5 seconds respectively; Ubuntu 26.04 took 178.7 and 190.5 seconds. It covers keyboard review, source publication without implicit refresh or package changes, explicit refresh, immutable PHP 8.3/8.4 selection, two sites, a branch-specific MariaDB driver and binding, HTTPS/redirect, Activity, Finish with a missing pool, fresh-controller reconstruction, mobile overflow and console errors. Its ordinary second-controller discovery reports protected database catalogs as inaccessible; independent privileged catalog reconstruction is covered by the native service journey. Only the public qualification gate is temporarily admitted in the fixture; the source, acquisition and native checks remain real.

## Regression and evidence limits

The broad native sweep completed on both arm64 releases, running 244 tests against a 243-test inventory while new test methods and fixtures were still changing. It reported five failed classes: a source-class count mismatch and four fixtures using superseded payload text, request fields, controller-user lookup or Finish ordering. The original eight source methods passed a stable-inventory rerun. The three affected legacy site classes passed corrected focused reruns on both releases, and the final integrated three-branch, both-engine journey passed on both in 255 seconds. Two VM reboot tests in the broad container collection were skipped; this record makes no VM qualification claim. The final native collection contains 251 tests per release, including those two VM-only cases. The aggregate sweep command did not pass, and no required native commit status is inferred from these combined local results.

After moving shared support out of test modules, the native first-site journey and all three affected native browser cases passed on both releases. All 1,275 non-browser tests passed with 252 environment-specific skips, and all 47 local browser tests passed. Ruff, formatting, mypy, Vulture, templates, Django checks, migration checks, frontend checks/build and the Python dependency audit passed. The npm audit remains the exception described below.

Exact-version source ambiguity has public review coverage rather than an injected native repository fault. Missing individual PHP binaries are covered by package admission; the native source fault removes the complete package index. The failed source-refresh test starts without usable prior source indexes and does not qualify a failed refresh retaining valid older indexes. These limits remain visible before enabling any source combination.

## Required evidence

- Reviewed source setup creates only missing exact resources, refuses drift, preserves existing PHP and never refreshes or installs implicitly.
- Fresh native package acquisition rejects a poisoned shared cache and corrupted download before package hooks. Record APT versions, hook order, sandbox ownership, cache locks, native cleanup and the 16 KiB payload bound.
- All advertised branches install without upgrades or removals, preserve automatic dependency markings and pass FPM/CLI, syntax, pool, driver and listening-socket checks.
- Separate sites retain branch selection through HTTP, challenge, HTTPS, redirect, database binding and Finish with an absent pool. Discovery reconstructs them from a controller database with no previous request or history.
- Old native site forms retain their exact bytes. Duplicate pools, unavailable evidence, source/priority/key drift, support expiry and conflicting controllers refuse the affected action.
- The operator journey passes the production and development browser checks, including permissions and review. Required local gates and full native statuses cover the exact published revision.

## Delivery blocker

[#221](https://github.com/rajandangi/barectl/issues/221) currently blocks the required npm dependency audit. On 2026-10-07, `npm run audit:dependencies` still reports ten high findings rooted in `braces@3.0.3`, and npm publishes no newer version. The accepted decision is to wait for an upstream patch, with no override or audit exception. No push, passing audit, required native status or merge is claimed by this record.

Implementation and local evidence can proceed independently. The specification and its qualification ticket remain open until the required evidence and delivery gate pass.
