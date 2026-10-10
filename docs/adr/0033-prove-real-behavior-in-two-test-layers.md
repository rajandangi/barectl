# Prove real behavior in two test layers, within a 10-minute build

Accepted on 2026-10-10 for [#323](https://github.com/rajandangi/barectl/issues/323) and [#322](https://github.com/rajandangi/barectl/issues/322); applies to the target stack from Phase A. A full local build, pre-push checks and native suite together, targets 10 minutes on the reference host (14 CPUs, 64 GiB, Docker) and never exceeds 15. Required CI has the same target and limit. The previous harness took 60 to 80 minutes: every test class booted a fresh server, most WordPress tests reinstalled packages, MariaDB and WordPress, tests downloaded from live sites, and payload fault permutations ran as full native tests. Nothing failed when a test got slower, so the total drifted, and a build that slow is not run before pushing.

## What a test must do

Every test proves that something an operator or a site depends on works, or fails safely: a site serves over HTTPS, a runtime switch keeps the site's data, a refused plan changes nothing, a fresh controller rebuilds the same state. Tests that only restate the implementation, such as exact generated command strings, call counts or file bytes that no reader depends on, are not kept. Tests for removed code are deleted with that code. A test that fails intermittently is not retried automatically; it is quarantined with an issue and an owner, then fixed or deleted.

## Fast layer

Barectl's own logic runs without a server: request validation, plan building and admission, convention rendering, discovery parsing and outcome reconciliation. Native evidence enters these tests as recorded real command output, captured from a real server and stored as fixtures, the way pyinfra tests its facts and operations against about 1,600 recorded outputs. Rendered configuration is checked by the native validator where one exists (`caddy validate`, `php-fpm -t`), not by comparing text. Payload failure paths ("exit 44 when the pool directory is unsafe") belong here, run against the payload in a lightweight container without the full stack. This layer runs in parallel and takes about a minute.

## Native layer

About 15 to 25 lifecycle scenarios run on real servers, each proving a whole outcome rather than one step. For example: create a WordPress site, check it over HTTP, issue a certificate, check it over HTTPS, switch its PHP runtime, back it up, delete it, restore it, check it again; then discover from a fresh controller and confirm a repeated review changes nothing. One scenario bootstraps a plain Ubuntu 26.04 server; every other scenario starts from a cached snapshot image taken after bootstrap, keyed by a hash of its provisioning inputs. Scenarios on the same lane share one server and use their own site, user and database names; only a scenario that changes server-wide state gets a fresh container. Real failure handling is covered by one scenario per kind of failure (a held lock, a failed unit, a lost controller), not every exit status.

Nothing in the build reaches the internet. Packages come from a local APT and Nix cache, WordPress and other downloads from pinned local copies, and certificates from a local ACME server. A scheduled job checks the live upstreams (Caddy's repository, the Nix cache, wordpress.org) and reports drift without blocking merges; wider breadth, such as the second architecture, also runs on a schedule.

## Enforcement

The runner fails any native item over 3 minutes and any build over 15, and reports the total against the 10-minute target; CI does the same. A new native scenario states why the fast layer cannot prove it. Phase A's first spike (Nix, Caddy, one WordPress site, snapshot-based scenarios) measures the build before the rest of the harness is built. If it cannot stay within 15 minutes, the test design changes first; the limit is not raised quietly.

Comparable projects run this way: HestiaCP installs once in a prebuilt container and runs its system tests on that shared state in about 9 minutes per change; Trellis provisions once and deploys three WordPress variants with a local ACME server in about 7; pyinfra keeps 15 end-to-end tests beside its recorded-output tests and finishes in about 6; Kubernetes and Ansible keep slow and disruptive tests out of the merge check and quarantine flaky ones. Dokku, which runs exhaustive system tests on every change, needs about 143 parallel jobs and still takes 60 to 90 minutes. Sources are recorded in [#322](https://github.com/rajandangi/barectl/issues/322).
