# Convention recognition qualification

[Specification #193](https://github.com/rajandangi/barectl/issues/193) implements
[ADR 0015](adr/0015-recognize-only-the-convention.md). Earlier release qualification
records remain historical evidence for their recorded revisions. This record covers
the final integration and the controller schema reset. Every required exact-head check
except the explicit known npm audit exception passed before delivery. #201 and #202 are closed with merged evidence.

On 2026-10-10, [#345](https://github.com/rajandangi/barectl/issues/345) removed Ubuntu 24.04 support; Barectl supports Ubuntu 26.04 only. The Ubuntu 24.04 results in this record are historical evidence, not current support.

## Delivered qualification

HTTP Finish merged in [PR #233](https://github.com/rajandangi/barectl/pull/233),
merge `d7b2d944c2d1d9f633ad2cef123e32d19eed2229`, tested head `b7995ea`.
Reconstruction and schema cleanup merged in [PR #234](https://github.com/rajandangi/barectl/pull/234),
merge `d9d64f4357add378e307a9d9177b72d65d273589`, tested head `ca420bb`.
The #234 merge has exactly its tested source tree. This final record changes only
documentation. PR #234's
[Checks](https://github.com/rajandangi/barectl/actions/runs/37576379636) report
check, frontend and browser SUCCESS; its
[Native](https://github.com/rajandangi/barectl/actions/runs/37576379513) reports
all 14 shards and both required release statuses SUCCESS. Cancelled earlier runs
are not qualification evidence.

The primary controller was manually rebuilt after schema delivery. Unchanged operator
accounts, password hashes and registrations were retained exactly from a protected
backup; no observations, requests, plans, jobs, sessions or operation history were
imported. All 63 other state tables are empty. Only initial discovery/bootstrap
migration records remain; SQLite integrity is OK, foreign-key violations are zero,
and Django check, migration drift and migrate check exit 0. The old database backup
and inactive sidecars remain protected. SSH configuration and credentials are unchanged.

The final read-only audit covers all 40 parent stories without actionable gaps.
The local complete integration results below are followed by passing exact-head CI.
The only exception is the known failed braces npm audit, explicitly accepted by the
[maintainer](https://github.com/rajandangi/barectl/issues/193#issuecomment-6031305490).
No audit threshold, CI requirement or branch protection was changed.

## Reconstruction evidence

`discovery.test_convention_remote.ConventionReconstructionTests` builds these native
states through ordinary administration on a disposable server:

- A hand-made site with exact account, paths, files and socket.
- A convention site whose Nginx file changed, with the expected content shown.
- A partly applied site with only its exact Nginx file and enablement link.
- A partly applied PostgreSQL binding containing the first statement's exact effects,
  then its satisfied state after an administrator completes the remaining statements.
- A foreign enabled site file and a foreign pool, each blocked individually.
- PostgreSQL clusters outside the release-default `main` profile, reported without
  querying their units or reading their configuration.

Two separate processes migrate empty SQLite databases and discover the same server
using their own controller keys. Their site and component evidence must match exactly.
After the hand-made binding is completed, another two empty databases independently
reconstruct its satisfied state and retain the other states unchanged.
The viewer sees the states without plan permissions. Neither database has an apply run
or plan preparation. Discovery must preserve regular-file bytes, path types, owners,
modes, link counts and targets, relevant service states and process IDs, and the fixed
site catalog read. Controller subprocesses clear the inherited SSH agent socket so each
uses its specified key.
The native runner executes this test on Ubuntu 24.04 and 26.04. Site finishing and
database finishing have their own interrupted-run, reviewed-apply and serving proofs.

Local verification on 2026-10-07, runtime/test revision `42e2ede` (unpushed):

| Check | Literal result |
| --- | --- |
| Empty SQLite database, actual `migrate`, discovery columns and migration history | Succeeded; only discovery and bootstrap `0001_initial` recorded. |
| `discovery.test_sites discovery.test_site_pages discovery.test_databases` | Ran 83 tests, OK. |
| Full non-browser local suite | Ran 1195 tests in 57.392 seconds, OK, skipped 221. SSH/VM fixture skips and the platform-specific skip remain separate from native qualification. |
| Ruff check/format, mypy and migration drift | Passed; 293 files formatted, 239 typed source files, no migration changes detected. Vulture source evidence was corrected during delivery, as recorded below. |
| `discovery.test_convention_remote.ConventionReconstructionTests`, disposable Ubuntu 24.04 | Passed on aarch64, 1 of 1 tests ran. |
| The same native reconstruction test, disposable Ubuntu 26.04 | Passed on aarch64, 1 of 1 tests ran. |

The reconstruction run used `docker/disposable-server/run-tests.sh --env-file .env --
--lanes 1 discovery.test_convention_remote.ConventionReconstructionTests`. It is focused
local evidence, not the full native commit statuses. A further empty database and process
as the unprivileged observer preserves inaccessible evidence instead of calling it drift.
The final template, Django, npm installation, frontend, build and Python dependency
audit gates exit 0. The browser suite runs 47 tests in 199.444 seconds, OK. The required
npm dependency audit exits 1 with ten high affected package records from the unpatched
[braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm); see the
[dependency evidence](frontend-assets.md). The maintainer now approves delivery with this known development-dependency audit failure. The audit remains visible and unchanged; every other required check must pass on the exact PR head.
Complete native integration exits 0 on this revision, as recorded below. No missing
or skipped required result counts as a pass.

## Controller database rebuild

The discovery and bootstrap migrations are consolidated into their current initial
schemas. There are no replacement migrations, data conversion or compatibility paths.
An existing controller database must be rebuilt manually before this revision runs.
This resets local requests, snapshots, plans and audit; it does not change managed
servers or recover another controller's private records. Unchanged operator accounts
and local registrations may be retained manually from a protected backup, without
importing cached observations or previous operation records.

Stop the dashboard and worker. Preserve a protected backup of the controller database
if its records are needed, then move the old SQLite database and any SQLite sidecar
files aside. Keep SSH configuration, keys and known-host trust on the controller. With
the configured `.env`, run:

```bash
uv run --env-file .env python manage.py migrate
uv run --env-file .env python manage.py createsuperuser
```

Restart the dashboard and worker, add the server aliases again, and run discovery.
Resources follow their native shape regardless of who created them. Do not use
`--fake`, `--fake-initial`, or import stale snapshots to bypass this rebuild. To roll
back, stop the processes, restore the earlier checkout and its protected database
backup together, then restart them. Native resources are unchanged by the rebuild.

Django documents [migration squashing and the transition to normal migrations](https://docs.djangoproject.com/en/6.1/topics/migrations/#squashing-migrations).
Its normal compatibility rollout retains old migrations until all installations have
upgraded. ADR 0015 instead requires a manual controller rebuild, so Barectl deletes the
old files, retains valid dependency references to the initial migrations, and records
the current schema directly without a `replaces` attribute.

## Hand-made site HTTPS proof

`tls.test_issuance_remote.IssuanceTests.test_create_and_install_runs_all_steps_from_one_request`
uses an HTTP site created by ordinary administrator commands in its fixture. It discovers
the site, applies Create and Install from one request, verifies all four steps and checks
that every declared name serves the certificate fingerprint on disk. Its four-case native class passes on both releases in the complete integration run
at the recorded revision.

## Reviewed recovery and native fixtures

The site and TLS challenge native suites pass 64 of 64 selected cases on each disposable
release, aarch64. They cover interrupted Finish, retained account IDs and application
content, locked-password prefixes, socket drift and adversarial probe cleanup preserving
replacement bytes and inodes. A final exact-method run passes the HTTPS one-action proof
and content-stage adversary on both releases (2 of 2 each). These focused runs do not
replace the full integration suites.

The HTTPS proof and browser journey explicitly authorize the disposable SSH identity
to read locked-account evidence, then require an observed managed site before starting
installation. A separate unreadable observation remains unavailable. Root-only certificate
evidence retains its independent inaccessible outcome. This changes fixture authority,
not production permission checks.

Generated ACME management certificates now pass default strict Python TLS verification,
with hostname and certificate validation retained. The real strict handshake regression
and seven native ACME fixture cases pass; exact native method dispatch is independently
verified without relaxing expected counts.

Real-kernel VM tests are opt-in and outside these disposable suites' required evidence.
This revision does not expand historical bootstrap/renewal reboot qualification. Site
recovery proves container restart, not a new real-kernel reboot result. The full runner
selects two VM cases that skip on containers; Ubuntu 24.04 also lacks the 26.04
provider-only fixture for two cases. Record those skips separately from executed tests.

The final acceptance review retains failed/truncated password-lock reads as their
unreadable outcome and requires observed site identity before a binding conforms.
The collect-seam regressions reproduced the incorrect outcomes before the corrections;
the focused site/page/database suite runs 83 tests, OK. Candidate and foreign-grant
documentation now follows the same finite recognition rule.

## Complete native integration

At `42e2ede`, `docker/disposable-server/run-tests.sh --env-file .env -- --lanes 3`
exits 0 after 1059 seconds. The actual disposable releases are Ubuntu 24.04.5 LTS
and Ubuntu 26.04.1 LTS, both aarch64. All 64 item logs per release are OK; each
release has 220 unique test IDs, with no duplicates or unexpected skips.

| Release | Selected / ran, including skips | Executed and passed | Skipped |
| --- | --- | --- | --- |
| Ubuntu 24.04.5 | 220 / 220 | 216 | 4 |
| Ubuntu 26.04.1 | 220 / 220 | 218 | 2 |

The two opt-in `bootstrap.test_reboot_vm.RebootTests` methods skip on both container
releases. Ubuntu 24.04 additionally skips the provider pre-install hook and third-party
package-source cases, whose provider fixture exists only on Ubuntu 26.04. These skips
are not passing reboot or provider evidence. No live server was used for mutation.

This complete run covers fresh-controller reconstruction, missing-only HTTP Finish,
both database binding engines and their recovery, hand-made-site HTTPS installation,
probe publication and cleanup adversaries, native browser journeys and authorization.
The earlier stale database-refusal assertion failed a complete run and was corrected;
other interrupted runs are not qualification evidence. Their history remains in the
[delivery checklist](convention-recognition-todos.md).

This earlier local checkpoint predates delivery. The maintainer subsequently approved
the known npm audit exception, without changing audit thresholds or CI. Exact-head PR
checks, native statuses and the primary controller rebuild remain required for delivery. The isolated worktree database was
manually rebuilt after proving it empty, and independent freshly migrated databases
prove the current initial schemas. At that historical checkpoint #201, #202 and #193
remained open. The delivered qualification above supersedes that delivery state.

## Delivery validation correction

The managed-worktree Vulture invocation returned 0 because the existing metadata
exclusion matched its absolute checkout path. That result is not evidence of a source
scan. Clean tracked-file archives outside the excluded path reproduced one unused
native-test helper; it and its import were removed. The clean archive now passes
Vulture with the unchanged configuration and threshold. Exact-head CI also scans the
actual checkout and remains a required merge gate.

The primary controller rebuild was rehearsed against a private disposable database.
Unchanged operator accounts and registrations were retained manually; no cached
observations, plans, jobs, sessions or operation history were imported. The current
initial migrations, foreign-key checks and integrity checks pass. The subsequent actual
primary replacement passed after schema delivery, as recorded above. No live server was mutated by the controller rebuild.
