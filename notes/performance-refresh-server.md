# Refresh server snapshot publication

Measured on 2026-11-15 against `d6824dac507a2e0651215fd542cba512ad9de3f9`.

## Hotspot and change

The Refresh server worker publishes its collected snapshot in
`discovery.services._discover`. Its final Save the server details stage calls
`discovery.snapshot.save_snapshot` inside the transaction that records success.
`_save_backups` previously recorded each site's integrity findings separately, with
two deletes when neither location had a finding, or an `update_or_create` per location
when findings were present. Every observed site incurred this work, including sites
without enabled backups.

`backups.integrity.record_many` now groups missing locations into one delete and
upserts the present findings through Django's `bulk_create(update_conflicts=True)`.
Snapshot publication passes all observed sites together. The single-site `record`
entry used by Check backups delegates to the same implementation.

The existing unique constraint on server, site identifier and location identifies
conflicts. Updates preserve row IDs and replace every observation field, including
the local check time. An absent finding still clears the corresponding old finding;
sites outside the supplied observations and other servers are left alone. Duplicate
findings for a location still use the last supplied value, and unsupported locations
are ignored as before.

The batch runs in one transaction. A failure after a cleanup delete now rolls that
delete back even for the single-site caller. Snapshot publication retains its outer
transaction and conditional lifecycle transition, so no partial snapshot is published.
The change preserves SSH commands, native locks and permission checks and requires no
schema or dependency changes.

## Before and after

These are local timings of the snapshot-saving transaction, not end-to-end Refresh
server times. SSH collection, queue waiting, authorization and browser polling are
outside the measurement. Attempt creation is also outside the timed region.

| Sites | Integrity findings | Total SQL queries before / after | Median before / after | p95 before / after | Median reduction |
| --- | --- | --- | --- | --- | --- |
| 0 | None | 21 / 21 | 3.231 / 3.410 ms | 4.590 / 5.516 ms | -6% |
| 1 | None | 28 / 29 | 4.146 / 4.119 ms | 5.155 / 5.061 ms | <1% |
| 1 | Both locations | 34 / 29 | 4.590 / 4.180 ms | 5.753 / 5.003 ms | 9% |
| 16 | None | 58 / 29 | 10.535 / 6.571 ms | 12.039 / 8.609 ms | 38% |
| 16 | Both locations | 154 / 29 | 17.707 / 7.898 ms | 21.127 / 10.221 ms | 55% |
| 64 | None | 154 / 29 | 28.736 / 13.341 ms | 38.588 / 22.438 ms | 54% |
| 64 | Both locations | 538 / 29 | 56.590 / 18.838 ms | 63.925 / 32.462 ms | 67% |

For the measured 64-site case with findings, integrity-table queries fell from 256
to one. Total SQL counts also include transaction/savepoint statements and the rest
of snapshot replacement. The one-site empty case adds one SQL statement because the
new helper has a transaction around the whole replacement. The zero-site median was
0.179 ms higher with the same query count. Absolute timings vary between runs; this
comparison does not establish a speedup for empty or one-site snapshots without
findings. Larger batches may be split by Django to respect database limits.

The benchmark uses a temporary SQLite file with the application's WAL and transaction
settings, and the same synthetic collected input for both implementations, including
the site rows with their accounts, names, PHP versions and native file paths, as well
as their backup observations. It loads the original
`_save_backups` and `record` functions directly from the baseline commit. Five warmups
precede 100 samples per implementation and workload, alternating which implementation
runs first. The benchmark ran without the native or controller test suites competing
for resources. p95 is the nearest-rank percentile.

Time is frozen for observation timestamps. The returned collected snapshot and all
integrity observation columns match exactly between implementations for every
workload. The test database is removed afterward, and no SSH connection is made.

## Regression evidence

The snapshot regression test exercises mixed absent, new and updated findings through
`save_snapshot`. It checks every returned finding field, local timestamps, preservation
of existing row IDs and isolation from other sites and servers. Its integrity-query
bound failed on the original implementation with 23 queries versus at most two.

The rollback test drives a real database constraint failure after an earlier location
would have been cleared. Running that test with the original `record` function leaves
the earlier finding missing and fails. The new implementation retains both original
findings and passes.

## Validation

- Controller suite before: 2,785 tests in 25.989 s, passed with one existing skip.
- Controller suite after: 2,787 tests in 26.278 s, passed with the same skip. The timing
  difference is within normal run-to-run noise.
- Focused snapshot and integrity tests: 31 passed.
- Command-neutral transcript replay: 56 passed. The source audit hashes were refreshed
  through the repository workflow; recorded commands and transcript contents are unchanged.
- Targeted browser checks: two passed, covering the Refresh server journey and the
  separate display of integrity findings.
- Native scenarios: 93 of 93 passed, exit status zero, in 307 s. This is seven seconds
  above the 300 s target and below the 900 s limit. The run reported cleanup residue
  after FullSiteRestore and Retention, each a retained integrity-check service. As
  documented in `docs/quality.md#native-layer`, the runner discarded those servers
  before subsequent scenarios; these were not scenario assertion failures.
- Ruff lint and formatting, strict mypy, Vulture, module-map check, provider setup
  check, frontend checks including Knip, template checks, Django system and migration
  checks, and `git diff --check` passed.

## Framework support

Django 6.1 documents [bulk creation with conflict updates](https://docs.djangoproject.com/en/6.1/ref/models/querysets/#bulk-create)
for SQLite when the conflicting unique fields are supplied. `BackupIntegrity` is a
plain model with no custom save method or save-signal handlers, so the documented
bulk-create restrictions do not bypass application behavior here. The batch uses the
existing database uniqueness constraint rather than adding a separate coordination
mechanism.
