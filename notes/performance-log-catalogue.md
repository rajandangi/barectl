# Logs catalogue performance

Measured on 2026-11-15 against baseline `26c668a5f23427fd4adbf89f5d8ee653baa9f303`.

The Logs section used one latest-read query per visible source. A Laravel site has
seven sources, so building the section required nine queries including expiry and
site-wide rotation evidence.

`logs/services.py` now selects the newest row ID per source with `ROW_NUMBER`, then
loads only those rows in the same SQL statement. The window orders by `queued_at`
descending and primary key descending, matching the original lookups. Ranking IDs
keeps historical log-page JSON out of the window's sort. Source views retain catalogue
order, and a source without a read retains its empty state.

All catalogue reads now come from one database statement. A worker cannot commit
between separate source lookups and give the catalogue a mixture of read states.
Expiry and site-wide rotation evidence keep their existing separate queries.
Permissions, filters, active states, page expiry and remote execution are unchanged.

## Measurement method

The comparison runs `context_for_site` with an already-built server read and warm
permission caches. It measures section construction, not a complete HTTP request.
Both arms use the same temporary Django test database, Laravel site and stored reads.
The original function is loaded from the baseline commit and run alongside the current
function. Five warmups precede 100 samples per arm, alternating which arm runs first.
The benchmark records median and nearest-rank p95 wall time and SQL query count.

Each source has zero, ten, one hundred or one thousand stored reads. Only the newest
read in each seed batch retains its page, matching next-read deletion. The comparison
checks identical source order, selected read IDs, parsed pages, configured states,
active/live flags, read/follow permissions and rotation state/action. Every workload
must match before timing results are accepted. No SSH connection is made.

## Before and after

The final comparison ran after the controller tests and native scenarios finished,
without those competing workloads. Times are local measurements, not an HTTP latency
guarantee.

| Stored reads | Queries before / after | Median before / after | p95 before / after | Median reduction |
| --- | --- | --- | --- | --- |
| 0 | 9 / 3 | 2.887 / 1.174 ms | 3.673 / 1.598 ms | 59% |
| 70 | 9 / 3 | 3.174 / 1.397 ms | 3.377 / 1.540 ms | 56% |
| 700 | 9 / 3 | 4.084 / 1.913 ms | 4.345 / 2.141 ms | 53% |
| 7,000 | 9 / 3 | 15.683 / 8.364 ms | 39.391 / 17.697 ms | 47% |

All workloads returned identical compared values. Catalogue lookups fell from seven
queries to one; the section's total fell from nine to three, a 67% reduction.

## Regression coverage

`logs.test_logs.LogsPageTests.test_the_catalogue_reads_the_latest_sources_in_one_query`
failed against the original implementation with `9 != 3`. It checks timestamp
ordering before primary-key ordering, tied timestamps, missing sources, failed reads
without fallback to older pages, running reads, retained filters and isolation between
sites and servers. Existing tests cover expiry, permissions, rotation evidence and
the browser journeys.

The transcript replay workflow accepts this as a command-neutral change. Only the
source audit hash changes in `discovery/transcript_sources.json`; recorded commands
and transcript contents are unchanged.

## Validation

- Full controller suite before: 2,784 tests in 27.837 s, passed with one existing skip.
- Full controller suite after: 2,785 tests in 26.798 s, passed with the same skip.
  The timing difference is within normal variation and is not a suite-speed claim.
- Focused Logs tests: 56 passed. Logs browser tests: six passed.
- Command-neutral transcript replay: 56 passed. Provenance and manifest checks:
  17 passed after the audit refresh.
- Native scenarios: 93 of 93 passed in 319 s. This exceeded the 300 s target by 19 s
  and remained below the 900 s limit. Some controller checks and exploratory benchmarks
  ran concurrently with this native run; no native baseline comparison was made.
- Ruff lint and formatting, strict mypy, Vulture, module-map check, provider setup
  check, template checks, Django system and migration checks, frontend checks including
  Knip, and `git diff --check` passed.

## Framework support

This uses the existing Django 6.1 ORM, with no dependency or schema change. The
implementation follows Django's documented [window expressions and subqueries](https://docs.djangoproject.com/en/6.1/ref/models/expressions/)
and SQLite's documented [`row_number` and partition ordering](https://www.sqlite.org/windowfunctions.html).
Selecting only IDs before loading the winning rows is a Barectl performance choice.
