# Phase B qualification record: Laravel Deploy and Roll back

This record lists the evidence for the Laravel Deploy, Roll back and release-failure slice of
Phase B specification [#356](https://github.com/rajandangi/barectl/issues/356), gathered on
2026-10-19 for [#259](https://github.com/rajandangi/barectl/issues/259) and the two criteria
[#382](https://github.com/rajandangi/barectl/issues/382) left open. It names the revision
tested, the measured times against the budget of
[ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), what each native scenario
asserts, and what is not qualified. Anything this record does not list as passing is not
qualified. Phase B is not released, and the rest of Phase B (WordPress, settings and secrets,
site removal, catalog updates) is out of scope here.

## Revisions

Every number below belongs to one code revision, `5027e72` on
`feat/259-deploy-lifecycle`. Later commits on that branch add this record and its hosted
figures only.

| Evidence | Where |
| --- | --- |
| Local fast suite, validators and native lifecycle scenarios, arm64 | `5027e72` |
| Hosted Checks and Native (4 shards), amd64 | Recorded on the pull request (see [hosted runs](#hosted-runs)). |

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Local | arm64 | Apple M4 Pro with 14 CPUs and a 16 GiB Docker VM; 3 lanes by the runner's `--lanes 3` | Ubuntu 26.04 LTS by the digest in `docker/disposable-server/pins.json` |

The lane serves the offline fixtures of [#375](https://github.com/rajandangi/barectl/issues/375):
a Git host over HTTPS and SSH, a Pebble ACME server, the mirrored Ubuntu snapshot with
MariaDB, PostgreSQL and Git, and the mirrored Composer distribution archives of the fixture
Laravel application at `docker/disposable-server/fixtures/laravel-app`.

## Build budget

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Controller fast tests, 785 tests with `--parallel` | 16.5 s | 90 s | | Meets the target |
| Fast snapshot validators, 3 items | 34 s | 60 s | | Meets the target |
| Native lifecycle scenarios, 61 of 61 passed, 3 lanes | 318 s | 300 s | 900 s | Within the limit; 18 s over the target at 3 lanes |
| Longest scenario | 39.0 s (`SitePHPLongDrain`) | | 180 s | Within the item limit |
| Longest new scenario | 37.8 s (`LaravelDeployOutcomes`) | | 180 s | Within the item limit |

The four Laravel Deploy scenarios take 22.8 s (`LaravelDeployBootFailure`), 33.7 s
(`LaravelDeployMariaDB`), 19.1 s (`LaravelDeployPostgreSQL`) and 37.8 s
(`LaravelDeployOutcomes`) as one exclusive item each. `LaravelCreateMariaDB` records the
transcript again on this revision and takes 18.8 s. They share one MariaDB or PostgreSQL
install and one created site per item and reuse the lane's prepared L1, so the slice adds
four items to the suite.

## Scenarios

| Item | Asserts |
| --- | --- |
| `LaravelDeployMariaDB` | Create a MariaDB Laravel site, push a reviewed commit to the lane's fixture Git host, review and apply a Deploy. The review states the exact commit and the apply fetched it; the build installed no dev packages and no source checkout; the shared `.env`, `storage` and `bootstrap/cache` links hold and the release modes are 0711 / 2750 / 640 / 600; the pending migration ran once behind the gate and is recorded once; `current` switched; readiness answers 200 over the site's private HAProxy socket and over Caddy's HTTPS against Pebble; the site serves the new code; `APP_KEY` is unchanged. Then a Deploy with the site's migrations switch off reports the pending migration in the run's journal and runs none. Then Roll back reactivates a retained release with the "not reversed" wording, and a final Deploy prunes exactly the releases its review named. A full passive discovery runs no PHP, Composer, Git or Artisan (canary wrappers). |
| `LaravelDeployOutcomes` | The repository-shape refusals of [#382](https://github.com/rajandangi/barectl/issues/382): a URL-credentialled Git metadata, an unsafe branch, a submodule, a Git LFS filter and a repository hook are each refused at review. A forged apply without the migration acknowledgement cannot build a body. A commit with a broken `composer.json` fails before the switch, leaving the old release serving over HTTPS with no gate. A commit whose migration fails keeps the gate, keeps the old release serving over the socket, records no migration, and `Check what happened` reads the original unit's journal line. |
| `LaravelDeployBootFailure` | A Deploy whose release renames Laravel's health endpoint switches `current` and then fails readiness: visitors get 503 from the gate and never reach the release, the run reports which release is current, the previous release is retained, and the recovery read of the original unit reports `laravel_readiness`. |
| `LaravelDeployPostgreSQL` | The same applied lifecycle on PostgreSQL: the review's exact commit, the switched release, the recorded migration, the readiness over the socket and over HTTPS, and an unchanged `APP_KEY`. |

The [#259](https://github.com/rajandangi/barectl/issues/259) composer-requirement and
discovery criteria are carried by `LaravelReleaseReconstruction`
([#422](https://github.com/rajandangi/barectl/pull/422)): a CI-shaped release is read,
listed, judged and its PHP requirement refused, and no PHP, Composer or Git runs during the
read.

## Qualification items

| Item | Result |
| --- | --- |
| Review states the exact commit and the confirm screen requires the acknowledgement | Proven by `LaravelDeployMariaDB` (the review's document names the pushed commit, and the apply's release is that commit) and `LaravelDeployOutcomes` (a document without the acknowledgement is refused). The confirm-screen checkbox itself is the fast test `ChangeApplyForm` and its browser journey. |
| A PHP requirement the runtime misses is refused, naming it | Proven natively by `LaravelReleaseReconstruction` and by `laravel.test_change`. |
| A failure before the switch leaves the old release serving with no gate | Proven by `LaravelDeployOutcomes`: `laravel_composer`, the old release still answers 200 over HTTPS, and the Caddy file is the open form. |
| A failed migration or a failure after the switch keeps the gate and reports the current release; nothing is retried and old code is not reactivated | Proven by `LaravelDeployOutcomes` (gate 503, `current` unchanged, the failed migration unrecorded, one attempt) and `LaravelDeployBootFailure` (`current` is the new release, the gate stays up, the previous release is retained). `Check what happened` is the engine's read of the original unit, asserted in both. |
| A per-site switch turns migrations off; they are reported and not run | Proven by `LaravelDeployMariaDB`. |
| Visitors never reach a release whose `/up` failed | Proven by the failing-migration fixture (gate 503, old release over the socket) and the failing-boot fixture (gate 503, `/up` 404 on the release). |
| Deploy is a Site change and passive discovery runs no application code | The Site scope and its permissions are fast tests; the native `LaravelDeployMariaDB` canaries prove a full passive discovery runs no PHP, Composer, Git or Artisan. |
| A CI-shaped release is discovered and listed, and a fresh controller reconstructs `current` and the releases | Proven natively by `LaravelReleaseReconstruction` and replayed by `laravel.test_recorded`. |
| The native lifecycle runs on MariaDB and once on PostgreSQL within the budget | Proven by `LaravelDeployMariaDB` and `LaravelDeployPostgreSQL`; the item and build times are in the [budget](#build-budget). |
| `APP_KEY` is never rotated by a Deploy | Proven by `LaravelDeployMariaDB` and `LaravelDeployPostgreSQL`. |
| Hooks, submodules and LFS are refused by the Deploy path | Proven by `LaravelDeployOutcomes`. |

Defects the scenarios found and this revision fixes: pruning removed the wrong releases
(it kept the reviewed removal set); the preflight compared an alphabetical release list with a
recency-ordered one; a fetched release lost its branch and could never be deployed a second
time; the maintenance gate dropped a site's HTTPS listener and, once up, could never be
lifted; a rolled-back or re-deployed site had no shared Laravel storage skeleton to boot
`artisan optimize`; and Composer reached packagist on every build.

## Hosted runs

Filled in from the pull request's `Checks` and `Native` workflows once they complete.

## Not qualified

- **Laravel's front-controller fallback for application routes.** The site file rewrites only
  `/` to `index.php` and proxies `.php` paths, so a request to any other Laravel route returns
  404; the fixture application serves `/` and `/up` only. A real multi-route application is not
  qualified, and the Phase B requirement to add the fallback for WordPress and Laravel sites is
  still open.
- **`GET /up` at the raw HAProxy socket.** HAProxy's FastCGI application cannot map an
  arbitrary path to the front controller, so the body requests `/index.php/up` (PATH_INFO) over
  the socket, where the application still routes `/up`; `/up` directly is 404. The Caddy path
  uses the same form for one transport.
- **Dashboard recovery of a site a failed Deploy left gated.** While the maintenance gate is
  the site file, the site read judges it outside supported settings, so a fresh Deploy or Roll
  back review refuses until an operator restores the file by hand. The one-decision recovery of
  #356 story 57 is not qualified, and Roll back after a failed Deploy is therefore unproven.
- **Composer advisory blocking.** The offline lane reaches no host but the repository, so the
  build passes `--no-blocking`; on a real host a Deploy therefore also skips Composer's
  advisory blocking.
- **Assertion depth.** `--prefer-dist` is asserted by the absence of dev packages and of
  `.git` directories under `vendor`, not by reading the build's argv. The readiness ordering
  (socket, then Caddy) is asserted by the body's stage order and by the two failure fixtures,
  not by a live interleaving. Pruning is proven with four synthesised retained releases.
- **Browser journey.** No browser test for Deploy or Roll back was added; the journeys of
  [#179](https://github.com/rajandangi/barectl/issues/179) are unchanged.
- **Other hosts and architectures.** No real VM, no arm64 CI run and no hosted amd64 run of
  this revision yet.
