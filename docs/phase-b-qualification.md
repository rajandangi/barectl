# Phase B qualification record

This record lists the evidence for the Phase B exit of specification
[#356](https://github.com/rajandangi/barectl/issues/356), gathered on 2026-10-24 for
[#387](https://github.com/rajandangi/barectl/issues/387). It audits every user story against
the code and tests that carry it, names the revision tested, records the measured times against
the budget of [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), and lists what is
not qualified. Anything this record does not list as passing is not qualified. Phase B is not
released.

The previous revision of this file qualified only the Laravel Deploy and Roll back slice
([#259](https://github.com/rajandangi/barectl/issues/259)); it is superseded by this record,
which keeps that evidence and covers the rest of Phase B.

**Gap-closure revision (2026-10-24).** This revision implements Laravel's front-controller
route and `/up` readiness ([#445](https://github.com/rajandangi/barectl/issues/445)), one
reviewed Domains and HTTPS change with WordPress and Laravel alias redirects
([#442](https://github.com/rajandangi/barectl/issues/442)), the Overview address and next
step ([#446](https://github.com/rajandangi/barectl/issues/446)), and Create site's Step 1
install of a missing database engine or PHP runtime ([#443](https://github.com/rajandangi/barectl/issues/443)).
It also adds browser journeys for the new Domains and HTTPS settings, Overview and the
WordPress Step 1 round trip. [#444](https://github.com/rajandangi/barectl/issues/444) adds
the optional certificate contact email after this record was gathered. [#447](https://github.com/rajandangi/barectl/issues/447)
added the remaining browser journeys: Deploy with its migration acknowledgement, Roll back
from the release list, the environment and WordPress settings, PHP settings, the database
engine install, site removal with its typed domain, and the HTTPS and certificate states.
Still not implemented: hosted shard balance ([#449](https://github.com/rajandangi/barectl/issues/449)).

## Revisions

Every local number in [Build budget](#build-budget) and [Scenarios](#scenarios) belongs to one
code revision, `5be4abc` on `fix/450-deploy-readiness`. The hosted figures belong to the revision
named under [Hosted runs](#hosted-runs), which differs from it only in documentation and, where
that section says so, dependency lock entries for disclosed advisories.

| Evidence | Where |
| --- | --- |
| Local fast suite, fast validators and native lifecycle scenarios, arm64 | `5be4abc` |
| Hosted Checks and Native (4 shards), amd64 | `9f42ba8`, Checks run [40066132997](https://github.com/rajandangi/barectl/actions/runs/40066132997) and Native run [40066133079](https://github.com/rajandangi/barectl/actions/runs/40066133079) (see [hosted runs](#hosted-runs)). |

## Environments

| Environment | Architecture | Host | Server image |
| --- | --- | --- | --- |
| Local full build | arm64 | Apple M4 Pro, 14 CPUs, 16 GiB Docker VM; 8 lanes by the runner's lane formula | Ubuntu 26.04 LTS by the digest in `docker/disposable-server/pins.json` |
| Hosted Native | amd64 | GitHub's `ubuntu-26.04` runners, 4 shards of 2 lanes | The same image |

The lane serves the offline fixtures of [#375](https://github.com/rajandangi/barectl/issues/375):
a Git host over HTTPS and SSH, a Pebble ACME server, the mirrored Ubuntu snapshot with MariaDB,
PostgreSQL and Git, the WordPress release mirror with its checksum API, and the mirrored Composer
distribution archives of the fixture Laravel application at
`docker/disposable-server/fixtures/laravel-app`. Every lane has no egress; the runner refuses a
name no mirror serves.

## Build budget

`docker/disposable-server/build.sh` at `5be4abc`: the fast gate, fast snapshot validators,
browser tests and native lifecycle scenarios run concurrently and each stage is timed.

| Stage | Measured | Target | Limit | Result |
| --- | --- | --- | --- | --- |
| Controller fast tests, 932 tests (`--parallel`) | 19.4 s alone, 42 s inside the build | 90 s | | Meets the target |
| Fast snapshot validators, 3 items | 39 s alone, 67 s inside the build | (part of the joint stage) | | The 60 s target is the joint stage; the validators have no separate target |
| Joint fast stage, as the build measures it | 67 s | 60 s | | Missed by 7 s in this build; met at 60 s in an earlier run |
| Browser tests | 54 s inside the build | | | |
| Native lifecycle scenarios, 65 of 65 passed, 8 lanes | 241 s | 300 s | 900 s | Within the target |
| Longest native item | 50.5 s (`WordPressCreateMariaDB`) | | 180 s | Within the item limit |
| Full local build, wall time | 241 s | 300 s | 900 s | Meets the target |

The [test time budget](quality.md#test-time-budget) measures one joint fast stage with the
fast gate and the validators side by side, and gives it a 60 s target. Builds of this code on
this host have measured 60 s, 67 s, 70 s and 78 s for that stage, with the fast gate at 19.4 s
to 27.3 s alone and the validators at 39 s alone; the four stages share 14 CPUs, so the joint
figure moves with what else is running and the 60 s target is met on a warm run but not on
every one. A build measured during an unrelated project's container run on the same host took
444 s with load averages above 100; it is excluded as host contention, not suite time. The fair
builds measured 218 s to 280 s, inside the 300 s target each time.

Native item times vary more than the total, because exclusive scenarios wait for the lane and
for each other: `LaravelDeployMariaDB` measured 102.1 s, 77.4 s, 67.4 s, 66.2 s and 49.3 s
across five builds; the last three builds follow the graceful reload that replaced the
five-second wait. `WordPressCreateMariaDB` is now the longest item at 50.5 s.

The hosted shards are reported separately in [Hosted runs](#hosted-runs): three of the four
exceed the 300 s target for one hosted shard (one met it) while all stay inside the 900 s
limit, tracked as [#449](https://github.com/rajandangi/barectl/issues/449).

## Scenarios

Phase B adds fifteen native scenario classes to the Phase A set. Each row lists the class and
the time this build took; a class that holds several test methods runs them in one exclusive
item against one prepared server.

| Scenario | Class | Local arm64 | Hosted amd64 |
| --- | --- | --- | --- |
| S11 HTTPS and certificate state | `HttpsSite` | 16.4 s | 37.6 s |
| S11 Database engine, MariaDB | `DatabaseEngineMariaDB` | 35.6 s | 67.7 s |
| S11 Database engine, PostgreSQL | `DatabaseEnginePostgreSQL` | 25.6 s | 42.4 s |
| S11 Site database, MariaDB | `SiteDatabaseMariaDB` | 37.6 s | 79.2 s |
| S11 Site database, PostgreSQL | `SiteDatabasePostgreSQL` | 28.9 s | 59.6 s |
| S12 WordPress lifecycle | `WordPressCreateMariaDB` | 50.5 s | 135.1 s |
| S13 Laravel create | `LaravelCreateMariaDB` | 32.1 s | 86.0 s |
| S13 Laravel Deploy and Roll back | `LaravelDeployMariaDB` | 49.3 s | 105.8 s |
| S13 Deploy refusals and failures | `LaravelDeployOutcomes` | 49.8 s | 110.9 s |
| S13 Deploy boot failure | `LaravelDeployBootFailure` | 33.8 s | 66.3 s |
| S13 CI release reconstruction | `LaravelReleaseReconstruction` | 13.6 s | 40.3 s |
| S14 Laravel on PostgreSQL | `LaravelDeployPostgreSQL` | 27.0 s | 56.8 s |
| S15 Catalog update and runtime removal | `CatalogRuntimeUpdate` | 30.2 s | 51.5 s |
| S15 Failed catalog update | `CatalogRuntimeUpdateFailure` | 17.5 s | 25.6 s |
| S16 Confidential input channel | `ConfidentialChannelLifecycle` | 3.3 s | 2.9 s |

The Phase A scenarios S1 to S10 also run on this revision and all passed; their times are in
the Phase A record. The hosted column is from the run named under [Hosted runs](#hosted-runs)
and is kept for comparison rather than as this revision's measurement. The longest item is
`WordPressCreateMariaDB` at 50.5 s locally and 135.1 s hosted, both inside the 180 s item
limit.

What the Phase B classes assert:

- `HttpsSite` creates a plain PHP site through the product's reviewed change against the lane's
  Pebble server: the home page answers over HTTPS with a certificate issued by Pebble, HTTP
  answers 308 to the HTTPS address, an unknown host gets 404 on HTTP and is refused on HTTPS,
  the public listeners are within SSH, 80/tcp, 443/tcp and 443/udp, discovery reads the site as
  HTTPS with an issued certificate and its expiry, a full collection rebuilds it, a repeated
  review proposes nothing, and a second site created HTTP only serves on HTTP with the state
  `http`.
- `DatabaseEngineMariaDB` and `DatabaseEnginePostgreSQL` install the engine through the reviewed
  APT transaction against the lane's pinned snapshot, then check its hardening: MariaDB listens
  on its socket alone with no anonymous account and no test database, PostgreSQL keeps peer
  authentication and a loopback-only listener. A second review proposes nothing, a fresh
  controller reconstructs the engine and its version, the second engine is Outside supported
  settings, and removal is refused while a site database exists and succeeds once it is gone.
- `SiteDatabaseMariaDB` and `SiteDatabasePostgreSQL` install the engine, create a site, bind
  `s<id>` over the socket, and prove through the site's own PHP master that it uses its database,
  sees no other, and cannot administer or log in over TCP with a password. A view, trigger,
  routine and event/function are dumped with the product's documented flags, dropped and
  re-imported by the same principal, and the other site's database is unreadable. A partial
  binding is finished without overwriting, a fresh review reconstructs it, and removing the site
  leaves another site serving.
- `WordPressCreateMariaDB` installs MariaDB, creates a WordPress site from the pinned offline
  release with the administrator password as a canary, and checks: the HTTPS home, login and
  REST pages answer, the canary signs in, pretty permalinks reach the front controller,
  `wp-config.php`, `.env` and PHP under uploads are denied, the private configuration is 0600
  with server-generated salts and no canary, the canary appears nowhere under `/var/www`,
  `/var/www/<id>/logs`, `/etc/caddy` or the journal, discovery reports core 7.1.3 without running
  PHP, a repeated review proposes nothing, and a reset password and core verification each
  report the documented outcome. A later test edits an extra constant with a second canary,
  proves the fixed block stays byte-identical and the value never leaks, and the last test
  removes the WordPress site through the reviewed removal and checks its Caddy file,
  directory, FPM and HAProxy configuration, accounts, database, principal and certificate are
  gone while the host no longer serves it.
- `LaravelCreateMariaDB` creates a Laravel site with a private repository over SSH, a deploy key
  and an exactly matched host-key fingerprint; it checks the private `.env`, the `APP_KEY`, the
  repository and branch, that a fresh controller reads the `.env` key names (never a value) and
  the deploy key's public half, and that an environment edit carries a canary that never leaves
  the private file.
- `LaravelDeployMariaDB` pushes a reviewed commit, deploys it, checks the exact commit, the
  build, the shared `.env`/`storage`/`bootstrap/cache` links, the release modes, the pending
  migration run once behind the gate, the switch, readiness over the private socket and over
  Caddy's HTTPS, that the site serves the new code immediately after the master's graceful
  reload and that `APP_KEY` is unchanged; then an
  environment save rebuilds the cached configuration the Deploy built, a Deploy with migrations
  off reports them and runs none, Roll back reactivates a retained release with the "not
  reversed" wording, a further Deploy prunes exactly the releases its review named, and a full
  passive discovery runs no PHP, Composer, Git or Artisan (canary wrappers).
- `LaravelDeployOutcomes` refuses URL credentials, an unsafe branch, a submodule, an LFS filter
  and a repository hook at review; a forged apply without the migration acknowledgement cannot
  build a body; a broken `composer.json` fails before the switch with the old release serving and
  no gate; and a failing migration keeps the gate, leaves the old release serving, records no
  migration and lets **Check what happened** read the original unit.
- `LaravelDeployBootFailure` switches `current` to a release whose `/up` is broken: visitors get
  503 from the gate, the run names the release that is current, the previous release is retained
  and the recovery read reports `laravel_readiness`.
- `LaravelDeployPostgreSQL` runs the same applied lifecycle against PostgreSQL.
- `LaravelReleaseReconstruction` reads a CI-shaped release, lists it, judges its shape and refuses
  a PHP requirement the runtime misses, with no PHP, Composer or Git executed during the read.
- `CatalogRuntimeUpdate` updates a live PHP build through the switch-and-drain with zero refused
  requests, keeps the previous generation, restarts only the tools whose own build changed,
  reverts to the previous build, and removes the runtime once no site or default uses it.
  `CatalogRuntimeUpdateFailure` proves a build that passes preflight but fails module
  verification reports `partial`, keeps the site serving and keeps the previous generation.
- `ConfidentialChannelLifecycle` stages a value for a transient unit and proves it is consumed and
  removed on success and also when the payload refuses, with the canary absent from the journal.

## Exit criterion

The specification's exit criterion is a walk on a fresh Ubuntu 26.04 host: WordPress on
MariaDB, and Laravel on MariaDB and on PostgreSQL, created over HTTPS from a local ACME server;
deployed (Laravel twice, once with a migration); rolled back; reconfigured with a secret; one
removed; no routine SSH; secret canaries never outside their private files; a fresh controller
reconstructing everything with repeated reviews proposing nothing; and the build within the
budget.

Two clauses cannot be one run, and the record says so plainly:

- **One engine per server** is a settled decision of the specification, so a WordPress site and a
  Laravel site on MariaDB share one host, and a Laravel site on PostgreSQL needs a second host.
  The walk is therefore proven on a MariaDB lane (WordPress plus Laravel) and a PostgreSQL lane
  (Laravel), not by one scenario on one host.
- **One item is capped at 180 s.** Wordpress creation, Laravel creation, two Deploys, Roll back,
  a settings change, a removal and two fresh-controller reconstructions in one test would exceed
  that cap. The walk is covered by the scenarios above, each on a freshly prepared L1 server from
  the same pinned image.

| Clause | Evidence |
| --- | --- |
| WordPress on MariaDB created over HTTPS from a local ACME server | `WordPressCreateMariaDB` (home, login and REST over Pebble-issued HTTPS) |
| Laravel on MariaDB and on PostgreSQL created | `LaravelCreateMariaDB`, `LaravelDeployPostgreSQL` |
| Deployed twice, once with a migration | `LaravelDeployMariaDB` (first Deploy runs the migration; second Deploy with migrations off; a further Deploy prunes), with an environment save between them that rebuilds the cached configuration |
| Rolled back | `LaravelDeployMariaDB` Roll back over a retained release |
| Reconfigured with a secret | `LaravelDeployMariaDB` edits a deployed site's environment, and `LaravelCreateMariaDB` and `WordPressCreateMariaDB` edit theirs, each with its own canary |
| One site removed | `WordPressCreateMariaDB` removes the WordPress site through the reviewed change and checks every resource is gone; `SiteDatabaseMariaDB` removes a plain site while another keeps serving |
| No routine SSH | Every create, deploy, roll back, settings change and removal above is applied through the change engine by the product's own preparation and native body; the harness uses SSH only to inspect the server and push the fixture commit |
| Secret canaries never outside their private files | [Secret canaries](#secret-canaries) |
| A fresh controller reconstructs everything; repeated reviews propose nothing | `FreshControllerReconstruction`, `HttpsSite`, `DatabaseEngineMariaDB`/`PostgreSQL`, `SiteDatabaseMariaDB`/`PostgreSQL`, `WordPressCreateMariaDB`, `LaravelCreateMariaDB`, `LaravelReleaseReconstruction`; each row also asserts a repeated review proposes no changes |
| The full local build stays within ADR 0033's budget | [Build budget](#build-budget): 280 s against the 300 s target and 900 s limit. The hosted shard target is a separate budget line and is missed ([#449](https://github.com/rajandangi/barectl/issues/449)) |

## User story audit

Each row names the code and the test that carry the story, or says it is not qualified and links
the ticket that tracks the gap. Test names without a path are in the app's `test_*.py` modules;
`browser` marks a Playwright journey in the browser suite.

### Creating sites

| Story | Evidence |
| --- | --- |
| 1. PHP, WordPress and Laravel offered as platforms | `sites/test_target_pages.py`, `wordpress/test_create.py::WordPressSiteTileTests`, `sites/test_laravel_create.py`, and the three create journeys in `sites/test_target_browser.py` |
| 2. Only the fields each platform needs, default PHP preselected | `sites/test_default_preselection.py` (3 tests); the browser create journeys submit exactly the documented fields |
| 3. Never asked about the web server or the database engine | The three forms and their prepared inputs hold no server or engine field (`sites/test_target_pages.py`, `wordpress/test_create.py`, `sites/test_laravel_create.py`, browser create journeys) |
| 4. Install a missing database engine as Step 1 and continue with the same answers | The create form offers **Step 1: install MariaDB** (WordPress) or MariaDB/PostgreSQL (Laravel), queues the existing `install_database_engine` kind, and its finished run returns to the prefilled form (`sites/test_creation_steps.py`; browser `test_operator_installs_a_missing_engine_first_and_keeps_the_create_answers`) |
| 5. Install a missing PHP version first and continue | The runtime select lists catalog PHP builds as *installs first*, queues the existing `add_runtime` kind, and returns to the same answers (`sites/test_creation_steps.py`, `sites/test_target_pages.py`); the browser journey uses an installed runtime |
| 6. Confirm screen says in plain words what will be created | The review documents for all three platforms (`sites/test_target_configuration.py`, `wordpress/test_create.py::WordPressReviewTests`, `sites/test_laravel_create.py`); the shared confirm screen is [#364](https://github.com/rajandangi/barectl/issues/364) |
| 7. Land on the new site's page with its HTTPS address and the next step | Overview links the site's own address, a WordPress sign-in page, or a Laravel current release with **Deploy**, and a plain PHP site's readiness path (`sites/test_target_pages.py`, browser `test_overview_links_the_site_address_without_ssh`) |
| 8. WordPress tile disabled on PostgreSQL with the reason | `wordpress/test_create.py::test_postgresql_disables_the_tile_with_the_reason` |
| 9. Short name derived from the domain, editable under More options | `sites/test_names.py`, `wordpress/test_create.py::test_derives_the_identifier_from_the_primary_domain`, `sites/test_laravel_create.py::test_derives_the_identifier_from_the_primary_domain`, and the keyboard journey that keeps an edited identifier |

### Database as a server setting

| Story | Evidence |
| --- | --- |
| 10. Server Settings > Database shows MariaDB, PostgreSQL or none | `databases/test_engine.py::DatabaseSettingPageTests` |
| 11. Install from the Ubuntu archive in one reviewed change naming exact versions | `databases/test_engine.py::EngineReviewTests`; native `DatabaseEngineMariaDB` and `DatabaseEnginePostgreSQL` |
| 12. Secure defaults: socket only, no anonymous user, no test database, loopback PostgreSQL | Native `DatabaseEngineMariaDB` and `DatabaseEnginePostgreSQL` |
| 13. Each WordPress and Laravel site gets its own database and user as the site's Linux user over the socket | Native `SiteDatabaseMariaDB`, `SiteDatabasePostgreSQL`, `WordPressCreateMariaDB`, `LaravelCreateMariaDB` |
| 14. A plain PHP site has no database until one is added from Settings | `databases/test_site.py`; native `SiteDatabaseMariaDB` creates the site first and binds afterwards |
| 15. Site Settings > Database shows the name, user and connection | `databases/test_site.py::SiteBindingPageTests`, `databases/test_site.py::SiteBindingReviewTests` |
| 16. Open the database as the site user without a password | Native `SiteDatabaseMariaDB` and `SiteDatabasePostgreSQL` run the dump, import and queries as `s<id>` over the socket |
| 17. A partial database reports how far it got and a fresh review finishes only what is missing | ADR 0013's statements; `databases/test_site.py::SiteBindingReviewTests`; native `SiteDatabaseMariaDB`/`PostgreSQL` partial test |
| 18. The engine is shown as used by N sites and its removal is refused while any site uses it | **Partly qualified.** Removal is refused and names the databases (`databases/test_engine.py::RemovalReviewTests`, native engine scenarios), but the panel does not show a count, because passive discovery reads no database catalog and a page may not open SSH |
| 19. A second controller reconstructs databases, users and bindings | Native `SiteDatabaseMariaDB`/`PostgreSQL` fresh-review tests; a full collection keeps reading only the engine package and units |

### HTTPS

| Story | Evidence |
| --- | --- |
| 20. Every new site served over HTTPS with a certificate Caddy issues and renews | Native `HttpsSite`; `WordPressCreateMariaDB` over Pebble |
| 21. The review checks DNS from the server and warns without refusing | `sites/test_target_configuration.py::DnsWarningTests` (4 tests) and the create review's acknowledgement |
| 22. Serve a site over HTTP only from More options | Browser `test_operator_prepares_the_real_registered_site_change_without_ssh`; native `HttpsSite` second site |
| 23. Turn HTTPS on for an HTTP-only site from its settings | One reviewed Shared change (`sites/domains_change.py`), its review and refusals (`sites/test_domains.py`), the Settings section and prepare request, and the browser journey. Native `HttpsSite` adds an alias over HTTP; the HTTPS transition itself is covered by the fast review and renderer tests because the lane’s DNS fixture resolves only the fixture domain for ACME |
| 24. The site page shows the certificate state read from the server | Issued with issuer and expiry natively (`HttpsSite`); HTTP-only natively; the waiting, failing and renewal-due wording is `discovery/test_presentation.py::test_the_certificate_state_is_worded_from_server_evidence`. The native probe's waiting and failing derivations have no fixture (see [Not qualified](#not-qualified)) |
| 25. HTTP redirects to HTTPS while challenge requests keep working | Native `HttpsSite` (308 redirect; the issued certificate itself proves the challenge path answered) |
| 26. Add and remove alias domains, with WordPress and Laravel aliases redirecting to the primary | The same change adds and removes names; WordPress and Laravel files carry an alias redirect to the primary (`sites/test_target_configuration.py`, `sites/test_domains.py`), and native `HttpsSite` proves a plain PHP alias serves directly |
| 27. Optional certificate contact email as a server setting | Implemented after this record: one Shared change (`bootstrap/certificate_email.py`) with its review and renderer, the Server Settings field and prepare request (`bootstrap/test_certificate_email.py`), and native `HttpsSite` sets and clears the address, proves discovery reads the rendered file and proves Caddy reissues with and without it. A full Phase B qualification run at the revision that ships it records it ([#444](https://github.com/rajandangi/barectl/issues/444)) |
| 28. Public listeners limited to SSH, 80/tcp, 443/tcp and 443/udp | Native `HttpsSite` reads the listening set; foundation verification enforces it |
| 29. Unknown host names answer 404 on HTTP and are refused on HTTPS | Native `HttpsSite` first and third tests |

### WordPress

| Story | Evidence |
| --- | --- |
| 30. Create with domain, title, administrator name, email and password | Browser `test_operator_prepares_the_wordpress_site_change_in_five_fields`; `wordpress/test_create.py` |
| 31. A Generate button makes a strong password in the browser and shows it once | **Partly qualified.** The control and `frontend/secret-generate.ts` exist and the page offers it (`wordpress/test_actions.py`), but no automated test exercises the generated value |
| 32. The password reaches the server only through the confidential channel and is never stored readable | `wordpress/test_actions.py::WordPressSecretChannelTests`; native `WordPressCreateMariaDB` canary; `operations/test_confidential.py` |
| 33. WordPress installed from a pinned release whose checksum Barectl ships | `wordpress/test_convention.py::CoreVersionTests`, the create review's archive size and SHA-256, and the native install from the mirror |
| 34. WordPress, WP-CLI, plugins and themes run as the site user, never root | Native `WordPressCreateMariaDB` reads the ownership and modes of the site and its configuration |
| 35. Salts generated on the server in a private file outside the public directory | Native `WordPressCreateMariaDB`: private `wp-config.php` is 0600, holds the salts, and neither the salts nor the canary reach the controller |
| 36. Installation verified by fetching the HTTPS home and login pages | Native `WordPressCreateMariaDB` |
| 37. The site is gated from visitors until installation finishes | The staged body publishes the maintenance form until verification; discovery recognizes the gate as partly applied (`wordpress/test_actions.py::test_a_gated_or_partly_applied_install_is_refused`). No native run interrupts the install (see [Not qualified](#not-qualified)) |
| 38. An interrupted installation is partly applied and a fresh review finishes only what is missing | **Not qualified as proven.** `wordpress/create.py` implements the gated and installed cases and never reinstalls into existing tables, but no test drives that review (see [Not qualified](#not-qualified)) |
| 39. Reset the administrator password through the same channel | Native `WordPressCreateMariaDB` second test (new password signs in, old does not); `wordpress/test_actions.py`; browser reset journey |
| 40. Verify core files against the official checksums | Native `WordPressCreateMariaDB` second test (match, mismatch, unavailable, match); `wordpress/test_actions.py` |
| 41. WordPress keeps updating itself as the site user; Barectl reports the version without running WordPress | **Partly qualified.** The version is reported from native files without PHP (native `WordPressCreateMariaDB`); self-updates as the site user are implemented but not proven (see [Not qualified](#not-qualified)) |
| 42. Pretty permalinks work and `wp-config.php`, dotfiles and PHP under uploads stay denied | Native `WordPressCreateMariaDB` requests `/wp-json/` and each denied path; `sites/test_target_configuration.py` and `sites/test_target_publication.py` |

### Laravel

| Story | Evidence |
| --- | --- |
| 43. Create with domain, repository and branch, default `main` | Browser Laravel journey; `sites/test_laravel_create.py`; native `LaravelCreateMariaDB` |
| 44. Public HTTPS repositories need no credentials | `laravel/test_configuration.py::RepositoryLocatorTests`; the fixture HTTPS repository in `LaravelDeployMariaDB` |
| 45. A read-only deploy key generated on the server, showing only its public half | Native `LaravelCreateMariaDB` reads the public half and checks the private half is 0600; `laravel/test_configuration.py::FingerprintTests` |
| 46. The repository host key trusted only by an exactly pasted fingerprint | Native `LaravelCreateMariaDB` wrong-fingerprint refusal; `laravel/test_configuration.py::FingerprintTests` |
| 47. The site has its database, a private `.env` with production defaults and one `APP_KEY` | Native `LaravelCreateMariaDB`; `laravel/test_configuration.py::EnvironmentTests` |
| 48. The new site's completion offers Deploy | Overview shows the current release and a Deploy form that leads to the existing review; Deployments keeps the full list (`sites/test_target_pages.py`, browser Overview journey) |
| 49. Deploy's review resolves the branch to an exact commit and shows it | `laravel/test_change.py::DeployReviewTests`; native `LaravelDeployMariaDB` deploys exactly the pushed commit |
| 50. A moved branch deploys the reviewed commit or refuses | The apply fetches the reviewed commit and refuses when it is unavailable (`laravel/bodies`); native `LaravelDeployMariaDB` |
| 51. Dependencies installed from the committed lock with the site's own Composer and PHP, with a platform check | Native `LaravelDeployMariaDB` (no dev packages, no `.git` under `vendor`, `--no-plugins --no-scripts`); `laravel/test_change.py` |
| 52. A `composer.json` requiring a PHP version the site does not run is refused, naming it | `laravel/test_change.py::DeployReviewTests`; native `LaravelReleaseReconstruction` |
| 53. Pending migrations run once before the new code serves behind a maintenance page, and no gate when none are pending | Native `LaravelDeployMariaDB` (migration recorded once behind the gate; second Deploy with migrations off) |
| 54. The confirm screen acknowledges that migrations may change data, that roll back does not reverse them and that no backup exists | `laravel/test_change.py::AcknowledgementTests`; native `LaravelDeployOutcomes` forged apply |
| 55. A per-site switch turns migrations off, reporting them unrun | `sites/test_deploy_pages.py`; native `LaravelDeployMariaDB` (the run's journal names the pending migration and runs none) |
| 56. The release is switched in only after the caches are built and `/up` answers 200, keeping the gate if it does not | Native `LaravelDeployMariaDB` (readiness over the socket and over HTTPS after the master's graceful reload) and `LaravelDeployBootFailure` (the gate stays up and `laravel_readiness` is reported) |
| 57. A failed or interrupted Deploy says which release is serving, whether the gate is up, and the safe next action | Native `LaravelDeployOutcomes` and `LaravelDeployBootFailure`; `Check what happened` reads the original unit |
| 58. A failed migration keeps the gate and the data, never retried or rolled back | Native `LaravelDeployOutcomes` (one attempt, gate 503, old release serving, migration unrecorded) |
| 59. Roll back to a retained release with a review that says nothing is reversed | `laravel/test_change.py::RollbackReviewTests`; native `LaravelDeployMariaDB` |
| 60. Each deploy keeps the newest five releases and names the removed ones | `laravel/test_change.py::DeployReviewTests` (prune set); native `LaravelDeployMariaDB` final Deploy |
| 61. A Deploy is refused before any change when the disk lacks the space the review states | `laravel/test_change.py::test_a_deploy_is_refused_before_any_change_when_the_disk_lacks_space` |
| 62. Each release's commit, time and state listed under Settings > Deployments | `sites/test_deploy_pages.py` checks the release, commit, created time, status and serving columns; native `LaravelReleaseReconstruction` |
| 63. `.env`, storage and logs live outside releases and are shared | Native `LaravelDeployMariaDB` follows the shared links and checks the release modes |
| 64. Laravel's logs rotate daily and keep 14 days | `laravel/test_configuration.py::EnvironmentTests` and the create review's `.env`; native `LaravelCreateMariaDB` |
| 65. A CI-created release in the same layout is discovered and listed | Native `LaravelReleaseReconstruction` |
| 66. Deploy is available to a Site operator | `laravel/test_change.py::DeployReviewTests` (Site scope); `sites/test_deploy_pages.py::test_a_viewer_cannot_prepare_a_deploy` |
| 67. Passive discovery never runs PHP, Composer, Git hooks or Artisan | Native `LaravelDeployMariaDB` canary wrappers; the release reader in `laravel/observation.py` reads files only |

### Settings and secrets

| Story | Evidence |
| --- | --- |
| 68. Environment settings list `.env` keys, showing known non-secret values and masking the rest | `laravel/test_settings.py`, `sites/test_settings_pages.py`; native `LaravelCreateMariaDB` |
| 69. Add, change and remove keys, saving only what changed | `laravel/test_settings.py::EnvironmentReviewTests` and `EnvironmentBodyTests`; native environment edit |
| 70. WordPress extra named constants in its private configuration | `wordpress/test_settings.py`; native `WordPressCreateMariaDB` third test |
| 71. A typed secret is unreadable after a worker restart or 10 minutes and cleared once sent | `operations/test_confidential.py`, `operations/test_secret_channel.py`; native `ConfidentialChannelLifecycle` |
| 72. Secrets never in arguments, unit properties, the journal, run records, events, pages or responses, with known values scrubbed from stored output | Fast canaries in `operations/test_secret_channel.py`, `wordpress/test_actions.py`, `laravel/test_settings.py`, `wordpress/test_settings.py`; native canaries in `ConfidentialChannelLifecycle`, `WordPressCreateMariaDB`, `LaravelCreateMariaDB`, `LaravelDeployMariaDB` |
| 73. Saving Laravel settings rebuilds the cached configuration | Native `LaravelDeployMariaDB`: after a Deploy built the cache, an environment save rewrites the private `.env` and the body's `config` stage runs, with the site still answering 200; `laravel/bodies/settings.py` reports partly applied if the rebuild fails |
| 74. Editing secrets needs "manage secrets" as well as site changes | `wordpress/test_actions.py`, `laravel/test_settings.py`, `operations` permission tests; the browser permission journeys |
| 75. Secrets are write-only in the dashboard | `sites/test_settings_pages.py`, `wordpress/test_settings.py`, `laravel/test_settings.py`; a full collection stores key names and digests only |

### Site PHP settings, removal and updates

| Story | Evidence |
| --- | --- |
| 76. Change memory limit, upload size, worker count and timeouts within the bounds | `sites/test_pool_settings.py` (15 tests); native `HttpSiteNativeBehavior` sets four children, switches PHP both ways and reconstructs the values |
| 77. Remove a site by typing its domain, with a review listing everything deleted | `sites/test_remove.py` (16 tests, including the forged apply and partial removal); native `SiteDatabaseMariaDB` removes a plain site while another keeps serving, and `WordPressCreateMariaDB` removes the WordPress site with its file, directory, configs, accounts, database, principal and certificate |
| 78. Remove a PHP version that no site and no server default uses | `runtimes/test_remove.py`; native `CatalogRuntimeUpdate` |
| 79. "Update available" for PHP, Caddy and HAProxy with the affected sites named | `runtimes/test_update.py`; native `CatalogRuntimeUpdate` |
| 80. A PHP update applied through the request-preserving switch | Native `CatalogRuntimeUpdate` measures zero refused requests through Caddy during the update |
| 81. The previous build kept until the update is verified, older generations collected afterwards | Native `CatalogRuntimeUpdate` (previous generation kept, revert works) and `CatalogRuntimeUpdateFailure` |

### Recovery, reconstruction and permissions

| Story | Evidence |
| --- | --- |
| 82. Every Phase B change recovers through #179 Journey 7 | **Partly qualified.** The engine's Check outcome is one path and is proven for Deploy failures; the browser Journey 7 is [#370](https://github.com/rajandangi/barectl/issues/370), still open, and no Phase B change has a browser recovery journey |
| 83. A fresh controller reconstructs certificates, engines, databases and users, applications, releases and `current`, settings keys and deploy keys | Native `FreshControllerReconstruction`, `HttpsSite`, `DatabaseEngineMariaDB`/`PostgreSQL`, `SiteDatabaseMariaDB`/`PostgreSQL`, `WordPressCreateMariaDB`, `LaravelCreateMariaDB`, `LaravelReleaseReconstruction` |
| 84. A hand-made resource that follows the convention is managed like Barectl's, and anything else is reported once | `sites/test_target_discovery.py::RecordedJudgeByShapeTests`, `sites/test_target_configuration.py`, native `JudgeByShape`, `HttpSiteReconstruction`, `LaravelReleaseReconstruction` |
| 85. A viewer sees sites, certificates, deployments and settings keys without changing them | `sites/test_settings_pages.py::test_a_viewer_reads_the_certificate_releases_and_settings_keys` (certificate, releases and key names, with SSH patched out); `sites/test_target_pages.py` viewer case; the viewer refusals in `sites/test_deploy_pages.py`, `sites/test_pool_settings.py`, `sites/test_remove.py` and `databases/*` |
| 86. Every new journey works with a keyboard, a screen reader and a 320-pixel screen | **Qualified.** Browser journeys cover the three create forms, the WordPress password reset, the Domains and HTTPS change, Deploy with its migration acknowledgement, Roll back from the release list, adding an environment key and a WordPress constant, PHP settings, the database engine install, removal with the typed domain, and the HTTPS and certificate states. The journeys that prepare a change drive the keyboard through focused controls; every journey checks its heading and asserts no horizontal scrolling at 320 pixels (`sites/test_target_browser.py`) |
| 87. Opening any page makes no SSH connection | Page tests patch `discovery.ssh.connect` to fail (`sites/test_target_pages.py`, `sites/test_deploy_pages.py`, `sites/test_settings_pages.py`, `sites/test_remove.py`, `databases/test_site.py`, `wordpress/test_actions.py`), and the browser journeys do the same |

### Maintainers

| Story | Evidence |
| --- | --- |
| 88. WordPress releases, Composer dist archives, Ubuntu database packages and the ACME server served from byte-exact local mirrors | `disposable/test_mirror.py`, `MirrorNixSignature`, `NativeFixtures`, `AptDailyActive` and the harness's egress refusal |
| 89. One native lifecycle scenario per application platform | `WordPressCreateMariaDB`; `LaravelCreateMariaDB` plus `LaravelDeployMariaDB`; `LaravelDeployPostgreSQL` |
| 90. A secret canary test that fails if a canary appears anywhere outside its private file | Fast `operations/test_secret_channel.py` and the per-kind canary tests; native `WordPressCreateMariaDB`, `LaravelCreateMariaDB`, `ConfidentialChannelLifecycle` |

### Added for Phases C and D

| Story | Evidence |
| --- | --- |
| 91. A site's own database user can dump and re-import its own database and nothing else | Native `SiteDatabaseMariaDB` and `SiteDatabasePostgreSQL` (dump, drop and import a view, trigger, routine and event/function; another database refused) |
| 92. A plain PHP site is confirmed to serve, using a readiness path defaulting to `/` | `sites/test_target_configuration.py::ReadinessReviewTests`; native `HttpSiteNativeBehavior` and `HttpsSite` |
| 93. Deploy checks `/up` on the new release while the gate still answers visitors, and opens the site only after it passes | Native `LaravelDeployMariaDB` and `LaravelDeployBootFailure` |

## Secret canaries

The fast layer drives every secret-bearing kind with canary values and fails if a canary appears
in a recorded command, a unit property, a journal line, a controller row, an event or a rendered
response (`operations/test_secret_channel.py`, with the shared harness in
`operations/secret_testing.py`; per-kind tests in `wordpress/test_actions.py`,
`wordpress/test_settings.py` and `laravel/test_settings.py`). The transcript reader refuses to
record a command that names a site's private directory or the confidential staging directory and
fails a transcript that holds the recording's seed secret (`discovery/test_recorded.py`).

Natively, four scenarios scan real servers for their canaries:

| Scenario | What it scans |
| --- | --- |
| `ConfidentialChannelLifecycle` | the staged file is consumed and removed on success and on refusal; the canary is absent from the unit's journal |
| `WordPressCreateMariaDB` | the administrator password and an extra constant: `/var/www`, the site's logs, `/etc/caddy` and the journal; the private file is 0600 |
| `LaravelCreateMariaDB` | a `MAIL_PASSWORD` value: the release tree, the site's logs and `/etc/caddy`; the private `.env` is 0600 |
| `LaravelDeployMariaDB` | canary wrappers around PHP, Composer, Git and Artisan prove a passive discovery runs no application code |

All four passed in the local build.

## Qualification items

The specification's open native qualification items, decided but not blockers:

| Item | Result |
| --- | --- |
| MariaDB `unix_socket` through PHP's `mysqli` as the site user under Nix PHP | Proven by `SiteDatabaseMariaDB`: the binding is ready only when the site's own PHP master connects through its driver as the site user and can read only its own database. `SiteDatabasePostgreSQL` does the same through `pdo_pgsql` |
| Memory and disk of MariaDB or PostgreSQL plus three sites on a 1 GiB limit | **Not qualified.** No Phase B scenario measures an engine plus three sites under a 1 GiB limit; `RuntimeSmallHost` measures the foundation and two runtimes only |
| Code pickup after a `current` switch without refused requests | **Partly qualified.** Deploy and Roll back reload the site's own PHP-FPM master gracefully after the switch, so readiness observes the switched release and in-flight requests finish under `process_control_timeout`; three consecutive native runs of all four Deploy scenarios pass. A Deploy without the maintenance gate is not implemented, so its no-refused-requests property is unproven and every deploy that switches code still uses the window |
| UMask behaviour for WordPress self-updates | **Not qualified.** Self-updates as the site user are implemented but not exercised on a server |
| Whether ZeroSSL fallback engages without a contact email | **Not qualified.** The optional setting now exists ([#444](https://github.com/rajandangi/barectl/issues/444)), and native `HttpsSite` proves issuance with and without an address against the lane's ACME server; Caddy's public issuer fallback itself is unmodified and unexercised |

Defects the scenarios found and this revision fixes: see the previous record's list (pruning,
preflight ordering, fetched-release branch loss, the gate dropping a site's HTTPS listener, the
missing shared Laravel storage skeleton, and Composer reaching packagist during a build). The
Phase B slices also found and fixed, before this record: the site master's idle timeout, the
pool inventory sizing and the bounded journal cap for tuned pools ([#384](https://github.com/rajandangi/barectl/issues/384)),
and a preflight refusal for a broken catalog build ([#386](https://github.com/rajandangi/barectl/issues/386)).

## Memory and disk

No minimum host size is claimed, and no Phase B measurement replaces the Phase A figures. The
[Phase A record](phase-a-qualification.md#memory-and-disk) holds the foundation, three plain PHP
sites and the 1 GiB figures; the database engine and application scenarios above were not
measured for memory or disk.

## Not qualified

- **The database engine's site count.** The panel does not show how many sites use the engine,
  because passive discovery reads no catalog and pages make no SSH call; removal still refuses
  and names the databases (story 18).
- **Certificate states waiting, failing and renewal due on a real server.** The wording is
  covered by a fast test; only Issued and HTTP-only are proven natively (story 24).
- **WordPress interrupted install.** The review that finishes a gated, partly installed site is
  implemented but has no test (story 38); the gate's recognition is covered.
- **The Generate button's value.** The control and its script exist; no automated test checks the
  generated password (story 31).
- **WordPress self-updates as the site user.** Not exercised (story 41).
- **Browser recovery journeys.** Phase B changes still have no browser journey through #179
  Journey 7, so story 82 stays partly qualified ([#370](https://github.com/rajandangi/barectl/issues/370)).
  Creation, review and settings journeys are covered (story 86).
- **Composer advisory blocking.** The offline lane reaches no host but the repository, so the
  build passes `--no-blocking`; a real host therefore also skips Composer's advisory blocking.
- **Assertion depth.** `--prefer-dist` is asserted by the absence of dev packages and of `.git`
  directories under `vendor`, not by reading the build's argv. The readiness ordering is asserted
  by the body's stage order and the two failure fixtures, not by a live interleaving. Pruning is
  proven with synthesised retained releases as well as natively.
- **One engine plus three sites on 1 GiB, and code pickup without refused requests.** See
  [Qualification items](#qualification-items).
- **Hosted shard time.** Three hosted `Native` shards exceed the 300 s target for one shard
  (360 s to 499 s of scenario time at `e9d8c44`; shard 4 met it at 286 s) while all stay inside
  the 900 s limit ([#449](https://github.com/rajandangi/barectl/issues/449)). The local full
  build is inside its target.
- **No real VM and no real DNS.** Every server is the pinned container image; the lane's resolver
  answers for the fixture names, so DNS warnings are proven by unit tests and the fixture, not by
  a public name. No certificate is issued by a public authority.

## Hosted runs

`Checks` run [40066132997](https://github.com/rajandangi/barectl/actions/runs/40066132997) at
`9f42ba8`, all required jobs passed:

| Job | Time | Result |
| --- | --- | --- |
| `check` | 1 m 41 s | Passed |
| `browser` | 1 m 48 s | Passed |
| `frontend` | 20 s | Passed |
| `dependency-audit` | 18 s | Passed |

`Native` run [40066133079](https://github.com/rajandangi/barectl/actions/runs/40066133079),
amd64, four shards of two lanes, all passed:

| Shard | Job wall time | Reported by the runner |
| --- | --- | --- |
| 1 of 4 | 11 m 9 s | Fast validators 3 of 3 in 104 s; egress control refused as intended; lifecycle scenarios 17 of 17 in 515 s |
| 2 of 4 | 7 m 12 s | 16 of 16 in 381 s |
| 3 of 4 | 6 m 57 s | 16 of 16 in 389 s |
| 4 of 4 | 6 m 31 s | 16 of 16 in 361 s |
| Required `native` check | 3 s | Passed |

The shards restored the keyed L1 snapshot (`native-l1-Linux-X64-l1-6dcac7a6c2d8`), so the
reported scenario times contain no S1 preparation. Every shard stays inside the 900 s hard
limit and no item exceeds 180 s, but all four exceed the
[test time budget](quality.md#test-time-budget)'s 300 s target for one hosted shard; the longest
is 515 s on shard 1, which also carries the validators and the egress control. The gap is
tracked as [#449](https://github.com/rajandangi/barectl/issues/449); the local full build
(241 s) is inside its own target.

The previous run on this branch (`757baaf`, run
[40065117754](https://github.com/rajandangi/barectl/actions/runs/40065117754)) missed the L1
snapshot on every shard, because the fix changes the Laravel body that the engine payload and
the L1 key hash; it prepared L1 through S1 and measured 407 s to 512 s, still inside the limit.
Earlier runs on the qualification branch failed `dependency-audit` on advisories disclosed after
the branch point: `filelock` 4.0.3 (three CVEs) and then `fast-uri` 3.1.8 and `zod` 4.6.5; both
lock updates are in the main history. While
[#450](https://github.com/rajandangi/barectl/issues/450) was open, shard 1 failed
`LaravelDeployBootFailure` with `succeeded/: expected partial/laravel_readiness`; this run
proves it unquarantined.
