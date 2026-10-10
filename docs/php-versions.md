# Per-site PHP versions

Accepted implementation specification [#236](https://github.com/rajandangi/barectl/issues/236), following the source decision in [#203](https://github.com/rajandangi/barectl/issues/203) and [ADR 0016](adr/0016-limit-third-party-php-supply.md). The implementation is delivered on both supported Ubuntu releases and architectures; [qualification](php-versions-qualification.md) records the evidence and its limits. Unified-source combinations outside the recorded qualification remain unavailable to new plans. Existing qualified Ubuntu-default workflows remain available.

The [competitor and package-source analysis](php-versions-competitor-analysis.md) compares this design with hosted panels, native server panels and container platforms. It records why the current native approach fits Barectl and which lifecycle capabilities need separate specifications.

## Outcome and boundaries

An operator can explicitly choose the approved unified PHP source on a fresh supported Ubuntu server, install a reviewed PHP branch, and create a convention site selecting that installed branch. A second controller reconstructs that choice from native configuration. Installing another branch, finishing a partial site, giving it database drivers or installing HTTPS preserves every existing site's selected branch and native bytes unless the reviewed action specifically adds the missing resource or TLS route.

The eligible initial branches are 8.3, 8.4 and 8.5 on Ubuntu 26.04, independently qualified on amd64 and arm64. All admitted PHP on one server follows one supply choice. Ubuntu supply retains the release's default branch. The unified source permits individually qualified eligible branches. Distribution identity and `Release.php` continue to describe Ubuntu's default; selected PHP is separate.

Existing Ubuntu PHP, legacy-PPA PHP and mixed-source PHP are not converted. Package upgrades, removals, repairs, downgrades, switching an existing site's PHP branch, application deployment, extra extensions, arbitrary repositories and unattended PHP patching are outside this specification. Existing released site revisions remain recognizable with their original bytes. No database rebuild or destructive schema squash is authorized.

## Observable requirements

1. Source setup is its own permission-protected bootstrap plan, read-only during preparation and explicitly reviewed before apply. It lists the source URL, own-release suite, signing fingerprint, key/source/preference files, authentication and publisher-trust effects. Matching native setup made by an administrator is accepted; differing state is refused with the resource named. A finish plan creates only missing exact setup resources.
2. Source setup requires the distribution's native GnuPG `gpg`, APT helper and CA certificates. Missing tools refuse preparation; an administrator supplies these prerequisites with ordinary Ubuntu tools. Setup never refreshes metadata or installs PHP implicitly. After setup, the existing explicit metadata-refresh workflow authenticates all configured sources and invalidates older package plans. Failed or incomplete updates refuse subsequent installation.
3. A server with existing PHP from another supplier refuses unified-source setup or installation before replacement is possible. No request chooses a source solely from a prior controller's records. Fresh privileged review identifies it from current source, trust, priority and package evidence.
4. The admitted source, key, pins and binary names are exactly ADR 0016's. Native APT uses the dedicated key path and full fingerprint filter, with source-specific `Check-Valid-Until: yes` and `Valid-Until-Max: 604800`. All other packages use the currently admitted Ubuntu sources. A third-party offer for a non-PHP transaction dependency refuses the plan even if APT would not select it. Competing third-party PHP offers and duplicate exact-version source instances refuse too. When the publisher has not published newer metadata within seven days, APT refuses to refresh the source and the source's indexes stop being current: the PHP plan's refusal names the metadata's publication time and when it stopped being current, and a failed refresh names an expired Release file as the publisher's delay. The recovery is to wait for a newer publication, then refresh and prepare again. The limit is not relaxed.
5. An installation plan names supply, branch, exact root versions, full missing dependency closure, FPM/CLI binaries, service effects, configuration directories and exposure. It preserves native automatic markings. Another eligible installed branch is not a blanket refusal; incompatible packages or layouts remain individually blocked.
6. Immutable package requests, plans and apply audit retain branch and supply through queueing, dispatch, reconciliation and server/plan deletion. Apply reconstructs exactly the reviewed profile without deriving a new selection from current server state. Missing selection on historical records means the legacy release-default profile, not a current-source guess.
7. Each branch's FPM service, default pool, native socket, packaged configuration and CLI version are inspected and qualified separately. Source PHP 8.5's OPcache packaging must come from observed packages, not assumptions from Ubuntu's PHP profile. Drivers are pinned to the installed selected branch's common-package version.
8. New sites explicitly choose an installed eligible branch. The form shows branches from observed evidence and their collection time. Unavailable, unqualified, expired-support or unreadable prerequisites produce a refused review or form error, never a silently selected default. Server records do not become live health claims.
9. The next native convention revision places `/run/php/s<identifier>-php<branch>.sock` in both Nginx `fastcgi_pass` and FPM `listen`, and the pool in `/etc/php/<branch>/fpm/pool.d/`. These are operative service settings. They preserve selection when a partial site's pool is absent and require no manifest, ownership marker or server tracking file.
10. The renderer recognizes complete exact forms for HTTP, challenge, HTTPS and redirect stages of the selected-branch revision. Existing revisions retain `/run/php/s<identifier>.sock` and the release-default branch. TLS replacement preserves the recognized revision, selected branch and socket instead of upgrading a legacy site implicitly.
11. Discovery lists only eligible branch pool directories and exact profile packages. It reconstructs a managed or partial site's branch from its supported native file form. A duplicate identifier or conflicting pool across branches refuses dependent management. Unreadable or ambiguous selection remains unreadable or unsupported; it never falls back to a snapshot or missing-pool default.
12. A Finish request retains the observed revision and branch and creates only missing matching resources. Any request/native mismatch or changed existing resource refuses it. A fresh controller can finish a partial selected-branch site without the original request record.
13. Driver preparation selects the site's branch. The review, installed driver check, syntax check, FPM reload and listening-socket verification use that branch. Binding plans and native payloads retain their already recorded `php_version`; they never substitute `Release.php`.
14. Challenge preparation, certificate readiness and HTTPS/redirect activation inspect and render the selected branch. Database and TLS permissions remain separate from bootstrap and site permissions. Accounts lacking plan permission may see observed branch information but cannot prepare or apply a related action.
15. Support expiry and release lag follow ADR 0016. Existing sites continue to be reported and served; Barectl refuses new changes selecting an unsupported branch and never stops or switches it automatically.
16. Operations retain the worker, one pyinfra SSH connection, fixed transient-systemd payload, shared native lock, boot/deadline fence, exact guard and reconciliation contract. An independent controller can inspect results without another device's audit. Mixed old/new controllers must be stopped or upgraded before managing unified-source servers; no remote controller registry is introduced.

## Source authentication and archive acquisition

The current package evidence identifies configured indexes and package offers, but does not prove the approved primary signing identity or effective per-package priorities. Extend privileged evidence at the existing `bootstrap.inspection` boundary. Collect native source entries and dedicated key identity, signature validity, exact authenticated index instances and effective selection. Refuse unknown or duplicate forms rather than parsing arbitrary repository layouts. Never classify the approved source as Ubuntu by changing `Release.owns()`.

A normal APT cache entry of the expected size can bypass acquisition hashing in both supported APT versions. The existing debconf hook executes package configuration scripts before the appended exact-transaction guard. Accordingly, the unified-source profile uses a fresh root-controlled native APT archive cache for each accepted run, native `Dir::Cache::Archives` and SHA-256 acquisition, then the current protocol-version-3 transaction guard adapted to the admitted cache path. It does not copy shared cached archives, clear the global cache, run another downloader, move the guard before native hooks or implement cryptography.

The cache must start empty, remain within validated root-controlled ancestry, permit `_apt` sandboxed downloads, and use ordinary APT cache locking. Its lifecycle is bounded to the native run; systemd-owned runtime state or another established native lifecycle is preferred to a custom janitor. Qualification must prove success, failed download, refusal, SSH loss, termination and timeout cleanup, and explain any recoverable native cache residue. No application approval or inventory is written there. Keep every payload within ADR 0006's 16 KiB bound; refuse oversize work rather than splitting it.

APT's own authenticated acquisition must reject corrupted newly fetched data before executable package hooks. Exact-version source uniqueness and index/configuration drift refusal bind acquisition to the approved source. A hash check only inside the current appended guard is insufficient. Record native evidence for the hook order and poisoned shared-cache case before enabling the exception.

## Module ownership and test seams

| Slice | Existing owning seam | Behavioral evidence |
| --- | --- | --- |
| Source setup and admission | `bootstrap.inspection`, `evidence`, `review`, native execution | A reviewed setup/installation is admitted or refused from current native source/key/pin evidence. |
| Per-branch profiles and acquisition | `bootstrap.profiles`, requests/plans/audit, `apply`, `native` | Correct immutable branch applies once, authenticates downloads before hooks and changes only reviewed packages. |
| Native site selection | `sites.convention`, inspection/admission, request/service/native; `discovery.observations` | A hand-made exact site is reconstructed; a missing-pool site retains its branch and finishes from a fresh controller. |
| Drivers, bindings and TLS | `databases.drivers`, admission/plans/native; TLS readiness/activation | Drivers and TLS preserve the observed branch and legacy native bytes. |
| Workflow and qualification | Forms/views/templates, browser journey and disposable native suites | Operator performs the complete journey with permissions, review and two-controller reconstruction. |

Use the existing fake-server collection, worker preparation/apply, rendered pages and disposable native seams. Work in small failing-test/implementation cycles. Do not test private parser branches or duplicate assertions of constants. Frontend work follows the official versioned [HTMX 4 guidance](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-guidance.md), repository USWDS lifecycle and Django 6.1 documentation. Keep runtime selection out of JavaScript state; Django validates the submitted choice and fresh native review admits it.

Existing request/audit schemas need additive, preserving migrations. First retain readers for historical release-default records and released native revisions; then add explicit selection writers. Do not rewrite native site files, infer migrations from cached observations or remove old readers in this milestone. The rollback path disables new choice preparation while retaining readers and reconciliation for accepted runs and new native sites; it cannot mean deleting installed PHP or downgrading to a controller unable to recognize those sites.

## Qualification and delivery gates

- Source matrix on Ubuntu 26.04 and both architectures: approved primary key, expiry/revocation failure, wrong/global/extra-key trust, key and preference drift, target-release priority interference, own-suite missing, missing package and incomplete update. Use the existing signed-repository fixture for deterministic faults, plus real approved-source installation for each advertised branch.
- Acquisition matrix: wrong same-size archive in the shared cache, freshly corrupted archive, ambiguous equal-version offers, failed/partial download, ordinary APT lock contention, exact-transaction refusal, dependency markings, debconf/hook order, sandbox ownership, cleanup and payload limit. No package scripts may run from an unverified archive.
- Runtime matrix: coinstalled eligible branches, their qualified defaults and syntax, drivers per branch, HTTP/challenge/HTTPS/redirect forms, Finish with absent pool, edited resources, duplicate pools, legacy exact bytes and unavailable branch evidence.
- Two independent controller databases: create, discover, conflict refusal, controller loss, native completion/reconciliation and selected-branch reconstruction without importing history.
- Production and development-browser journey: source setup, explicit refresh, install two branches, create separate sites, drivers/binding, HTTPS, Finish and second-controller discovery. Include plan/audit permissions and inaccessible evidence.
- Run all repository gates and affected native modules locally before pushing; then obtain full native statuses on Ubuntu 26.04 for the exact published revision. Record tested branch/release/architecture combinations and material limits. A metadata preflight is not installation qualification.

[#221](https://github.com/rajandangi/barectl/issues/221) is closed following the verified non-applicability assessment. The required npm dependency audit applies [the owner-accepted advisory ignore](braces-advisory-review.md#required-audit-policy) while retaining the complete report and low-severity threshold for other findings. A local policy pass does not replace passing checks on the published revision. Delivery still requires those checks and the qualification evidence; no third-party combination is enabled by this assessment alone.

## Implementation sequence

| Ticket | Required result | Dependencies |
| --- | --- | --- |
| [#237](https://github.com/rajandangi/barectl/issues/237) | Reviewed source setup and source/key/pin admission | Accepted ADR 0016 |
| [#238](https://github.com/rajandangi/barectl/issues/238) | Explicit PHP branch installation with authenticated acquisition | #237 |
| [#239](https://github.com/rajandangi/barectl/issues/239) | Native site selection and fresh-controller reconstruction | Accepted native convention |
| [#240](https://github.com/rajandangi/barectl/issues/240) | Selected-branch drivers, bindings and TLS | #238, #239 |
| [#241](https://github.com/rajandangi/barectl/issues/241) | Operator journey and delivery qualification | #237, #238, #239, #240, #221 |

The [source metadata preflight](php-source-preflight.md) records both-release arm64 authentication, priority, expiry and package simulations. It does not qualify archive acquisition, installation, runtime behavior or amd64.

The GitHub specification and native issue dependencies own delivery state. Source setup/admission comes first; per-branch package profiles and authenticated acquisition build on it. Native site selection and reconstruction can be developed independently behind the unqualified-source gate. Drivers/bindings/TLS depend on package and site selection. The final workflow and qualification ticket depends on all preceding slices and #221. A ticket closes only with its acceptance evidence, not because its specification or another ticket's tests are complete.

The original convention specification [#193](https://github.com/rajandangi/barectl/issues/193) and its nine children are already closed. This specification tracks separate implementation work; it does not reopen them or claim per-site PHP is implemented by their existing qualification.

## Official sources

- [PHP packaged installation](https://www.php.net/manual/en/install.unix.debian.php) and [support dates](https://www.php.net/supported-versions.php).
- [Ubuntu third-party repository guidance](https://documentation.ubuntu.com/server/explanation/software/third-party-repository-usage/), [Resolute apt_preferences](https://manpages.ubuntu.com/manpages/resolute/man5/apt_preferences.5.html), [Resolute sources.list](https://manpages.ubuntu.com/manpages/resolute/man5/sources.list.5.html) and [Resolute apt.conf](https://manpages.ubuntu.com/manpages/resolute/man5/apt.conf.5.html).
- APT [2.8.3 acquisition source](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-pkg/acquire-item.cc) and [3.2.0 acquisition source](https://salsa.debian.org/apt-team/apt/-/blob/3.2.0/apt-pkg/acquire-item.cc), including cached-archive acceptance; native verification remains required.
- [Maintainer instructions](https://packages.sury.org/php/README.txt), [live Launchpad migration description](https://api.launchpad.net/1.0/~ondrej/+archive/ubuntu/php) and [pyinfra APT operations](https://docs.pyinfra.com/en/3.x/operations/apt.html).

The upstream documents explain packaging and acquisition behavior. Source choice, allowed package names, support cutoff, native convention and delivery gates are Barectl decisions.
