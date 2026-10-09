# Site creation

**Status: product design; implementation and qualification pending.** Tracked in [#320](https://github.com/rajandangi/barectl/issues/320). This document records the requested replacement for the normal hosting setup journey. It does not claim that a fresh server can already create WordPress this way, that additional WordPress/PHP combinations are qualified, or that Node provisioning exists. Current implemented behavior remains documented in [bootstrap](bootstrap.md), [sites](sites.md), [PHP versions](php-versions.md), [WordPress](wordpress.md) and [TLS](tls.md). The [competitor comparison](site-creation-competitor-analysis.md) records the official sources behind the workflow choices.

## Operator journey

1. **Add and check the server.** Reuse the [saved connection design](saved-server-connections.md), including existing SSH aliases, host-managed credentials, host identity verification and the discovery worker. Connection implementation and qualification remain separate prerequisites. Introduce no new SSH transport or browser key store.
2. **Create site → WordPress.** Enter the primary domain, site title, administrator username and email. Use the server's default PHP version unless an optional site setting selects another supported version. Additional domain aliases belong under Advanced. Derive the internal site identifier automatically using the native convention's bounds; refuse collisions rather than overwrite or adopt another site.
3. **Read one authorization summary and press Create.** State that Barectl will install required server software, trust the approved PHP package publisher, create the site's isolated Linux identity and database, obtain its HTTPS certificate and install WordPress. Name the certificate authority, link its agreement and show the contact email; Create explicitly accepts the required certificate agreement. Show the selected PHP version and first-login expectation in plain language. No separate source, index refresh, driver, component-plan or intermediate Apply clicks appear in this journey.
4. **Follow progress and open the site.** Show the current stage, completed stages, useful failure details and the next supported action. Completion requires verified HTTPS and WordPress, plus a safe browser first-login path. A mandatory terminal password command does not meet this target.

The operator-input target is **two minutes or less**, measured from a usable server connection through submitting Create with ordinary inputs. Package downloads, certificate validation and installation have no promised wall-clock duration until measured. Connection failures and corrective administration are reported separately from the ordinary input measurement.

## One request, existing native operations

Create authorizes one bounded site recipe. Record its requester, server connection and identity, domain names, derived identifier, PHP selection, administrator metadata and certificate contact/authority in the controller's application database. The administrator email supplies the certificate contact, shown in the authorization summary. Repeated submissions return the same active intent; they do not queue another installation.

Reuse the [one-action TLS coordinator](adr/0014-install-site-certificates-with-one-operator-action.md), operation lifecycle, completion callbacks and existing application services. Internally prepare, admit, apply and verify the required work in prerequisite order:

- Inspect the fresh server and establish the PHP source's required distribution tools, including GnuPG, CA certificates and APT's helper, through authenticated Ubuntu-only package admission. This owned prerequisite stage must not ask the operator to install tools in a terminal. Authenticate and set up the fixed PHP source where needed, then refresh package indexes.
- Install or observe satisfied Nginx, the selected PHP CLI/FPM and MariaDB.
- Create the convention site and its isolated Linux identity/pool.
- Install the authenticated WP-CLI tool and selected-branch WordPress extensions, including the database driver; create the site's MariaDB binding.
- Run the existing challenge-route, guarded Certbot renewal, certificate issuance and HTTPS activation stages.
- Prepare and apply the exact WordPress installation, then verify its native application and HTTPS state.

Record internal immutable plans and runs for audit and Advanced inspection. The operator's single authorization replaces repeated review clicks, not fresh evidence or exact native admission. Missing prerequisites are handled by the recipe's owned stages; they must not send the operator through six separate setup workflows.

Each mutation still uses the existing SSH worker boundary, fixed bounded payload, transient systemd unit, nonblocking native lock, boot/deadline fences, package provenance, permissions and postcondition checks. Do not combine the recipe into an oversized payload, hold a remote lock across the entire sequence, or introduce another execution path. Native configuration remains the server's authority; no Barectl inventory manifest or persistent remote agent is added.

## PHP defaults and site versions

Fresh servers use **one PHP supply method: the existing approved Surý source**, under [ADR 0016](adr/0016-limit-third-party-php-supply.md). Keep its exact repository/suite/architecture restrictions, scoped signing trust, PHP-only allowlist, authenticated index freshness and transaction provenance. Other packages retain their approved Ubuntu sources. No source picker or fallback supplier appears in normal creation.

Existing Ubuntu PHP, legacy-PPA PHP and mixed-source installations are not silently converted. Recognize their actual native state and preserve existing sites. A conflicting supply stops with an actionable explanation; any migration needs a separately accepted design. This requirement changes the fresh-server product policy, not the qualification status of current WordPress code.

The **server default PHP** is reconstructed from the native `/usr/bin/php` alternative, including its resolved version and package provenance. It supplies the initial selection for new sites. On a fresh server with no PHP, the recipe establishes a qualified initial default. Missing, inaccessible or unsupported default evidence is explicit; another controller's cached preference is never authority.

Sites remain pinned to versioned CLI paths and their operative Nginx/FPM pool configuration. Changing the server default affects subsequent site creation, not existing sites. Install a selected version on demand through the approved package path. If package installation changes the CLI alternative, restore the reviewed intended server default through supported native alternatives operations and verify it. A partial failure must report the observed default honestly, not claim restoration without proof.

**Switching an existing site's PHP version is required.** Prepare fresh evidence, install missing runtime capabilities, preserve the server default and other sites, update only the selected site's admitted pool/routing, and verify its database and application compatibility. Keep a clear recoverable failure boundary; do not describe merely installing another branch as switching a site. The exact switch/recovery design must precede implementation.

WordPress presently admits only the qualified Ubuntu-supply combinations in its [qualification record](v0.4-qualification.md). The new Surý and multi-version recipe cannot ship by hiding or bypassing those gates. Expand and record qualification before offering the new selections.

## Node and browser first login

Node must follow the same operator model: a native reconstructable server default, per-site runtime selection, installation on demand, pinned existing sites and a safely reviewed version switch. **Node's supported versions, supply/trust mechanism, native application convention and qualification remain technical-design gates.** The [native runtime comparison](site-creation-competitor-analysis.md#native-runtime-alternatives) identifies mise's system installation as the candidate to qualify and nvm as the per-user alternative. Node runtime management is required here; general Git deployment, arbitrary build commands and package-manager selection need their own application contract. Show no working runtime picker or creation option until those capabilities exist. Controller development Node is not managed-server support.

**Safe browser first login is a launch gate.** The [current WordPress policy](wordpress.md#first-login) generates and discards the initial password and requires a terminal command. Retaining that command as the required final chore fails this design. A bounded owning secret-delivery design must specify how the browser establishes first access, requester authorization, expiry/single use where applicable, controller/server failure and recovery, and credential handling before code is written. Final passwords must never enter URLs. Protect all first-access secrets from process arguments/environments, logs, audit, ordinary persistent controller records and other users' views. The [reset-link candidate](site-creation-competitor-analysis.md#native-runtime-alternatives) uses a bearer key in WordPress's standard reset URL; any such channel needs a separate explicit decision covering expiry, single use, referrer and request-log protection, and authorized reveal. No password-storage or token-delivery mechanism is implicitly approved here.

## Progress, failure and recovery

Completed native steps survive controller or SSH loss; starting later stages requires the controller worker. Say when continuation is waiting for that worker. A second device reconstructs supported server resources, not another device's private recipe history.

Stop on changed identity/names/selection, denied permissions, failed DNS or certificate validation, conflicting native work, failed verification or unknown outcome. Inspect/reconcile the original unit before proceeding. Never replay an uncertain certificate order or WordPress installation, drop partial tables, rotate credentials, delete content or claim automatic rollback. Recovery uses fresh native evidence and the existing exact missing-resource/Finish rules; ambiguous state requires an honest refusal.

## Acceptance and rollout gates

- Demonstrate the ordinary connection → Create WordPress → verified HTTPS/application → browser first-login journey within the measured input target, with one Create authorization and no prerequisite review clicks.
- Qualify fresh Ubuntu 24.04 and 26.04 on amd64 and arm64 for every offered PHP branch/supply pair. Exercise multiple installed branches, default reconstruction/change, on-demand installation and preservation of pinned existing sites. Unsupported combinations remain disabled.
- Prove two controllers with independent databases, aliases and keys cannot duplicate or conflict with mutations; reconstruct site, PHP default and runtime selections without a prior controller database or remote manifest.
- Test denied/revoked permissions, stale identity, failed DNS, source/index unavailability, partial steps, controller/SSH loss and unknown outcomes. Verify no destructive retry and no misleading completion.
- Qualify per-site PHP switching and the final browser secret design independently, including secret absence on every exposed surface and unauthorized/repeated access.
- Keep Node unavailable until its owning technical design, native implementation and complete runtime/default/switch qualification pass.
- Complete required repository, browser and affected native checks before pushing, then full exact-head native statuses. Publish operator docs and qualification limits with the delivered behavior.

This deliberately changes [explicit source selection and metadata refresh](php-versions.md#observable-requirements), [individual site reviews](sites.md), and the [terminal first-login policy](wordpress.md#first-login). Advanced diagnostics remain available. The existing one-action TLS authorization establishes the reusable pattern; these broader authorizations and unresolved technical gates must be implemented and qualified before current guides claim the new journey works.
