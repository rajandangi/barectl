# Native contract

Barectl publishes one versioned native contract for the shapes it reads and writes on a
managed server. The current contract version is **1**. The decision is
[ADR 0042](adr/0042-version-the-native-contract-without-a-server-marker.md), which amends
[ADR 0015](adr/0015-recognize-only-the-convention.md) and
[ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md) with one version number and
one change policy.

The contract is not a marker, inventory or journal on the server. A managed server stays
the source of truth, and a fresh controller recognizes its native shapes without a Barectl
database ([state and discovery](architecture.md#state-and-discovery)). The version travels
in every change's `barectl-result` line as `"contract": 1`; the line is native evidence,
not a tracking record.

`contract/` owns the machine-readable manifest and its test. `contract/manifest.json` is
the pinned expectation, and `contract/test_contract.py` builds the manifest from the owning
modules and fails when a promised shape changes, is removed or is renamed without updating
the version and the pinned file together. Each section is one module registered in
`contract/manifest.py`; a later area adds one module and one registry entry.

## Change policy

- **Additive change.** A new optional field, site, runtime, command or permission that
  leaves every existing promised shape unchanged is compatible. It may ship within
  version 1 when every reader in the previous release ignores it safely. The manifest
  gains the entry, and the contract test records it.
- **Breaking change.** Removing, renaming, retyping or meaningfully changing a promised
  shape requires a new contract version. The release must carry a discovery migration or
  dual-read support for the previous version and keep both for at least one release, a
  deprecation window. The contract names the old and new shapes, and the pinned manifest
  keeps both during the window.
- **Unmigratable shape.** A shape the controller cannot migrate is reported once as
  **Outside supported settings** and blocks only the actions that depend on it. Discovery
  stays read-only and never rewrites the server to fit.
- **Refusal.** A controller that cannot recognize a version, or that finds a shape outside
  its contract, refuses every change with one plain sentence. It does not guess, downgrade,
  rewrite or partially apply.

## Site convention

The native PHP site layout is owned by [site conventions](site-conventions.md), with
runtime selection and serving masters in [runtimes](runtimes.md). The manifest's
`site_convention` section covers:

- the identifier grammar and reserved names;
- the site and proxy accounts and the shared `caddy` user;
- site directories with their owners, groups and modes, including `releases/`, `current`,
  `private/`, `logs/` and `bin/`;
- the release layout, `current` link and the stable `.deploy.lock`;
- the per-site Caddy file and its route;
- the HAProxy service template, configuration, state file and its HTTP and administrative
  sockets; and
- the per-runtime PHP-FPM service templates, configuration files, master and diagnostic
  pools, and application, status and diagnostic sockets.

## Server foundation

The host foundation is owned by [setting up a server](bootstrap.md), and its runtime
profiles and templates by [runtimes](runtimes.md). The module that publishes the shapes is
in the [module map](architecture.md#module-map). The manifest's `foundation` section
covers:

- the Nix profile root and the foundation's `caddy`, `composer`, `wp-cli` and `haproxy`
  profiles, plus the catalog's runtime entries and the Nix configuration;
- the catalog lock's path, format, architectures and entry pattern;
- the main Caddy configuration, its unit, its sites directory and its private admin
  socket, and the persistent-journal drop-in;
- the runtime master unit template and the per-site PHP-FPM templates;
- the root-controlled mutation lock directory and file; and
- the transient unit prefix and name pattern, the payload and staged-body limits, the
  setup stages and the engine's exit contract.

## Backups

The backup layout is owned by [backups](backups.md); the operator's recovery commands are
[native recovery](recovery.md). The module that publishes the shapes is
`backups/convention.py`, and the recovery kit's fields come from its public signature. The
manifest's `backups` section covers:

- the onsite repository root, a site's repository directory and its root-only server key;
- the offsite storage root, non-secret config file, capture and pruning credential files,
  source-site list and health repository, plus the `s3:<endpoint>/<bucket>/<prefix>/<site>`
  repository shape and the supported providers;
- the pinned restic profile, entry, binary, cache directory and repository lock root;
- the capture marker, identifier, tag and point grammars, the database name and dump
  filename, the scope, part, origin and application names, the parts each scope requires,
  the retention policies and free-space headroom;
- the live and paused snapshot tag order, including `complete`;
- the schedule's script, payload and slice, service and timer files and contents, its
  frequencies, weekly day, UTC calendar expressions, scopes, timeout, lock wait and window;
  and
- the recovery kit's non-secret fields.

## Results

The result line and its vocabulary are owned by the
[one change engine](adr/0035-one-change-engine-with-effect-derived-consent.md), read by
[server jobs](server-jobs.md) and written into the operator's
[native recovery](recovery.md) journal evidence. `operations/engine.py` is the one reader,
and `operations/reasons.py`, `operations/body_reasons.py` and each app's
`bodies/reasons.py` declare the reasons. The manifest's `results` section is built from
those modules and does not keep a second list:

- the `barectl-result ` line and its `barectl-stage ` progress prefix;
- every wire field: `class`, `reason`, `change_kind`, `sites` and the contract version
  field `contract`, whose current value is 1;
- the result classes `succeeded`, `refused`, `partial`, `failed`, `lock_busy` and
  `timed_out`, and the site identifier grammar the `sites` field accepts;
- the engine's admission reasons, the shared body reasons, every registered kind's and
  non-kind body's reasons, and the retired names that stay readable as older evidence.

Jobs keeps the `contract` value on each observed result line. A controller compares it
with its own contract version before it offers a change. A recorded version newer than the
controller's, or an older positive version, is reported as **Outside supported settings**:
the server page says so, every change card is withheld with one plain sentence, and a
direct preparation request is refused. A line written before the field existed recorded
`0`; v0.4.0 wrote no field and is contract 1, so `0` is compatible. No result lines
establish no version and are not by themselves unrecognized. Discovery stays read-only:
it reads the retained line and never writes a version marker on the server.

## Application surface

The application surface is what operators and scripts address directly: permission names,
URL names, management commands and documented environment variables. It is owned by
`operations/models.py`, the URLconf, Django's command registry, `config.settings` and
`dashboard/management/commands/`, and described by
[operator accounts](../README.md#operator-accounts), [site logs](logs.md#permission),
[settings and secrets](settings.md#permissions-and-discovery),
[dashboard workflows](dashboard-workflows.md) and [upgrading](upgrade.md). The manifest's
`application` section is built from those owners and covers:

- the change engine's six scope permissions `operations.view_changes`,
  `operations.change_site`, `operations.change_shared`, `operations.change_destructive`,
  `operations.manage_secrets` and `operations.view_evidence`, plus `servers.view_server`,
  `servers.add_server`, `servers.change_server`, `servers.delete_server`,
  `discovery.add_discoveryattempt` and `discovery.view_siteobservation`;
- every named route in `config/urls.py`, including the redirects that keep the old
  `stack/`, `setup/` and `changes/` paths working;
- the documented management commands `barectl_upgrade`, `changepassword`, `check`,
  `collectstatic`, `createsuperuser`, `db_worker`, `makemigrations`, `migrate`,
  `runserver`, `showmigrations` and `test`; and
- the documented environment variables `BARECTL_SECRET_KEY`, `BARECTL_ALLOWED_HOSTS`,
  `BARECTL_DEBUG`, `BARECTL_SSH_CONFIG`, `BARECTL_SSH_KNOWN_HOSTS`,
  `BARECTL_SSH_APPROVED_KEYS`, `BARECTL_CONFIDENTIAL_KEY`, `BARECTL_EXPORT_STAGING`,
  `BARECTL_VITE_DEV_SERVER_URL` and `BARECTL_TEST_DATABASE`.

A permission name, URL name, command or documented environment variable is part of the
contract. Renaming, removing or retyping one is a breaking change under
[ADR 0042](adr/0042-version-the-native-contract-without-a-server-marker.md): it needs a new
contract version, a discovery migration or dual-read support for the previous name, and at
least one release of deprecation. Adding one is additive when every existing shape is
unchanged.
