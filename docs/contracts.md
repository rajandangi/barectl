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
