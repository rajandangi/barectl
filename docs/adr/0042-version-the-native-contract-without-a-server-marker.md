# Version the native contract without a server marker

Accepted on 2026-11-09 for [#529](https://github.com/rajandangi/barectl/issues/529) under the
1.0 specification [#528](https://github.com/rajandangi/barectl/issues/528). It amends
[ADR 0015](0015-recognize-only-the-convention.md) and
[ADR 0026](0026-manage-fresh-hosts-on-one-target-stack.md) with one version number and one
change policy; it does not add a new execution path or a Barectl record on the server.

## Context

Barectl already publishes its native conventions: the site layout and units in
[site conventions](../site-conventions.md), the host foundation in
[bootstrap](../bootstrap.md), the restic layout in [backups](../backups.md), the
`barectl-result` line and reason vocabulary in
[ADR 0035](0035-one-change-engine-with-effect-derived-consent.md), and the dashboard's
permission and URL names. Operators build ordinary Linux administration around those shapes,
and a later Barectl release must not silently change them. The managed server is the source
of truth and carries no Barectl inventory, manifest or journal
([AGENTS.md](../../AGENTS.md)), so a version cannot live in a controller-written file on the
server. A server can also be managed by two controllers of different releases.

## Decision

Publish one native contract with an integer version. Version `1` is the first contract, and
it describes what a 1.0 controller reads and writes. The contract covers:

- the site convention: paths, owners, groups, modes, release layout, deploy lock, Caddy site
  file, per-site HAProxy and PHP-FPM units and sockets;
- the server foundation: Nix profile paths, the catalog lock, Caddy and journald
  configuration, runtime templates, the native lock and the transient unit shape;
- backups: onsite and offsite repository layout, snapshot tags, part and scope names,
  filenames, key paths and recovery-kit fields;
- results: the `barectl-result` line, its class, reason, change-kind and site fields, and the
  reason vocabulary; and
- the application surface operators script against: permission names, URL names,
  management commands and documented environment variables.

`docs/contracts.md` owns the reader-facing text and links each area to its topic document.
`contract/` owns the machine-readable manifest and the contract test, and builds every entry
from the module that owns it. The manifest is checked in as a pinned expectation, so a
promised shape cannot change without a reviewed version bump.

### Where the version is carried

The version is native evidence, never a server-side marker:

- Every change's `barectl-result` line carries `"contract": 1`. The engine writes the field
  beside `change_kind` and `sites`, including on a line a kind's body prints, so any
  authorized controller reading the retained journal can tell which contract wrote the run
  without the starting controller's database. It is non-secret, contains no path or
  application value, and is not a tracking record.
- Discovery does not need the field to reconstruct state. It recognizes the native shapes
  themselves. A shape outside the contract is reported once as **Outside supported settings**
  and blocks only the changes that depend on it
  ([ADR 0015](0015-recognize-only-the-convention.md)).
- A running Barectl unit is recognized by the contract's transient unit name,
  `barectl-apply-<32 lowercase hex>.service`, and by its `barectl-stage` and `barectl-result`
  journal lines. The mutation lock is the root-controlled, empty
  `/run/lock/barectl/mutation.lock`; it carries no process, PID, review or version. Nothing
  else on the server records the controller's version.
- When a result line names a contract version this controller does not recognize, the line
  is still native evidence of an outcome, but it is not evidence the controller may act on.
  The server is reported as outside supported settings and changes are refused rather than
  approximated.

### Change policy

- **Additive change.** A new optional field, a new site, runtime, command or permission that
  does not change an existing promised shape, is compatible. It may ship within the same
  contract version when every reader in the previous release ignores it safely. The manifest
  gains the entry and the contract test records it.
- **Breaking change.** Removing, renaming, retyping or meaningfully changing a promised
  shape requires a new contract version. The release must carry a discovery migration or
  dual-read support for the previous version and keep both for at least one release
  (a deprecation window). The contract document names the old and new shapes, and the
  contract test pins both during the window.
- **Unmigratable shape.** A shape the controller cannot migrate is reported once as outside
  supported settings and blocks only the actions that depend on it. Discovery stays
  read-only; the controller never rewrites the server to fit.
- **Refusal.** A controller that cannot recognize a version, or that finds a shape outside
  its contract, refuses every change with one plain sentence. It does not guess, downgrade,
  rewrite or partially apply.

### Upgrade baseline

The only supported controller upgrade source is v0.4.x. v0.4.0's database migrates to 1.0
in place, and a v0.4.0-managed server is discovered and managed by 1.0 without a server-side
edit. v0.3.0 and earlier are not upgradeable: their application schema and their Nginx,
Certbot and APT-PHP stack were replaced, and [CHANGELOG](../../CHANGELOG.md) keeps the
"rebuild the local database" instruction for those versions only.

## Alternatives considered

- **A version file in `/etc/barectl/` or the site directory.** Rejected: it is a custom
  server-side tracking record, contradicts the core philosophy, and can disagree with the
  native configuration it claims to describe.
- **A version in the transient unit name or an environment variable.** Rejected: the unit is
  gone after the run, and a name or environment value is neither durable evidence nor
  readable by ordinary administration.
- **Infer the version only from the release tag.** Rejected: a server may be partly changed
  or managed from another device, and a tag records the installer, not the native state.
- **Freeze every native shape forever.** Rejected: it forbids necessary migrations and
  hides incompatibility instead of naming it. The additive-or-migration rule keeps a stable
  contract without pretending the stack never changes.

## Consequences

- `contract/` and `docs/contracts.md` become required reading for native changes; the fast
  contract test fails an unversioned promised-shape change.
- The result-line parser accepts the `contract` field and refuses an unrecognized value as
  evidence it cannot act on.
- The 1.0 qualification record names the tested upgrade source and the contract version.
- Each later breaking change carries a manifest version bump, a migration or dual-read path,
  and a named deprecation window.

## Sources

- [Django 6.1 migrations](https://docs.djangoproject.com/en/6.1/topics/migrations/): the
  application schema is versioned as ordered migration files, which is the model for the
  additive-or-migration rule on the controller side.
- [Django 6.1 custom management commands](https://docs.djangoproject.com/en/6.1/howto/custom-management-commands/):
  the documented way the upgrade command exposes installation and schema state.
- [Semantic Versioning 2.0.0](https://semver.org/): a release version is not a native
  contract; the two are recorded separately.
- [systemd-run](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html):
  the transient unit lifecycle the running-unit recognition relies on.
- [Nix profiles](https://nix.dev/manual/nix/latest/package-management/profiles): the
  foundation profile paths the contract freezes.
- [restic repository and snapshot tags](https://restic.readthedocs.io/en/stable/045_working_with_repos.html):
  the backup layout and tag shapes the contract freezes.
- [ADR 0006](0006-use-native-bootstrap-execution.md),
  [ADR 0015](0015-recognize-only-the-convention.md),
  [ADR 0026](0026-manage-fresh-hosts-on-one-target-stack.md) and
  [ADR 0035](0035-one-change-engine-with-effect-derived-consent.md): the execution, recognition,
  target-stack and result-line decisions this record versions.
