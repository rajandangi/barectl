# Roadmap

The [README](README.md#current-status) lists implemented behavior, and [Releases](https://github.com/rajandangi/barectl/releases) records published versions. GitHub Issues own implementation priorities and ticket state. Release publication and qualification evidence establish availability; a specification or a completed local implementation alone does not.

Every phase follows the [core philosophy](README.md#core-philosophy): local operation by default, native server state as authority, and independent discovery from another authorized device. Barectl's own history stays in its application database. Provisioning uses one standard configuration and proves reconstruction without that database or custom server-side tracking records.

## Phases

The [target architecture](docs/target-architecture.md), tracked in [#323](https://github.com/rajandangi/barectl/issues/323), is the one stack Barectl manages: fresh Ubuntu 26.04 hosts with Caddy, Nix-supplied runtimes, per-site HAProxy and PHP-FPM, systemd automation and restic ([ADR 0026](docs/adr/0026-manage-fresh-hosts-on-one-target-stack.md)). Each phase has its own specification, tickets and qualification record.

- **A. Foundation, implemented.** Specification [#325](https://github.com/rajandangi/barectl/issues/325). [Saved connections](docs/saved-server-connections.md) with host keys confirmed against the provider's fingerprint ([ADR 0034](docs/adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md)), the [host foundation](docs/bootstrap.md), [runtimes and server defaults](docs/runtimes.md), [plain PHP sites over HTTP](docs/sites.md) with per-site PHP and Node selection, discovery and fresh-controller reconstruction, the one change engine of [ADR 0035](docs/adr/0035-one-change-engine-with-effect-derived-consent.md) and the snapshot-based native test harness of [ADR 0033](docs/adr/0033-prove-real-behavior-in-two-test-layers.md). The Nginx, Certbot, APT-PHP and rclone code and its tests were deleted at the phase exit, so `main` has no HTTPS, WordPress or database workflows until Phase B.
- **B. PHP sites, planned.** WordPress and Laravel creation and deployment, databases, [HTTPS](docs/tls.md), settings and secrets. The [databases](docs/databases.md) and [WordPress](docs/wordpress.md) pages record the accepted direction. The [v0.4](docs/v0.4.md) and [v0.5](docs/v0.5.md) specifications and the site-first creation workflow of [#320](https://github.com/rajandangi/barectl/issues/320) are requirement inputs; the target architecture's ADRs supersede their Nginx, Certbot and APT mechanics.
- **C. Automation, planned.** WordPress cron, Laravel scheduler and workers in per-site slices ([ADR 0036](docs/adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md)), per-site object cache ([ADR 0030](docs/adr/0030-give-each-site-its-own-valkey-instance.md)), log viewing.
- **D. Protection, planned.** restic backups onsite and to S3-compatible storage, live scheduled recovery points and selective restore ([ADR 0031](docs/adr/0031-back-up-with-restic.md), [ADR 0037](docs/adr/0037-capture-scheduled-backups-live.md)). The [v0.6](docs/v0.6.md) and [retention](docs/backup-retention.md) specifications are requirement inputs; their rclone mechanics are superseded.
- **E. Operations, planned.** Server and site dashboards, [Server Jobs](docs/server-jobs.md), log retention, the [security baseline](docs/v0.9.md) and permissions.
- **F. Later languages, planned.** Node.js and Python services, Go and Rust binaries, on the same application contract.

A full local build targets 10 minutes and never exceeds 15, and so does required CI. Each phase measures memory and disk on small hosts before claiming a minimum size.

## After the phases

- **1.0:** Documented upgrades, stable configuration contracts, and recovery guarantees proven by integration tests. Requires a specification of its own before release.
- **After 1.0:** Optional shared remote database support across local installations, fleet overview, CLI parity, and tested team hosting with credential management. Hosted application or shared database use remains optional.

Email hosting, billing, reseller management, DNS hosting, and container orchestration are outside scope.

Long-running operations accepted by the server and server schedules use native Linux facilities or established packages and continue without a connected Barectl device. Accepted changes already run as transient systemd units; discovery and change preparation still depend on the controller's worker. See [changes and jobs](docs/architecture.md#changes-and-jobs).
