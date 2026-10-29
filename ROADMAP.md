# Roadmap

The [README](README.md#current-status) lists implemented behavior, and [Releases](https://github.com/rajandangi/barectl/releases) records published versions. GitHub Issues own implementation priorities and ticket state. Release publication and qualification evidence establish availability; a specification or a completed local implementation alone does not.

Every phase follows the [core philosophy](README.md#core-philosophy): local operation by default, native server state as authority, and independent discovery from another authorized device. Barectl's own history stays in its application database. Provisioning uses one standard configuration and proves reconstruction without that database or custom server-side tracking records.

## Phases

The [target architecture](docs/target-architecture.md), tracked in [#323](https://github.com/rajandangi/barectl/issues/323), is the one stack Barectl manages: fresh Ubuntu 26.04 hosts with Caddy, Nix-supplied runtimes, per-site HAProxy and PHP-FPM, systemd automation and restic ([ADR 0026](docs/adr/0026-manage-fresh-hosts-on-one-target-stack.md)). Each phase has its own specification, tickets and qualification record.

- **A. Foundation, implemented.** Specification [#325](https://github.com/rajandangi/barectl/issues/325). [Saved connections](docs/saved-server-connections.md) with host keys confirmed against the provider's fingerprint ([ADR 0034](docs/adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md)), the [host foundation](docs/bootstrap.md), [runtimes and server defaults](docs/runtimes.md), [plain PHP sites](docs/sites.md) with per-site PHP and Node selection, discovery and fresh-controller reconstruction, the one change engine of [ADR 0035](docs/adr/0035-one-change-engine-with-effect-derived-consent.md) and the snapshot-based native test harness of [ADR 0033](docs/adr/0033-prove-real-behavior-in-two-test-layers.md). The Nginx, Certbot, APT-PHP and rclone code and its tests were deleted at the phase exit, and Phase B later added HTTPS, databases, WordPress and Laravel on the same foundation. The [qualification record](docs/phase-a-qualification.md) lists the measured build times and what is not qualified.
- **B. PHP sites, implemented.** Specification [#356](https://github.com/rajandangi/barectl/issues/356): WordPress and Laravel creation and deployment, site databases, HTTPS, settings and secrets, site and runtime removal and catalog updates. The [qualification record](docs/phase-b-qualification.md) audits every user story, names the tested revision and lists what is not qualified. Phase B is not released.
- **C. Automation, implemented.** Specification [#357](https://github.com/rajandangi/barectl/issues/357): WordPress cron, Laravel scheduler and queue workers, per-site object cache and log viewing. The [qualification record](docs/phase-c-qualification.md) names the tested revision and lists what is not qualified. Phase C is not released.
- **D. Protection, implemented.** Specification [#358](https://github.com/rajandangi/barectl/issues/358): restic backups onsite and to S3-compatible storage, recovery points and selective restore. The [qualification record](docs/phase-d-qualification.md) names the tested revision, the measured scenarios and what is not qualified. Phase D is not released.
- **E. Operations, planned.** Server and site dashboards, [Server Jobs](docs/server-jobs.md), log retention, the [security baseline](docs/v0.9.md) and permissions.

A full local build targets five minutes and never exceeds 15, and so does each required CI shard; adding code must not make the suite slower ([test time budget](docs/quality.md#test-time-budget)). Each phase measures memory and disk on small hosts before claiming a minimum size.

## After the phases

- **1.0:** Documented upgrades, stable configuration contracts, and recovery guarantees proven by integration tests. Requires a specification of its own before release.
- **After 1.0:** Optional shared remote database support across local installations, fleet overview, CLI parity, and tested team hosting with credential management. Hosted application or shared database use remains optional.

Email hosting, billing, reseller management, DNS hosting, and container orchestration are outside scope.

Long-running operations accepted by the server and server schedules use native Linux facilities or established packages and continue without a connected Barectl device. Accepted changes already run as transient systemd units; discovery and change preparation still depend on the controller's worker. See [changes and jobs](docs/architecture.md#changes-and-jobs).
