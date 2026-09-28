# Roadmap

The README lists implemented discovery behavior. Release numbers below describe intended scope; v0.2 is specified but not implemented.

Every milestone follows the [core philosophy](README.md#core-philosophy): local operation by default, native server state as authority, and independent discovery from another authorized device. Barectl's own history stays in its application database. Future provisioning must use standard configuration and prove reconstruction without that database or custom server-side tracking records.

- **0.1: Connect and discover.** Register servers by controller SSH alias, check host keys against the controller's known_hosts, authenticate using the controller's SSH environment, queue read-only discovery, and display OS, resources, web-stack components and service states, and detected Nginx site files and PHP-FPM pools. Start with Ubuntu 24.04 LTS. Define supported layouts through fixtures and disposable-server tests.
- **0.2: Bootstrap.** [Review exact Ubuntu 24.04 Nginx and PHP 8.3 plans](docs/v0.2.md), explicitly refresh package metadata, and apply through detached native execution with cross-device exclusion and reconciliation. Preserve distribution defaults, validate outcomes, and reconstruct them from a fresh controller. Package installation remains gated on exact-transaction admission and real-server recovery tests. It builds on the pyinfra SSH connection discovery already uses ([#105](https://github.com/rajandangi/barectl/issues/105)).
- **0.3: PHP sites.** Per-site Linux users, PHP-FPM pools, Nginx configuration, databases, and TLS.
- **0.4: WordPress.** Installation and WP-CLI operations.
- **0.5: Laravel.** Git deployments, Composer, migrations, scheduler, and workers.
- **0.6: Backups and restore.** Verified restore workflows before automated retention.
- **Later:** Saved SSH connection details, optional shared remote database support across local installations, native server history and job views, security auditing, fleet overview, CLI parity, and tested team hosting with credential management. Hosted application or shared database use remains optional.
- **1.0:** Documented upgrades, stable configuration contracts, and recovery guarantees proven by integration tests.

Email hosting, billing, reseller management, DNS hosting, and container orchestration are outside the initial scope.

Long-running operations accepted by the server and server schedules must use native Linux facilities or established packages and continue without a connected Barectl device. This is planned behavior; current read-only discovery still depends on the controller's worker. See [changes and jobs](docs/architecture.md#changes-and-jobs).
