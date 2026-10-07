# Roadmap

The [README](README.md#current-status) lists implemented behavior, and [Releases](https://github.com/rajandangi/barectl/releases) records published versions. v0.2.0 includes the discovery foundation and reviewed bootstrap; v0.3.0 adds PHP sites, site databases and HTTPS. The [v0.2](docs/v0.2-qualification.md) and [v0.3](docs/v0.3-qualification.md) qualification records identify tested revisions, environments and remaining limits. Later milestones describe planned scope, without delivery dates.

Every milestone follows the [core philosophy](README.md#core-philosophy): local operation by default, native server state as authority, and independent discovery from another authorized device. Barectl's own history stays in its application database. Future provisioning must use standard configuration and prove reconstruction without that database or custom server-side tracking records.

- **0.1: Connect and discover, included in v0.2.0.** Register servers by controller SSH alias, check host keys against the controller's known_hosts, authenticate using the controller's SSH environment, queue read-only discovery, and display OS, resources, web-stack components and service states, and detected Nginx site files and PHP-FPM pools. Start with Ubuntu 24.04 LTS. Define supported layouts through fixtures and disposable-server tests.
- **0.2: Bootstrap, released as v0.2.0.** [Review exact Nginx and PHP plans for Ubuntu 24.04 and 26.04](docs/v0.2.md), explicitly refresh package metadata, and apply through detached native execution with cross-device exclusion and reconciliation. Preserve distribution defaults, validate outcomes, and reconstruct them from a fresh controller. Package installation admits only the exact reviewed transaction. It builds on the pyinfra SSH connection discovery already uses; see [bootstrapping a server](docs/bootstrap.md).
- **0.3: PHP sites, released as v0.3.0.** [Accepted specification](docs/v0.3.md). Reconstruct and create PHP sites with dedicated Linux users, PHP-FPM pools and Nginx configuration; prepare MariaDB/PostgreSQL engines and site bindings; and install HTTPS with native Certbot renewal. Each slice has its own reconstruction, mutation and failure evidence in the [qualification record](docs/v0.3-qualification.md). See the [first-site walkthrough](docs/first-site.md), [design decisions](docs/v0.3-decisions.md) and [native convention](docs/site-conventions.md).
- **0.4: WordPress.** Installation and WP-CLI operations.
- **0.5: Laravel.** Git deployments, Composer, migrations, scheduler, and workers.
- **0.6: Backups and restore.** Verified restore workflows before automated retention.
- **Later:** Saved SSH connection details, optional shared remote database support across local installations, native server history and job views, security auditing, fleet overview, CLI parity, and tested team hosting with credential management. Hosted application or shared database use remains optional.
- **1.0:** Documented upgrades, stable configuration contracts, and recovery guarantees proven by integration tests.

## Follow-up work

[Per-site PHP versions](docs/php-versions.md), tracked in [#236](https://github.com/rajandangi/barectl/issues/236), preserve explicit branch selection through site creation, discovery, database drivers and HTTPS. The approved source's reviewed branches are qualified per the [qualification record](docs/php-versions-qualification.md); further branches or suppliers need their own qualification. Existing qualified Ubuntu-default workflows remain available.

GitHub Issues own implementation priorities and ticket state. Release publication and qualification evidence establish availability; a specification or completed local implementation alone does not.

Email hosting, billing, reseller management, DNS hosting, and container orchestration are outside the initial scope.

Long-running operations accepted by the server and server schedules must use native Linux facilities or established packages and continue without a connected Barectl device. v0.2 bootstrap runs already do so as transient systemd units; read-only discovery and plan preparation still depend on the controller's worker. See [changes and jobs](docs/architecture.md#changes-and-jobs).
