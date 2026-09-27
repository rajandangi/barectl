# Roadmap

Only the foundation listed in the README is implemented. Release numbers below describe intended scope.

- **0.1: Connect and discover.** Register servers by controller SSH alias, check host keys against the controller's known_hosts, authenticate using the controller's SSH environment, queue read-only discovery, and display OS, resources, web-stack components and service states, and detected Nginx site files and PHP-FPM pools. Start with Ubuntu 24.04 LTS. Define supported layouts through fixtures and disposable-server tests.
- **0.2: Bootstrap.** Review and apply package/service configuration plans, with audit records, validation, and recovery steps.
- **0.3: PHP sites.** Per-site Linux users, PHP-FPM pools, Nginx configuration, databases, and TLS.
- **0.4: WordPress.** Installation and WP-CLI operations.
- **0.5: Laravel.** Git deployments, Composer, migrations, scheduler, and workers.
- **0.6: Backups and restore.** Verified restore workflows before automated retention.
- **Later:** Security auditing, fleet overview, CLI parity, and tested team hosting with credential management.
- **1.0:** Documented upgrades, stable configuration contracts, and recovery guarantees proven by integration tests.

Email hosting, billing, reseller management, DNS hosting, and container orchestration are outside the initial scope.
