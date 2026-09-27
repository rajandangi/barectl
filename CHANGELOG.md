# Changelog

## 0.0.1 - Unreleased

- Add Django authentication, server inventory, and admin forms.
- Protect inventory access with Django permissions.
- Add environment-based configuration, CI, and project documentation.
- Record the discovery-first roadmap. Remote operations are not implemented.
- Restyle sign-in and the Servers page with a Barectl USWDS theme, the approved palette and self-hosted Inter.
- Build frontend assets with Vite and serve them through Django's static files using the Vite manifest.
- Add HTMX 4 server search with fragment updates, CSRF headers and authentication-aware redirects.
- Add Playwright browser tests against production-built assets.
- Register and edit servers by choosing an SSH alias from the controller's configuration, read with paramiko as the planned pyinfra connector resolves it. Patterns, `Match` blocks, removed aliases and aliases using settings the connection does not implement are rejected with guidance.
- Django admin no longer adds or edits servers.
- Verify SSH connections in a durable `db_worker` process after registration or on request. Host keys must already be trusted in the controller's known_hosts; unknown, changed and revoked keys are refused. Authentication uses the controller's key files or SSH agent.
- Show each server's connection state and an operating system snapshot read from os-release, with collection time, provenance and sanitized failures. Discovery attempts and snapshots are stored separately, with one active attempt per server.
- Add architecture, available CPUs, memory and root filesystem capacity to the snapshot, read with `uname -m`, `nproc`, `/proc/meminfo` and `df`. Missing, unrunnable and unsupported observations are shown with warnings, never as zero.
- Observe Nginx site files and PHP-FPM pools during discovery, read with the SSH user's own permissions from the supported Debian and Ubuntu layouts. Only server names, listen addresses, pool names and PHP versions are stored; credentials, secret environment values and configuration dumps are discarded before persistence. Permission denials and unsupported syntax are distinct from absent sites and pools, partial results are preserved, and sites are never linked to pools.
- Name discovery observations after the glossary in `CONTEXT.md` throughout the server page, code and documentation: web-stack components, component observations, Nginx site files and PHP-FPM pools.
- Report observations Barectl could not inspect as unsupported, never absent. A missing inspection command, os-release file or `/proc/meminfo` no longer claims the server lacks an operating system or capacity, and the database refuses absent attributes. Nginx site files and PHP-FPM pools are read only where dpkg shows the component installed, and pools only for installed PHP-FPM versions; configuration left by removed packages is not reported.
- Read Nginx site files and PHP-FPM pools only after confirming that `nginx.conf` and each version's `php-fpm.conf` include the Debian directories, as the stock files do. A missing, unparseable or changed include is reported as unsupported instead of showing configuration the daemon may not load.
