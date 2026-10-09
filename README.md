<h1>
  <img src="static/brand/barectl-wordmark.svg" alt="Barectl" width="480">
</h1>

An open-source, agentless control plane for reconstructing, managing, and provisioning Linux web servers over SSH.

Barectl is intended for developers and agencies running PHP, WordPress, and Laravel on their own servers. Run the local-first dashboard on your computer or a private management host. Managed servers use standard Linux packages, with no Barectl agent or container requirement.

## Core philosophy

The server is the source of truth. Barectl can disappear today, and the server remains a normal, independently manageable Linux server. Managing it must not depend on an external service, a proprietary management database, or a persistent Barectl management server.

The goal is to connect from any computer with Barectl and authorized SSH access and reconstruct an accurate inventory of the server's websites, applications, databases, PHP-FPM pools, systemd services, SSL certificates, queues, users, and infrastructure configuration. Reconstruction must work without the previous Barectl installation's database. Discovery reports what it can verify and identifies inaccessible or unsupported configuration.

Barectl should provision each supported stack in one documented, consistent way, following the distribution's and services' standard conventions. Discovery must understand the resulting configuration and relationships directly from the server. Barectl must not add its own tracking files, inventory manifests, audit journals, or management database to the server. Each discovery cycle must reflect current server configuration, including changes made outside Barectl.

The planned dashboard covers the full application lifecycle: provisioning sites, deploying Laravel and WordPress applications, managing databases and services, configuring PHP and Nginx, updating packages, inspecting logs, managing queues and certificates, and maintaining server infrastructure. Barectl aims to offer the convenience and visibility of platforms such as Laravel Forge while remaining self-hosted, portable, agentless, and independent of an external control plane.

By default, each device runs Barectl with its own local database for its application login, preferences, saved connections, discovery snapshots, queued requests, and operation history. Future releases will also store SSH connection details locally. The Barectl login is separate from server users and permissions; SSH determines access to the server. Server-derived information remains a cached view of native evidence. Barectl's own operation history stays in its application database and never overrides the server's actual configuration or execution state.

The same server should be manageable from multiple devices with the convenience of a hosted dashboard. A new device needs authorized SSH access and discovery, with no database transfer, synchronization, or central Barectl service required. Discovery rebuilds supported server views and available native history. It cannot recover another device's private Barectl records or native history the server no longer retains. Operators may choose an optional remote database to share Barectl records across local installations; it does not become the source of truth for server state.

Future long-running operations accepted by the server and server schedules should continue when Barectl disconnects. Execution and coordination must use native Linux facilities or established, widely used packages verified against upstream guidance. A conflicting change must wait for fresh discovery and operator review. If reliable coordination is unavailable, Barectl must not allow conflicting changes to proceed as though they were safe. These are product requirements; the current implementation is listed below.

## Current status

Version 0.3.0 adds PHP sites, site databases and one-action HTTPS installation. Local functional verification is complete. This release carries a documented exception for an unpatched advisory in the development dependency tree; the audit failure remains visible. The [v0.3 qualification record](docs/v0.3-qualification.md) identifies the tested revisions, public staging evidence and remaining limits; the [v0.2 record](docs/v0.2-qualification.md) describes the published release.

The Django 6.1.1 dashboard uses USWDS for sign-in, Servers and Activity. Permission-protected discovery reconstructs the operating system, capacity, profile packages and services, convention sites, blocked items and their certificate relationships from native evidence. Root-authorized reads also reconstruct database bindings against the [native site convention](docs/site-conventions.md).

Reviewed [bootstrap](docs/bootstrap.md) installs distribution packages on Ubuntu 24.04 and 26.04: Nginx, PHP FPM and CLI (8.3 and 8.5), MariaDB (10.11 and 11.8), and PostgreSQL (16 and 18). Metadata refresh is a separate reviewed action. Accepted changes run under native systemd and continue without the controller.

The [per-site PHP implementation](docs/php-versions.md) retains each site's selected branch through discovery, database drivers and TLS, while preserving released site forms. The approved PHP source supplies the reviewed branches 8.3, 8.4 and 8.5 on Ubuntu 24.04 and 26.04, qualified on amd64 and arm64; the [qualification record](docs/php-versions-qualification.md) lists the evidence and its limits. The existing Ubuntu-default workflows remain available.

The v0.3 implementation [creates HTTP PHP sites](docs/sites.md) with their own Linux identity and optional [MariaDB or PostgreSQL database](docs/databases.md). **Create and Install** adds the HTTP-01 challenge route, guarded Certbot renewal, production certificate and verified HTTPS redirect through one authorized request ([TLS](docs/tls.md)). Advanced plans and staging diagnostics remain available. [Native recovery](docs/recovery.md) describes inspection and repair after partial changes. Application provisioning remains planned. SSH credentials stay in the controller host's SSH agent or key files.

The current implementation stores dashboard accounts, discovery jobs, plans, apply runs and their audit in its local Django database. Discovery covers the observations listed above. Bootstrap runs are coordinated across controllers and SSH aliases by one native lock on the server, and continue under the server's systemd when the controller stops; discovery attempts and plan preparations depend on the controller's worker and do not. Native server history views, locally saved SSH connection details and optional remote database support remain planned work.

## Run locally

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), Python 3.14 or newer, and Node 24 (selected by `.node-version`). Development and CI use Python 3.14. Older Python versions are unsupported.

```bash
git clone https://github.com/rajandangi/barectl.git
cd barectl
uv sync --locked
npm ci
npm run build
cp .env.example .env
uv run --env-file .env python manage.py migrate
uv run --env-file .env python manage.py createsuperuser
uv run --env-file .env python manage.py runserver 127.0.0.1:8000
```

In a second terminal, as the same account, start the discovery worker. It runs connection checks outside web requests:

```bash
uv run --env-file .env python manage.py db_worker
```

Open http://127.0.0.1:8000 and sign in. `npm run build` compiles the styles, scripts and fonts that Django serves. To edit frontend code with live reloading, run `npm run dev` in another terminal and start Django with `BARECTL_VITE_DEV_SERVER_URL=http://localhost:5173`. See [frontend assets](docs/frontend-assets.md). Use **Add server** to register a server by choosing a `Host` alias from the controller's SSH configuration, `~/.ssh/config` of the account running Barectl unless `BARECTL_SSH_CONFIG` names another file. Keep connection settings, keys and host trust in that configuration; Barectl only reads it. Registration queues a connection check: the worker verifies the server's host key against the controller's known_hosts, authenticates with the controller's keys or agent, and reads the operating system, capacity, web-stack components, convention sites and blocked items without changing the server. Unknown and changed host keys are refused. See [SSH alias registration](docs/ssh-aliases.md) and [SSH connections and discovery](docs/ssh-connections.md).

Each server opens on **Overview**, with **Sites**, **Setup**, **Activity** and **Advanced** sections. Overview shows recorded observations and their collection time; it does not claim live health. See [dashboard workflows](docs/dashboard-workflows.md).

Follow [Host your first PHP site](docs/first-site.md) to prepare hosting, create a PHP site, add an optional database and enable HTTPS. Each action links to its detailed prerequisites, review effects and recovery instructions. For a specific task, see [bootstrap](docs/bootstrap.md), [sites](docs/sites.md), [databases](docs/databases.md) and [TLS](docs/tls.md).

To remove a server, open it and choose **Remove**, then confirm. See [server removal](docs/ssh-connections.md#server-removal) for what is deleted and when removal is refused.

### Operator accounts

`createsuperuser` above creates the operator account. Barectl has no public registration, email password reset or Django admin; manage accounts on the controller host. To reset a forgotten password, run:

```bash
uv run --env-file .env python manage.py changepassword <username>
```

The superuser has every permission. Other accounts need the `servers.view_server` permission to see the inventory, plus `servers.add_server` to register servers, `servers.change_server` to edit them, `servers.delete_server` to remove them and `discovery.add_discoveryattempt` to start a connection check. Reviewing bootstrap plans and their preparations needs `bootstrap.view_configurationplan`, and preparing one also needs `bootstrap.prepare_configurationplan`; inventory access alone never shows plans. The same permission lets an account check the outcome of an apply run that is being reconciled. `bootstrap.apply_configurationplan` applies reviewed metadata refresh, Nginx and PHP profile plans and acknowledges an unknown outcome of such a run, and `bootstrap.clear_native_results` does the same for plans that clear finished bootstrap runs. Site plans have their own permissions, `sites.view_siteplan`, `sites.prepare_siteplan` and `sites.apply_siteplan`; database plans `databases.view_databaseplan`, `databases.prepare_databaseplan` and `databases.apply_databaseplan` ([site databases](docs/databases.md#permissions)); and TLS plans `tls.view_tlsplan`, `tls.prepare_tlsplan` and `tls.apply_tlsplan`, with `tls.issue_certificate` required to apply a production certificate order ([TLS](docs/tls.md#permissions)). WordPress application evidence on a site's page needs `discovery.view_siteapplicationobservation` in addition to `discovery.view_siteobservation` ([WordPress](docs/wordpress.md#passive-application-discovery)), and WordPress installation reviews have `wordpress.view_wordpressplan`, `wordpress.prepare_wordpressplan` and `wordpress.install_wordpress` ([WordPress](docs/wordpress.md#review-permissions)). Bootstrap permissions grant none of these. Barectl has no interface for granting permissions. Inventory is shared among authorized operators; organization isolation is not implemented.

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run --env-file .env mypy
uv run vulture
uv run djlint templates --lint --check
uv run --env-file .env python manage.py check
uv run --env-file .env python manage.py makemigrations --check --dry-run
uv run --env-file .env python manage.py test --exclude-tag browser
npm ci
npm run check
npm run build
uv run playwright install chromium
uv run --env-file .env python manage.py test --tag browser
uv run pip-audit --strict
npm run audit:dependencies
```

Frontend checks use Node 24, selected by `.node-version`, and the Vite+ CLI through `npm run check`. TypeScript, Oxlint and Oxfmt check first-party tooling and browser source; Stylelint checks the Sass theme. The browser tests run Chromium through Playwright against the production build and against a Vite development server they start on a free port. To use a Chromium you already have, set `BARECTL_BROWSER_EXECUTABLE` instead of running `playwright install`. Tests tagged `ssh` run against disposable Ubuntu servers and skip unless one is configured; `docker/disposable-server/run-tests.sh --env-file .env -- <test labels>` runs the ones you name on fresh servers in Docker, and the pull request's `native-ci` label runs them all in CI for both supported releases and records the results on the pushed commit for `main`'s branch protection; see [native suites](docs/quality.md#native-suites). One of them drives Chromium against the production build, so run `npm run build` first. Tests tagged `vm` need a real kernel reboot and run only through `docker/vm-server/run-tests.sh --env-file .env`, which boots Ubuntu's cloud image under QEMU; they are slow and not part of the native suites or CI. See [acceptance against a real server](docs/ssh-connections.md#acceptance-against-a-real-server) and the [v0.2 qualification record](docs/v0.2-qualification.md).

Vulture reports unused Python functions, classes and other symbols. `npm run check` includes Knip for unused JavaScript and TypeScript files, exports and dependencies. Review findings before removing code. Django discovers some hooks dynamically; `vulture_allowlist.py` records those uses. See [dead-code checks and package security](docs/quality.md#dead-code-checks).

## Architecture

See [quality requirements](docs/quality.md) for the enforced Python and template checks, official-source selection policy, and frontend checking requirements.

Django templates, USWDS and HTMX 4 for the interface; application services for workflows; a `db_worker` process from the same codebase for durable discovery, plan preparation and apply jobs; pyinfra's SSH connector for read-only discovery, the SSH integration [reviewed bootstrap](docs/v0.2.md) also uses. Bootstrap reviews and applies metadata refreshes, cleanup of finished runs and the Nginx and PHP profiles. SQLite is the current local database. Future saved SSH connection details and optional shared remote database support require design and verification before release; neither requires a hosted Barectl application.

The managed server is the source of truth. Discovery rebuilds supported state from native evidence when the operator changes computers. Resources match the convention exactly regardless of who created them; non-matching resources are blocked individually. A reviewed Finish plan creates only missing convention resources. See [convention qualification](docs/convention-qualification.md), including the required controller database rebuild.

See [the roadmap](ROADMAP.md), [architecture](docs/architecture.md), [v0.1 acceptance criteria](docs/v0.1.md), [v0.2 bootstrap design](docs/v0.2.md) with its [qualification record](docs/v0.2-qualification.md), [bootstrapping a server](docs/bootstrap.md), and [hosting notes](docs/hosting.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending changes. Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Barectl is the working project name; package and domain registrations are not part of this repository setup.
