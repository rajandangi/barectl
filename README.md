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

Version 0.2.0, the first public release. This repository contains a runnable Django 6.1.1 foundation, a Barectl-branded USWDS sign-in page, Servers page and Activity page, permission-protected server inventory with search, server registration by controller SSH alias and confirmed removal, verified SSH connections with an operating system and capacity snapshot (architecture, CPUs, memory and root filesystem), component observations (Nginx, PHP-FPM, MariaDB and PostgreSQL package versions and systemd service states), Nginx site file and PHP-FPM pool observations, PHP sites reconstructed from native evidence against the [native site convention](docs/site-conventions.md) for accounts allowed to view them, per-server discovery history and cross-server Activity, and CI. It also bootstraps Ubuntu 24.04 and 26.04 servers with the distribution's Nginx, or PHP FPM and CLI, version 8.3 on 24.04 and 8.5 on 26.04, after the operator reviews the exact package and service change, refreshes package metadata as its own reviewed action, and runs each change as a native systemd unit that continues without the controller; see [bootstrapping a server](docs/bootstrap.md). The [qualification record](docs/v0.2-qualification.md) defines the tested environments and remaining limits of this release. Barectl does **not yet** create sites or provision applications, which is planned, not released. The current release stores no SSH credentials: it uses the controller host's SSH agent or key files.

The current implementation stores dashboard accounts, discovery jobs, plans, apply runs and their audit in its local Django database. Discovery covers the observations listed above. Bootstrap runs are coordinated across controllers and SSH aliases by one native lock on the server, and continue under the server's systemd when the controller stops; discovery attempts and plan preparations depend on the controller's worker and do not. Native server history views, locally saved SSH connection details and optional remote database support remain planned work.

## Run locally

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), Python 3.14 or newer, and Node 24 (selected by `.nvmrc`). Development and CI use Python 3.14. Older Python versions are unsupported.

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

Open http://127.0.0.1:8000 and sign in. `npm run build` compiles the styles, scripts and fonts that Django serves. To edit frontend code with live reloading, run `npm run dev` in another terminal and start Django with `BARECTL_VITE_DEV_SERVER_URL=http://localhost:5173`. See [frontend assets](docs/frontend-assets.md). Use **Add server** to register a server by choosing a `Host` alias from the controller's SSH configuration, `~/.ssh/config` of the account running Barectl unless `BARECTL_SSH_CONFIG` names another file. Keep connection settings, keys and host trust in that configuration; Barectl only reads it. Registration queues a connection check: the worker verifies the server's host key against the controller's known_hosts, authenticates with the controller's keys or agent, and reads the operating system, capacity, web-stack components, Nginx site files and PHP-FPM pools without changing the server. Unknown and changed host keys are refused. See [SSH alias registration](docs/ssh-aliases.md) and [SSH connections and discovery](docs/ssh-connections.md).

To install Nginx or PHP (8.3 on Ubuntu 24.04, 8.5 on Ubuntu 26.04) on an Ubuntu 24.04 or 26.04 server, open it and prepare a plan in **Bootstrap plans**; read [bootstrapping a server](docs/bootstrap.md) first for the prerequisites, the privileges it needs and what to expect.

To remove a server, open it and choose **Remove**, then confirm. See [server removal](docs/ssh-connections.md#server-removal) for what is deleted and when removal is refused.

### Operator accounts

`createsuperuser` above creates the operator account. Barectl has no public registration, email password reset or Django admin; manage accounts on the controller host. To reset a forgotten password, run:

```bash
uv run --env-file .env python manage.py changepassword <username>
```

The superuser has every permission. Other accounts need the `servers.view_server` permission to see the inventory, plus `servers.add_server` to register servers, `servers.change_server` to edit them, `servers.delete_server` to remove them and `discovery.add_discoveryattempt` to start a connection check. Reviewing bootstrap plans and their preparations needs `bootstrap.view_configurationplan`, and preparing one also needs `bootstrap.prepare_configurationplan`; inventory access alone never shows plans. The same permission lets an account check the outcome of an apply run that is being reconciled. `bootstrap.apply_configurationplan` applies reviewed metadata refresh, Nginx and PHP profile plans and acknowledges an unknown outcome of such a run, and `bootstrap.clear_native_results` does the same for plans that clear finished bootstrap runs. Barectl has no interface for granting permissions. Inventory is shared among authorized operators; organization isolation is not implemented.

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

Frontend checks use Node 24, selected by `.nvmrc`. TypeScript and ESLint check first-party tooling and browser source; Stylelint checks the Sass theme. The browser tests run Chromium through Playwright against the production build and against a Vite development server they start on a free port. To use a Chromium you already have, set `BARECTL_BROWSER_EXECUTABLE` instead of running `playwright install`. Tests tagged `ssh` run against a disposable Ubuntu 24.04 server and skip unless one is configured; `docker/disposable-server/native-check.sh --env-file .env` creates one of each supported release in Docker, runs them in parallel and records the results on the pushed commit for `main`'s branch protection; see [native suites](docs/quality.md#native-suites). One of them drives Chromium against the production build, so run `npm run build` first. Tests tagged `vm` need a real kernel reboot and run only through `docker/vm-server/run-tests.sh --env-file .env`, which boots Ubuntu's cloud image under QEMU; they are slow and not part of the native suites or CI. See [acceptance against a real server](docs/ssh-connections.md#acceptance-against-a-real-server) and the [v0.2 qualification record](docs/v0.2-qualification.md).

Vulture reports unused Python functions, classes and other symbols. `npm run check` includes Knip for unused JavaScript and TypeScript files, exports and dependencies. Review findings before removing code. Django discovers some hooks dynamically; `vulture_allowlist.py` records those uses. See [dead-code checks and package security](docs/quality.md#dead-code-checks).

## Architecture

See [quality requirements](docs/quality.md) for the enforced Python and template checks, official-source selection policy, and frontend checking requirements.

Django templates, USWDS and HTMX 4 for the interface; application services for workflows; a `db_worker` process from the same codebase for durable discovery, plan preparation and apply jobs; pyinfra's SSH connector for read-only discovery, the SSH integration [reviewed bootstrap](docs/v0.2.md) also uses. Bootstrap reviews and applies metadata refreshes, cleanup of finished runs and the Nginx and PHP profiles. SQLite is the current local database. Future saved SSH connection details and optional shared remote database support require design and verification before release; neither requires a hosted Barectl application.

The managed server is the source of truth. Discovery should rebuild observed state from an existing server when the operator changes computers. Unknown configuration must be reported without silently adopting or overwriting it.

See [the roadmap](ROADMAP.md), [architecture](docs/architecture.md), [v0.1 acceptance criteria](docs/v0.1.md), [v0.2 bootstrap design](docs/v0.2.md) with its [qualification record](docs/v0.2-qualification.md), [bootstrapping a server](docs/bootstrap.md), and [hosting notes](docs/hosting.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending changes. Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Barectl is the working project name; package and domain registrations are not part of this repository setup.
