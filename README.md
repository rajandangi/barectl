<h1>
  <img src="static/brand/barectl-wordmark.svg" alt="Barectl" width="480">
</h1>

An open-source, self-hostable Django application for managing native Linux web servers over SSH.

Barectl is intended for developers and agencies running PHP, WordPress, and Laravel on their own servers. Run the control application on your computer or a private management host. Managed servers will use standard Linux packages, with no Barectl agent or container requirement.

## Current status

Early development, version 0.0.1. This repository contains a runnable Django 6.1.1 foundation, a Barectl-branded USWDS sign-in page, Servers page and Activity page, permission-protected server inventory with search, server registration by controller SSH alias and confirmed removal, verified SSH connections with an operating system and capacity snapshot (architecture, CPUs, memory and root filesystem), component observations (Nginx, PHP-FPM, MariaDB and PostgreSQL package versions and systemd service states), Nginx site file and PHP-FPM pool observations, per-server discovery history and cross-server Activity, and CI. It does **not yet** provision anything; that is planned, not released. Barectl never stores SSH credentials: it uses the controller host's SSH agent or key files.

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

To remove a server, open it and choose **Remove**, then confirm. See [server removal](docs/ssh-connections.md#server-removal) for what is deleted and when removal is refused.

### Operator accounts

`createsuperuser` above creates the operator account. Barectl has no public registration, email password reset or Django admin; manage accounts on the controller host. To reset a forgotten password, run:

```bash
uv run --env-file .env python manage.py changepassword <username>
```

The superuser has every permission. Other accounts need the `servers.view_server` permission to see the inventory, plus `servers.add_server` to register servers, `servers.change_server` to edit them, `servers.delete_server` to remove them and `discovery.add_discoveryattempt` to start a connection check. Barectl has no interface for granting permissions. Inventory is shared among authorized operators; organization isolation is not implemented.

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

Frontend checks use Node 24, selected by `.nvmrc`. TypeScript and ESLint check first-party tooling and browser source; Stylelint checks the Sass theme. The browser tests run Chromium through Playwright against the production build and against a Vite development server they start on a free port. To use a Chromium you already have, set `BARECTL_BROWSER_EXECUTABLE` instead of running `playwright install`. Tests tagged `ssh` run against a disposable Ubuntu 24.04 server and skip unless one is configured; see [acceptance against a real server](docs/ssh-connections.md#acceptance-against-a-real-server).

Vulture reports unused Python functions, classes and other symbols. `npm run check` includes Knip for unused JavaScript and TypeScript files, exports and dependencies. Review findings before removing code. Django discovers some hooks dynamically; `vulture_allowlist.py` records those uses. See [dead-code checks and package security](docs/quality.md#dead-code-checks).

## Architecture

See [quality requirements](docs/quality.md) for the enforced Python and template checks, official-source selection policy, and frontend checking requirements.

Django templates, USWDS and HTMX 4 for the interface; application services for workflows; a `db_worker` process from the same codebase for durable discovery jobs; paramiko for read-only discovery. pyinfra is planned for later changes over SSH. SQLite is the initial database. Hosted credential storage and PostgreSQL support will be designed before team deployments.

The managed server is the source of truth. Discovery should rebuild observed state from an existing server when the operator changes computers. Unknown configuration must be reported without silently adopting or overwriting it.

See [the roadmap](ROADMAP.md), [architecture](docs/architecture.md), [v0.1 acceptance criteria](docs/v0.1.md), and [hosting notes](docs/hosting.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending changes. Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Barectl is the working project name; package and domain registrations are not part of this repository setup.
