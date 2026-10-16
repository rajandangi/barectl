<h1>
  <img src="static/brand/barectl-wordmark.svg" alt="Barectl" width="480">
</h1>

An open-source, agentless control plane for reconstructing, managing, and provisioning Linux web servers over SSH.

Barectl is intended for developers and agencies running PHP applications on their own servers. Run the local-first dashboard on your computer or a private management host. Managed servers use ordinary native software, with no Barectl agent or container requirement.

## Core philosophy

The server is the source of truth. Barectl can disappear today, and the server remains a normal, independently manageable Linux server. Managing it must not depend on an external service, a proprietary management database, or a persistent Barectl management server.

The goal is to connect from any computer with Barectl and authorized SSH access and reconstruct an accurate inventory of the server's websites, applications, databases, PHP-FPM pools, systemd services, SSL certificates, queues, users, and infrastructure configuration. Reconstruction must work without the previous Barectl installation's database. Discovery reports what it can verify and identifies inaccessible or unsupported configuration.

Barectl should provision each supported stack in one documented, consistent way, following the distribution's and services' standard conventions. Discovery must understand the resulting configuration and relationships directly from the server. Barectl must not add its own tracking files, inventory manifests, audit journals, or management database to the server. Each discovery cycle must reflect current server configuration, including changes made outside Barectl.

The planned dashboard covers the full application lifecycle: provisioning sites, deploying Laravel and WordPress applications, managing databases and services, configuring PHP and the web server, updating packages, inspecting logs, managing queues and certificates, and maintaining server infrastructure. Barectl aims to offer the convenience and visibility of platforms such as Laravel Forge while remaining self-hosted, portable, agentless, and independent of an external control plane.

By default, each device runs Barectl with its own local database for its application login, preferences, saved connections, discovery snapshots, queued requests, and operation history. Saved non-secret SSH connection definitions and their immutable revisions are stored locally. The Barectl login is separate from server users and permissions; SSH determines access to the server. Server-derived information remains a cached view of native evidence. Barectl's own operation history stays in its application database and never overrides the server's actual configuration or execution state.

The same server should be manageable from multiple devices with the convenience of a hosted dashboard. A new device needs authorized SSH access and discovery, with no database transfer, synchronization, or central Barectl service required. Discovery rebuilds supported server views and available native history. It cannot recover another device's private Barectl records or native history the server no longer retains. Operators may choose an optional remote database to share Barectl records across local installations; it does not become the source of truth for server state.

Future long-running operations accepted by the server and server schedules should continue when Barectl disconnects. Execution and coordination must use native Linux facilities or established, widely used packages verified against upstream guidance. A conflicting change must wait for fresh discovery and operator review. If reliable coordination is unavailable, Barectl must not allow conflicting changes to proceed as though they were safe. These are product requirements; the current implementation is listed below.

## Current status

Barectl manages fresh Ubuntu 26.04 LTS servers on amd64 and arm64 on one stack: Caddy, runtimes from a pinned Nix catalog, and a private HAProxy process and PHP-FPM master per site ([target architecture](docs/target-architecture.md)). Phase A of the [roadmap](ROADMAP.md) is implemented on `main` and not yet released; its [qualification record](docs/phase-a-qualification.md) names the tested revision and what is not qualified. The last releases, [v0.2.0 and v0.3.0](https://github.com/rajandangi/barectl/releases), managed the earlier Nginx, Certbot and APT PHP stack, which has been deleted.

- **Add a server** with a saved connection: address, SSH user, port and this computer's SSH agent or an approved key file. An unknown host key is trusted only when it matches the fingerprint the operator pastes from the provider's console ([saved server connections](docs/saved-server-connections.md)).
- **Host standing**: every discovery judges the server as a Fresh host, an Incomplete foundation, a Target stack or Not manageable, with named reasons. Servers with another web stack, APT PHP or a hosting panel, including servers set up by earlier Barectl builds, are read but never changed.
- **Set up server** installs the pinned Nix, Caddy and the foundation's tools, and makes the journal persistent, as one reviewed native run ([setting up a server](docs/bootstrap.md)).
- **Runtimes**: add PHP 8.4, PHP 8.5, Node.js 22 and Node.js 24, and choose the server's default commands ([runtimes](docs/runtimes.md), [server defaults](docs/runtime-defaults.md)).
- **Sites**: create plain PHP sites over HTTP, each with its own Linux account, PHP-FPM master, private HAProxy admission and Caddy site file; switch a site's PHP runtime without dropped requests and choose its Node runtime ([creating a PHP site](docs/sites.md), [site convention](docs/site-conventions.md)).
- **Reconstruction**: a fresh controller with its own database and credentials rebuilds the foundation, runtimes, defaults and sites from the server alone.

Every change is prepared, reviewed and applied through one change engine. Accepted changes run as transient systemd units under one native lock, continue without the controller, and are reconciled from native evidence ([dashboard workflows](docs/dashboard-workflows.md)). HTTPS, databases, WordPress, Laravel, automation and backups are later phases; `main` has no HTTPS, WordPress or database workflows until Phase B. [Native recovery](docs/recovery.md) describes how to inspect and repair a server with ordinary Linux tools.

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

Barectl keeps no migration history from earlier builds: if you ran an earlier build, delete `db.sqlite3` and run `migrate` again.

Open http://127.0.0.1:8000 and sign in. `npm run build` compiles the styles, scripts and fonts that Django serves. To edit frontend code with live reloading, run `npm run dev` in another terminal and start Django with `BARECTL_VITE_DEV_SERVER_URL=http://localhost:5173`. See [frontend assets](docs/frontend-assets.md). Use **Add server** to enter a display name, address, SSH user and port, then **Save and check**. Saved addresses use the worker's SSH agent or an administrator-approved key file, with default key-file search and forwarding disabled. The worker checks host trust against the controller file named by `BARECTL_SSH_KNOWN_HOSTS`, then reads the host's standing without changing the server. Unknown, changed and revoked host keys are refused before authentication. For an unknown saved host, paste the exact SHA256 fingerprint obtained independently from the provider console to confirm its identity and continue the check. Changed and revoked keys remain hard refusals. An advanced SSH alias remains available from `~/.ssh/config`, or `BARECTL_SSH_CONFIG`; it uses that alias's configured credentials and trust. See [saved server connections](docs/saved-server-connections.md) and [SSH connections and discovery](docs/ssh-connections.md).

Each server opens on **Overview**, with **Sites**, **Stack**, **Setup**, **Changes**, **Activity** and **Advanced** sections. Overview shows recorded observations and their collection time; it does not claim live health. On a Fresh host, follow **Set up server**, then add a PHP runtime from **Stack** and create a site from **Sites**. See [host your first PHP site](docs/first-site.md) and [dashboard workflows](docs/dashboard-workflows.md).

To remove a server, open it and choose **Remove**, then confirm. See [server removal](docs/ssh-connections.md#server-removal) for what is deleted and when removal is refused.

### Operator accounts

`createsuperuser` above creates the operator account. Barectl has no public registration, email password reset or Django admin; manage accounts on the controller host. To reset a forgotten password, run:

```bash
uv run --env-file .env python manage.py changepassword <username>
```

The initial migrations create the **Viewer**, **Site operator** and **Administrator** groups. Assign a preset from the controller host's Django shell:

```python
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

user = get_user_model().objects.get(username="operator")
user.groups.add(Group.objects.get(name="Site operator"))
```

| Preset | Permissions | Allows |
| --- | --- | --- |
| Viewer | `servers.view_server`, `operations.view_changes` | Servers, reviews and runs |
| Site operator | The above and `operations.change_site` | Preparing any change, and applying Site changes such as a site's PHP or Node selection |
| Administrator | The above and `operations.change_shared`, `operations.change_destructive`, `operations.manage_secrets` | Applying Shared changes such as Set up server, Add runtime, server defaults and site creation beside other sites |

The superuser has every permission. Registering, editing and removing servers need `servers.add_server`, `servers.change_server` and `servers.delete_server`, starting a connection check needs `discovery.add_discoveryattempt`, and seeing sites needs `discovery.view_siteobservation`; the presets grant none of these. Barectl has no interface for granting permissions. Inventory is shared among authorized operators; organization isolation is not implemented.

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run --env-file .env mypy
uv run vulture
uv run djlint templates --lint --check
uv run --env-file .env python manage.py check
uv run --env-file .env python manage.py makemigrations --check --dry-run
uv run --env-file .env python manage.py test --exclude-tag browser --exclude-tag scenario
npm ci
npm run check
npm run build
uv run playwright install chromium
uv run --env-file .env python manage.py test --tag browser
uv run pip-audit --strict
npm run audit:dependencies
```

Frontend checks use Node 24, selected by `.node-version`, and the Vite+ CLI through `npm run check`. TypeScript, Oxlint and Oxfmt check first-party tooling and browser source; Stylelint checks the Sass theme. The browser tests run Chromium through Playwright against the production build and against a Vite development server they start on a free port. To use a Chromium you already have, set `BARECTL_BROWSER_EXECUTABLE` instead of running `playwright install`. The native scenarios run offline on real servers: `docker/disposable-server/run-scenarios.sh --env-file .env`, and the `Native` workflow runs the required `native` check on every pull request. One of the browser tests drives Chromium against the production build, so run `npm run build` first. See [native layer](docs/quality.md#native-layer).

Vulture reports unused Python functions, classes and other symbols. `npm run check` includes Knip for unused JavaScript and TypeScript files, exports and dependencies. Review findings before removing code. Django discovers some hooks dynamically; `vulture_allowlist.py` records those uses. See [dead-code checks and package security](docs/quality.md#dead-code-checks).

## Architecture

See [quality requirements](docs/quality.md) for the enforced Python and template checks, official-source selection policy, and frontend checking requirements.

Django templates, USWDS and HTMX 4 for the interface; application services for workflows; a `db_worker` process from the same codebase for durable discovery, change preparation and apply jobs; pyinfra's SSH connector for every connection to a server. SQLite is the local database. Optional shared remote database support needs design and verification before release and never requires a hosted Barectl application.

The managed server is the source of truth. Discovery rebuilds supported state from native evidence when the operator changes computers. Resources that match the convention are managed whoever created them; a setting Barectl does not interpret is reported once and blocks only the changes that depend on it.

See [the roadmap](ROADMAP.md), the [target architecture](docs/target-architecture.md), [architecture](docs/architecture.md) with its module map, and [hosting notes](docs/hosting.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending changes. Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Barectl is the working project name; package and domain registrations are not part of this repository setup.
