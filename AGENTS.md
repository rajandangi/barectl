# Barectl agent instructions

Read `README.md`, `CONTRIBUTING.md`, and the relevant specification before changing behavior.
`docs/architecture.md` describes the implemented foundation and planned architecture.
`docs/v0.1.md` contains the discovery milestone's acceptance criteria; it does not mean those features are implemented.
`docs/v0.2.md` specifies reviewed bootstrap, released as v0.2.0. `docs/bootstrap.md` describes current operator behavior, and `docs/v0.2-qualification.md` records the revisions it is qualified on and what is not qualified.

`docs/v0.3.md` is the accepted PHP sites specification; site reconstruction with its database bindings, site creation (`docs/sites.md`), the MariaDB and PostgreSQL bootstrap profiles, the PHP database drivers and MariaDB and PostgreSQL site databases (`docs/databases.md`), renewal exclusion, Certbot renewal setup and the HTTP-01 challenge route (`docs/tls.md`) are implemented. `docs/site-conventions.md` defines its native layout; `docs/v0.3-decisions.md` records the design choices and sources, and `docs/v0.3-qualification.md` the revisions each implemented slice is qualified on.

## Official guidance first

Before selecting a package or recommending an approach, check the relevant framework's official documentation, then the package maintainers' documentation and compatibility guidance. Follow documented best practices for the versions in use. Record source links for consequential choices and distinguish upstream recommendations from Barectl-specific judgments. A third-party package's own documentation is not a framework endorsement. Do not select tools from memory or search snippets alone; identify gaps when no official recommendation exists.

For Django, use the version-matched official docs at `https://docs.djangoproject.com/en/6.1/` and the installed release's notes. See `docs/documentation-sources.md`. No official Django documentation MCP has been verified; do not present community servers as official or add application-access MCP tools merely to retrieve documentation.

For HTMX 4 work, consult the official versioned agent skills linked in `docs/frontend-assets.md#official-htmx-4-agent-skills`. Use the core guidance for implementation, debugging guidance for failures, and extension or migration guidance only when relevant.

## Reuse existing tools first

Before implementing infrastructure behavior, check the existing repository code and the official documentation for pyinfra and the relevant native tools. Prefer supported upstream operations and established packages over custom installers, configuration engines, certificate clients, or renewal schedulers. For TLS, Certbot owns certificate issuance and renewal; check pyinfra's operations and deploy composition before writing provisioning logic.

Custom code must address a specific requirement that the existing tools cannot meet. Record the requirement, the alternatives checked, official source links, and the reason for the gap in the relevant GitHub issue before adding a new mechanism. Keep custom code limited to the missing behavior and Barectl's operator workflow. Do not duplicate upstream behavior merely to control its implementation.

Reuse must preserve the documented SSH execution boundary, native locking, and controller-independent server state. If an existing architecture decision prevents suitable reuse, review that decision explicitly rather than adding a parallel execution path. Apply this check when fixing or extending existing custom code as well as when adding features.

## Agent skills

### Issue tracker

Track specs and implementation tickets in GitHub Issues at `rajandangi/barectl`. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels. See `docs/agents/triage-labels.md`.

### Domain docs

Use a single root `CONTEXT.md` and `docs/adr/`, created as terms and decisions are resolved. See `docs/agents/domain.md`.

## Development checks

Run from the repository root with the local `.env` configured as described in the README:

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
uv run --env-file .env python manage.py test --tag browser
uv run pip-audit --strict
npm run audit:dependencies
```

Browser tests need Chromium: run `uv run playwright install chromium`, or set `BARECTL_BROWSER_EXECUTABLE` to an installed Chromium.

The pre-push hook runs the fast checks only. Complete the checks above locally before pushing. For a change to a native-affecting path, also run the native suites locally for both supported Ubuntu releases before pushing:

```bash
docker/disposable-server/run-tests.sh --env-file .env
```

Fix failures and repeat the affected local checks before pushing. Do not use GitHub CI to experiment with unverified changes. After local validation and push, record the required native commit statuses with the command below, or use the pull request's `native-ci` label for verification. See [native suites](docs/quality.md#native-suites).

```bash
docker/disposable-server/native-check.sh --env-file .env
```

## Project boundaries

- Follow the [core philosophy](README.md#core-philosophy): the managed server is the source of truth. Discovery must reconstruct supported observed state from a fresh controller without the previous Barectl database. Future management must leave servers independently manageable through ordinary Linux tools, without an installed Barectl agent, an external control plane, or a persistent Barectl management server.
- Keep a local database per device by default for Barectl accounts, settings, connections, requests, operation history, and cached server views. Barectl logins are separate from Linux users and SSH permissions. Future saved SSH connection details and an optional shared remote database are planned. Another authorized device must be able to discover and manage the same server without importing or sharing that database. See [state and discovery](docs/architecture.md#state-and-discovery).
- Keep Barectl's own tracking and audit records in its application database, never in custom server-side files, manifests, journals, or management databases. Discover native configuration, service state, and retained logs; do not promise recovery of another device's private records. Cached observations never become fallback authority when native evidence is unavailable.
- Future background operations and coordination across devices must use native Linux facilities or established, widely used packages verified against upstream guidance, without a Barectl agent. A local database lock cannot coordinate independent controllers. Block conflicting changes until fresh discovery and review; refuse them when reliable coordination is unavailable. See [management from multiple devices](docs/architecture.md#management-from-multiple-devices).
- Provisioning must use one documented standard configuration convention per supported distribution and stack, with reconstruction tests from a fresh controller. Discovery must derive resources and relationships from current server evidence, including external changes, without importing another controller's inventory or reading custom Barectl manifests from the server. See [standard configuration and reconstruction](docs/architecture.md#standard-configuration-and-reconstruction).
- Follow `docs/quality.md`: strict Python typing, TypeScript and JavaScript checks, type-aware ESLint, CSS linting, template checks, dependency audits, and runtime validation at external boundaries. Keep Vite assets covered by the frontend checks; do not weaken checks to silence errors.
- Run Vulture and Knip for dead-code detection. Review Django/template uses before removing a reported symbol. Keep `vulture_allowlist.py` explicit and explained; do not raise the confidence threshold or add blanket ignores to hide findings. Register actual frontend entry files in Knip when adding browser assets.
- Build a Django monolith, currently pinned to Django 6.1.1. Keep remote operations behind application services and infrastructure adapters.
- Require Python 3.14 or newer. Keep the development pin, CI and analysis targets on Python 3.14; do not add compatibility work for older Python versions.
- The custom Barectl dashboard owns all operator workflows. Django admin is not installed; do not reintroduce it or any other admin fallback. Keep Django authentication and permissions for the custom interface, with terminal-based account creation and password recovery (`createsuperuser`, `changepassword`). See `docs/dashboard-plan.md` for confirmed design decisions.
- Use USWDS for the design system and Django templates with HTMX 4 for interactions. Frontend dependencies are exact pins; `docs/frontend-assets.md` records the versions, sources and the USWDS/HTMX lifecycle contract. Verify upstream guidance before changing a pin.
- Apply Barectl's color palette through the USWDS theme. Use the semantic colors recorded in `docs/design-palette.md`.
- Use Inter for Barectl's English interface and Vite for the asset pipeline. Templates load assets with `{% vite_entry %}`; never link built files by hand. See `docs/frontend-assets.md` for typography and Django integration.
- Keep SSH credentials on the controller host, accessed through its SSH agent or key files. Do not add browser private-key uploads or application database storage for SSH secrets in v0.1.
- Read-only SSH discovery, plan preparation and bootstrap apply run in the `db_worker` process through `discovery/ssh.py` (`docs/ssh-connections.md`); keep remote execution behind that boundary. It connects through pyinfra's SSH connector, the one SSH execution integration. Apply submits fixed native payloads to transient systemd units under the shared native lock (`docs/adr/0006-use-native-bootstrap-execution.md`); do not add another execution path.
- Never commit `.env`, local databases, SSH credentials, or private server inventories.

## Code comments

Comment only business logic the code cannot make clear. Do not restate what code does, narrate steps or repeat names. Business rules belong in `docs/adr/` and the other Markdown docs; a necessary comment points to the owning document instead of explaining the rule again. See [code comments](docs/quality.md#code-comments).

## Public documentation

Keep personal filesystem paths, private project names, internal source references and proprietary implementation details out of the repository. Describe approved design choices as Barectl requirements. Preserve required third-party license notices and public repository identifiers.
