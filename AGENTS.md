# Barectl agent instructions

Before changing behavior, read `README.md`, `CONTRIBUTING.md`, the specification that owns the area, and the module map in `docs/architecture.md#module-map`. `docs/architecture.md` describes the implemented foundation and planned architecture; `ROADMAP.md` holds milestone scope.

Specifications are `docs/v0.1.md`, `docs/v0.2.md`, `docs/v0.3.md` and `docs/v0.4.md`, plus the topic documents they name: `docs/bootstrap.md`, `docs/sites.md`, `docs/site-conventions.md`, `docs/databases.md`, `docs/tls.md`, `docs/wordpress.md`, `docs/php-versions.md` and `docs/dashboard-workflows.md`. A specification records accepted design; it does not mean its features are implemented. Each implemented slice's qualification record (for example `docs/v0.2-qualification.md`) names the revision it is tested on and what is not qualified.

## Official guidance first

Before selecting a package or recommending an approach, follow `docs/quality.md#official-guidance-first` and record sources for consequential choices. Use version-matched official documentation: Django 6.1 via `docs/documentation-sources.md`, and the official HTMX 4 agent skills linked in `docs/frontend-assets.md#official-htmx-4-agent-skills`.

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

Use a single root `GLOSSARY.md` and `docs/adr/`, created as terms and decisions are resolved. See `docs/agents/domain.md`.

### Orchestration

Delivering a specification and its sub-issues end to end as an autonomous orchestrator: read `docs/agents/orchestration.md`.

## Development checks

Run the checks in `docs/quality.md#local-commands` before pushing; the pre-push hook runs the fast subset ([before every push](docs/quality.md#before-every-push)). A native-affecting change also needs the native tests it affects, named after `--`, before pushing:

```bash
docker/disposable-server/run-tests.sh --env-file .env -- tls.test_issuance_remote
```

A full local run is `docker/disposable-server/native-check.sh --env-file .env`. After pushing, add the pull request's `native-ci` label so CI records the native statuses. Browser tests need Chromium: `uv run playwright install chromium`, or set `BARECTL_BROWSER_EXECUTABLE`. See [native suites](docs/quality.md#native-suites).

## Project boundaries

- Follow the [core philosophy](README.md#core-philosophy): the managed server is the source of truth. Discovery must reconstruct supported observed state from a fresh controller without the previous Barectl database. Future management must leave servers independently manageable through ordinary Linux tools, without an installed Barectl agent, an external control plane, or a persistent Barectl management server.
- Keep a local database per device by default for Barectl accounts, settings, connections, requests, operation history, and cached server views. Barectl logins are separate from Linux users and SSH permissions. Future saved SSH connection details and an optional shared remote database are planned. Another authorized device must be able to discover and manage the same server without importing or sharing that database. See [state and discovery](docs/architecture.md#state-and-discovery).
- Keep Barectl's own tracking and audit records in its application database, never in custom server-side files, manifests, journals, or management databases. Discover native configuration, service state, and retained logs; do not promise recovery of another device's private records. Cached observations never become fallback authority when native evidence is unavailable.
- Future background operations and coordination across devices must use native Linux facilities or established, widely used packages verified against upstream guidance, without a Barectl agent. A local database lock cannot coordinate independent controllers. Block conflicting changes until fresh discovery and review; refuse them when reliable coordination is unavailable. See [management from multiple devices](docs/architecture.md#management-from-multiple-devices).
- Provisioning must use one documented standard configuration convention per supported distribution and stack, with reconstruction tests from a fresh controller. Discovery must derive resources and relationships from current server evidence, including external changes, without importing another controller's inventory or reading custom Barectl manifests from the server. See [standard configuration and reconstruction](docs/architecture.md#standard-configuration-and-reconstruction).
- Follow `docs/quality.md`: strict Python typing, TypeScript and JavaScript checks, type-aware Oxlint through Vite+, CSS linting, template checks, dependency audits, and runtime validation at external boundaries. Keep Vite assets covered by the frontend checks; do not weaken checks to silence errors.
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
