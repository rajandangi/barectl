# Barectl agent instructions

Read `README.md`, `CONTRIBUTING.md`, and the relevant specification before changing behavior.
`docs/architecture.md` describes the implemented foundation and planned architecture.
`docs/v0.1.md` contains the discovery milestone's acceptance criteria; it does not mean those features are implemented.

## Official guidance first

Before selecting a package or recommending an approach, check the relevant framework's official documentation, then the package maintainers' documentation and compatibility guidance. Follow documented best practices for the versions in use. Record source links for consequential choices and distinguish upstream recommendations from Barectl-specific judgments. A third-party package's own documentation is not a framework endorsement. Do not select tools from memory or search snippets alone; identify gaps when no official recommendation exists.

For Django, use the version-matched official docs at `https://docs.djangoproject.com/en/6.1/` and the installed release's notes. See `docs/documentation-sources.md`. No official Django documentation MCP has been verified; do not present community servers as official or add application-access MCP tools merely to retrieve documentation.

For HTMX 4 work, consult the official versioned agent skills linked in `docs/frontend-assets.md#official-htmx-4-agent-skills`. Use the core guidance for implementation, debugging guidance for failures, and extension or migration guidance only when relevant.

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

## Project boundaries

- Follow `docs/quality.md`: strict Python typing, TypeScript and JavaScript checks, type-aware ESLint, CSS linting, template checks, dependency audits, and runtime validation at external boundaries. Extend the existing frontend checks with the Vite implementation; do not weaken checks to silence errors.
- Run Vulture and Knip for dead-code detection. Review Django/template uses before removing a reported symbol. Keep `vulture_allowlist.py` explicit and explained; do not raise the confidence threshold or add blanket ignores to hide findings. Register actual frontend entry files in Knip when adding browser assets.
- Build a Django monolith, currently pinned to Django 6.1.1. Keep remote operations behind application services and infrastructure adapters.
- Require Python 3.14 or newer. Keep the development pin, CI and analysis targets on Python 3.14; do not add compatibility work for older Python versions.
- The custom Barectl dashboard will own all operator workflows. Remove Django admin entirely as part of that milestone; it currently still provides inventory forms. Keep Django authentication for the custom interface. See `docs/dashboard-plan.md` for confirmed design decisions and open questions.
- Use USWDS for the design system and Django templates with HTMX 4 for interactions. USWDS replaces the earlier Tailwind direction. Frontend dependencies are exact pins; `docs/frontend-assets.md` records the versions, sources and the USWDS/HTMX lifecycle contract. Verify upstream guidance before changing a pin.
- Apply Barectl's color palette through the USWDS theme. Use the semantic colors recorded in `docs/design-palette.md`.
- Use Inter for Barectl's English interface and Vite for the asset pipeline. Templates load assets with `{% vite_entry %}`; never link built files by hand. See `docs/frontend-assets.md` for typography and Django integration.
- Keep SSH credentials on the controller host, accessed through its SSH agent or key files. Do not add browser private-key uploads or application database storage for SSH secrets in v0.1.
- SSH execution, pyinfra integration, durable jobs, and provisioning remain planned work.
- Never commit `.env`, local databases, SSH credentials, or private server inventories.

## Public documentation

Keep personal filesystem paths, private project names, internal source references and proprietary implementation details out of the repository. Describe approved design choices as Barectl requirements. Preserve required third-party license notices and public repository identifiers.
