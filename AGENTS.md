# Barectl agent instructions

Read `README.md`, `CONTRIBUTING.md`, and the relevant specification before changing behavior.
`docs/architecture.md` describes the implemented foundation and planned architecture.
`docs/v0.1.md` contains the discovery milestone's acceptance criteria; it does not mean those features are implemented.

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
uv run --env-file .env python manage.py check
uv run --env-file .env python manage.py makemigrations --check --dry-run
uv run --env-file .env python manage.py test
```

## Project boundaries

- Build a Django monolith. Keep remote operations behind application services and infrastructure adapters.
- The custom Barectl dashboard will own normal operator workflows. Django admin currently provides inventory forms; complete removal of admin is undecided.
- HTMX and Tailwind are intended frontend dependencies but are not installed. Confirm versions when implementing the frontend.
- SSH execution, pyinfra integration, durable jobs, and provisioning remain planned work.
- Never commit `.env`, local databases, SSH credentials, or private server inventories.
