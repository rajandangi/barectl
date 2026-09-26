# Frontend typography and asset build

## English typography

Use Inter for Barectl's English interface.

```css
font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif;
```

Use regular 400, medium 500, semibold 600, and bold 700. Serve variable WOFF2 files for Latin and Latin Extended, with normal style, a weight range of 400 to 700, and `font-display: swap`.

Serve these font assets from Barectl rather than relying on runtime requests to a font CDN. Preserve the accompanying Inter OFL license when adding the assets. Configure USWDS body and heading typography to use this English UI family while retaining its component structure and the palette in `docs/design-palette.md`.

## HTMX 4 requirement

Use HTMX 4, with `htmx.org@4.0.0` as the confirmed release baseline. Install an explicitly selected stable 4.x version with an exact package pin and lockfile when implementing the frontend. Verify any newer patch against upstream release notes; do not use an unqualified npm install or rely on the `latest` tag to select the major version.

The [official HTMX 4.0.0 announcement](https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released) confirms the release and explains that npm's `latest` tag remains on 2.x for now. Use the [HTMX 4 documentation](https://four.htmx.org/docs/).

Test explicit attribute inheritance, including CSRF headers; HTMX 4 event names for USWDS initialization and cleanup; and history navigation with authenticated Django responses. Include repeated fragment updates and production-built assets. Do not copy HTMX 2 lifecycle handlers or assume extensions support version 4 without checking their maintainers' guidance.

HTMX 4 is a required frontend implementation dependency, not installed functionality in the current foundation. The first frontend ticket owns installation and Vite integration.

### Official HTMX 4 agent skills

The [release announcement's LLM section](https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released#llms) links these versioned upstream resources:

- [htmx-guidance](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-guidance.md): developing HTMX 4 interfaces.
- [htmx-debugging](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-debugging.md): investigating HTMX behavior.
- [htmx-extension-authoring](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-extension-authoring.md): implementing extensions when needed.
- [htmx-upgrade-from-htmx2](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-upgrade-from-htmx2.md): identifying version-2 assumptions during migration or review. Barectl targets HTMX 4 only.

These are reference links, not installed local skills. Consult the relevant resource for HTMX work and check for matching guidance if the pinned package version changes.

## Vite build direction

Vite is the selected frontend build tool. Django does not require it, but it provides an asset pipeline for the chosen Sass theme, JavaScript components, and font files.

During frontend implementation:

- Extend the existing `package.json` and npm lockfile with the asset-build dependencies.
- Write first-party browser code in strict TypeScript. The independent type-check command, type-aware ESLint, and CSS linting are already configured; extend them for Sass as described in `docs/quality.md`. Vite bundling alone does not type-check.
- Use Vite with a Sass compiler and the USWDS package load paths and CSS processing requirements.
- Bundle the USWDS component JavaScript and HTMX 4, and build the Barectl USWDS theme with the selected palette and Inter font.
- Keep required early USWDS initialization separate where the upstream loading guidance requires it.
- In development, integrate the Vite development server with Django-rendered templates.
- In production, resolve entry points and their CSS dependencies through Vite's generated manifest. Serve the compiled assets through the configured static file deployment, without requiring a Vite server at runtime.
- Test production asset resolution and HTMX 4 component lifecycle handling. Development hot reload alone is not sufficient validation.

Reference: [Vite backend integration](https://vite.dev/guide/backend-integration.html).

## Django baseline

Barectl is pinned to Django **6.1.1** in `pyproject.toml` and `uv.lock`. The official download page and PyPI confirmed this release when the requirement was added. Existing tests, lint, formatting, Django checks, and migration consistency checks pass after the upgrade.

References: [Django downloads](https://www.djangoproject.com/download/), [Django 6.1.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1.1/).

The frontend checking tools are installed. Vite, USWDS, and Inter remain recorded implementation requirements; they have not yet been installed or applied to the current dashboard.
