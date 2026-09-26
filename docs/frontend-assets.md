# Frontend typography and asset build

## English typography

Use Inter for Barectl's English interface.

```css
font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif;
```

Use regular 400, medium 500, semibold 600, and bold 700. Serve variable WOFF2 files for Latin and Latin Extended, with normal style, a weight range of 400 to 700, and `font-display: swap`.

Serve these font assets from Barectl rather than relying on runtime requests to a font CDN. Preserve the accompanying Inter OFL license when adding the assets. Configure USWDS body and heading typography to use this English UI family while retaining its component structure and the palette in `docs/design-palette.md`.

## Vite build direction

Vite is the selected frontend build tool. Django does not require it, but it provides an asset pipeline for the chosen Sass theme, JavaScript components, and font files.

During frontend implementation:

- Extend the existing `package.json` and npm lockfile with the asset-build dependencies.
- Write first-party browser code in strict TypeScript. The independent type-check command, type-aware ESLint, and CSS linting are already configured; extend them for Sass as described in `docs/quality.md`. Vite bundling alone does not type-check.
- Use Vite with a Sass compiler and the USWDS package load paths and CSS processing requirements.
- Bundle the USWDS component JavaScript and HTMX, and build the Barectl USWDS theme with the selected palette and Inter font.
- Keep required early USWDS initialization separate where the upstream loading guidance requires it.
- In development, integrate the Vite development server with Django-rendered templates.
- In production, resolve entry points and their CSS dependencies through Vite's generated manifest. Serve the compiled assets through the configured static file deployment, without requiring a Vite server at runtime.
- Test production asset resolution and HTMX component lifecycle handling. Development hot reload alone is not sufficient validation.

Reference: [Vite backend integration](https://vite.dev/guide/backend-integration.html).

## Django baseline

Barectl is pinned to Django **6.1.1** in `pyproject.toml` and `uv.lock`. The official download page and PyPI confirmed this release when the requirement was added. Existing tests, lint, formatting, Django checks, and migration consistency checks pass after the upgrade.

References: [Django downloads](https://www.djangoproject.com/download/), [Django 6.1.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1.1/).

The frontend checking tools are installed. Vite, USWDS, and Inter remain recorded implementation requirements; they have not yet been installed or applied to the current dashboard.
