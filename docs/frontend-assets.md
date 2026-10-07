# Frontend typography and asset build

The sign-in page, the Servers and server pages, the server forms and the access-denied page use Barectl's USWDS theme, Inter, HTMX 4 and Vite. This page records the implemented integration, the selected versions and the sources behind each choice.

## Layout

| Path | Purpose |
| --- | --- |
| `frontend/main.ts` | Application entry: styles, HTMX 4 configuration and USWDS lifecycle |
| `frontend/uswds-init.ts` | USWDS initializer, loaded before first paint |
| `frontend/uswds.ts` | USWDS component setup for the page shell and HTMX fragments |
| `frontend/styles/` | USWDS theme settings, palette, fonts and Barectl styles |
| `vite.config.ts` | Vite development server and production build |
| `dashboard/vite.py` | Django manifest reader and `{% vite_entry %}` template tag |
| `static/dist/` | Generated production build, ignored by Git |

## Selected packages

Versions are exact pins in `package.json` and `package-lock.json`. The frontend packages are build-time dependencies; browsers receive only the compiled files.

| Package | Version | Use | Source consulted |
| --- | --- | --- | --- |
| `htmx.org` | 4.0.0 | Fragment requests and history | npm registry, v4.0.0 package source and bundled agent skills |
| `@uswds/uswds` | 3.14.0 | Components, Sass theme and behaviors | [USWDS README](https://github.com/uswds/uswds/blob/v3.14.0/README.md) and package source |
| `vite-plus` | 1.0.0 | `vp` toolchain: development server and production build (Vite 8.3.1), Oxlint and Oxfmt; `vite` is aliased and overridden to `@voidzero-dev/vite-plus-core` 1.0.0 | [Vite+ migration](https://viteplus.dev/guide/migrate), [migration rules](https://viteplus.dev/guide/migrate-rules), [Backend integration](https://vite.dev/guide/backend-integration.html), [build options](https://vite.dev/config/build-options.html) |
| `sass-embedded` | 1.105.0 | Sass compiler used by Vite | [Vite CSS pre-processors](https://vite.dev/guide/features.html#css-pre-processors) |
| `@fontsource-variable/inter` | 5.3.0 | Inter variable WOFF2 subsets | Package metadata and OFL license |
| `stylelint-config-standard-scss` | 17.0.0 | Sass linting | [Stylelint configuration](https://stylelint.io/user-guide/configure/) |

Vite+ 1.0 requires Node `^22.18.0 || ^24.11.0 || >=26.0.0`; Barectl uses Node 24, selected by `.node-version`. `devEngines` pins npm 11.19.0 for `vp install`. npm records Vite's optional `sass` peer in the lockfile, but Vite uses the declared `sass-embedded` compiler when both are present.

### Dependency audit status

The lockfile resolves `source-map-js` to 1.2.2 within its existing consumers' declared ranges. The [maintainer's 1.2.2 release](https://github.com/7rulnik/source-map-js/releases/tag/v1.2.2) fixes [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q). No dependency override is needed.

On 2026-10-07, `npm run audit:dependencies` still fails on [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm). The installed chain is `stylelint@17.15.0` to `micromatch@4.0.8` to `braces@3.0.3`, with additional paths through `fast-glob@3.3.3` and `globby@16.2.4`. npm reports ten high-severity affected package records from this single advisory. The advisory lists no patched release, and the [upstream report](https://github.com/micromatch/braces/issues/70) remains open. The npm registry still lists braces 3.0.3 and micromatch 4.0.8 as their latest releases.

An update to the latest Stylelint 17.16.0 cannot resolve this advisory: its [published dependency declarations](https://github.com/stylelint/stylelint/blob/17.16.0/package.json) retain `micromatch`, `fast-glob` and `globby`, and [micromatch's declarations](https://github.com/micromatch/micromatch/blob/4.0.8/package.json) retain `braces`. Keep the failing audit visible and retain the existing Sass checks. On 2026-10-07 the project owner accepted this known development-dependency advisory as a delivery exception for #201 and #202. It does not waive other audit findings or change the audit command, severity threshold, dependency constraints or checks. A supported upstream fix and a new passing audit remain follow-up work.

### Django integration

Barectl reads Vite's manifest with a small first-party module rather than a third-party Django package. The Vite guide defines the manifest format and tag order. `django-vite` 3.2.0 declares Django classifiers only up to 4.2 on PyPI, so it does not state support for Django 6.1. The first-party reader is strictly typed, validates the manifest as external input, and is covered by tests. This is a Barectl decision, not a Django recommendation.

## Development and production

Development uses two servers:

```bash
npm run dev
BARECTL_VITE_DEV_SERVER_URL=http://localhost:5173 uv run --env-file .env python manage.py runserver 127.0.0.1:8000
```

With `BARECTL_VITE_DEV_SERVER_URL` set, `{% vite_entry %}` loads `@vite/client` and the entry modules from the Vite server. Vite's `server.origin` makes font URLs resolve to that server. The development server only serves `frontend/` and `node_modules/`, not other repository files. Django refuses to start with this setting unless `BARECTL_DEBUG=1`, and `check --deploy` reports it as an error. Styles arrive through JavaScript in development, so a brief unstyled flash there is expected.

Production uses the build:

```bash
npm run build
uv run python manage.py collectstatic
```

`npm run build` writes hashed files to `static/dist/` and the manifest to `static/dist/.vite/manifest.json`. Django reads the manifest from that source path. Collectstatic skips the hidden `.vite` directory, so the manifest is not published. Pages link the collected files through `{% static %}`, and no Vite server runs at runtime. Built CSS uses relative URLs, so font links do not depend on `STATIC_URL`. `manage.py check --deploy` fails if the manifest or a template entry is missing.

The `{% vite_entry %}` tag follows the Vite guide's order: stylesheets, the entry module, then `modulepreload` links for imported chunks. `classic=True` renders a render-blocking `<script>` in production and rejects entries that import other chunks. The development server always serves modules.

## USWDS

`frontend/styles/_theme.scss` configures `uswds-core` with the palette in `docs/design-palette.md`. `main.scss` forwards only the component packages that Barectl renders. USWDS images resolve from the package through Vite, and small icons are inlined into the CSS.

USWDS component settings that choose text colors from a background must be given theme tokens, not hex values. The body background is therefore the `base-lightest` token for USWDS contrast calculations, and Barectl's stylesheet applies the warmer page color on top. The two colors have nearly the same luminance.

USWDS's installation guidance loads `uswds-init.min.js` in the document head to prevent JavaScript-dependent components from flashing. Barectl bundles that initializer as the classic `uswds-init.ts` entry. Barectl imports individual component behaviors rather than the complete `uswds.js` bundle, so `main.ts` sets `window.uswdsPresent` after setup, as the complete bundle does.

### Components and HTMX lifecycle

USWDS behaviors expose `on(root)` and `off(root)`. `on` runs component setup within the root and adds delegated listeners to the root element. Binding one behavior to both the body and a fragment inside it would run each delegated handler twice. Barectl therefore separates the two cases:

- Page-shell components (skip link and header navigation) are bound once to `document.body`. They are never swapped.
- Fragment components (the sortable table) are bound to each element marked `data-uswds-fragment`. `htmx.onLoad`, which listens for HTMX 4's `htmx:after:process`, binds roots found in the initial page and in swapped content. After `htmx:after:swap`, detached roots are released with `off`.

Fragment roots must be replaced whole with `outerHTML`. Replacing only a root's children is not supported. Browser tests repeat searches and check that one sort action toggles the order once.

## HTMX 4

Barectl uses `htmx.org@4.0.0`, an exact pin. On 2026-09-26 the npm registry listed 4.0.0 as the only stable 4.x release, under the `next` tag, while `latest` still pointed to 2.0.11. Check upstream release notes before changing the pin, and do not install through `latest`.

The [official HTMX 4.0.0 announcement](https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released) confirms the release and explains that npm's `latest` tag remains on 2.x for now. Use the [HTMX 4 documentation](https://four.htmx.org/docs/).

Barectl relies on these HTMX 4 behaviors, each covered by tests:

- **Explicit inheritance and CSRF.** HTMX 4 inherits attributes only with the `:inherited` modifier. `<body hx-headers:inherited='{"X-CSRFToken": …}'>` sends Django's CSRF token with every HTMX request, using [Django's documented header](https://docs.djangoproject.com/en/6.1/howto/csrf/#setting-the-token-on-the-ajax-request).
- **Fragment responses.** The Servers search form sends `hx-get` with `outerHTML` swaps into `#server-results`. Django returns the fragment only when `HX-Request-Type` is `partial`. History restores and body-targeted requests receive the full page. Responses vary on `HX-Request` and `HX-Request-Type` and are not cached. An `<hx-partial>` updates the persistent live status region.
- **Polling.** While a connection check is queued or running, the server page's `#discovery` fragment polls with `hx-trigger="every 2s"` and `outerHTML` swaps. A finished response omits the trigger, which stops polling. When the check's state changes, an `<hx-partial>` updates a persistent `role="status"` region. After **Verify connection**, the response marks the section heading `autofocus`, and HTMX moves focus to it; polling responses leave focus alone.
- **History.** `htmx.config.history = "reload"` makes back and forward navigation reload the page from Django. Each restored page passes authentication and permission checks and initializes USWDS from a complete response. Inventory pages send `Cache-Control: no-store`.
- **Authentication failures.** `fetch()` follows redirects silently, and HTMX 4 swaps 4xx responses by default. `HtmxAuthenticationMiddleware` turns a sign-in redirect for an HTMX request into `HX-Redirect`, and adds `HX-Refresh` to a 403 response. The browser then loads the page normally instead of placing a sign-in or error page inside a fragment.
- **No extensions.** Barectl loads no HTMX extensions. Check extension compatibility with the maintainers' HTMX 4 guidance before adding one.

### Official HTMX 4 agent skills

The [release announcement's LLM section](https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released#llms) links these versioned upstream resources:

- [htmx-guidance](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-guidance.md): developing HTMX 4 interfaces.
- [htmx-debugging](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-debugging.md): investigating HTMX behavior.
- [htmx-extension-authoring](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-extension-authoring.md): implementing extensions when needed.
- [htmx-upgrade-from-htmx2](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-upgrade-from-htmx2.md): identifying version-2 assumptions during migration or review. Barectl targets HTMX 4 only.

These are reference links, not installed local skills. Consult the relevant resource for HTMX work and check for matching guidance if the pinned package version changes. The same files ship in the installed package under `node_modules/htmx.org/dist/skills/`.

## English typography

Barectl's English interface uses Inter.

```css
font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
```

The weights are regular 400, medium 500, semibold 600 and bold 700. `frontend/styles/_fonts.scss` declares variable WOFF2 files for Latin and Latin Extended, with normal style, a 400 to 700 weight range and `font-display: swap`. Unicode ranges come from the package's Sass metadata. USWDS uses the family through a custom `inter` typeface token for body, headings and UI text.

Inter's project publishes release archives on GitHub rather than an npm package. Barectl uses Fontsource's `@fontsource-variable/inter`, a third-party repackaging of the Google Fonts build with separate Latin and Latin Extended subsets. Vite copies the two WOFF2 files into the build with hashed names. Pages never request a font CDN. Production browser tests assert that every request stays on the Barectl origin.

## Licenses

`npm run build` writes `static/dist/licenses/dependencies.md` using Vite's `build.license` option. It includes the USWDS and HTMX notices for the bundled code, and the USWDS notice also covers the Material icons inlined into the CSS. Inter reaches the build only as font files, so a small Vite plugin adds its SIL Open Font License as `static/dist/licenses/inter-ofl.txt`. Collectstatic deploys both files with the assets.

## Django baseline

Barectl is pinned to Django **6.1.1** in `pyproject.toml` and `uv.lock`. The official download page and PyPI confirmed this release when the requirement was added.

References: [Django downloads](https://www.djangoproject.com/download/), [Django 6.1.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1.1/).
