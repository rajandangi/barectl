# Type checking and static analysis

Barectl requires strict checking of first-party code and runtime validation at external boundaries. Passing checks is not a proof that all runtime behavior is type-safe: Django's dynamic ORM, template context lookup, third-party interfaces, and remote command output still need behavioral tests.

## Official guidance first

Before choosing a dependency or recommending an approach, read the relevant framework's official guidance and the dependency maintainers' documentation for the versions in use. Check compatibility explicitly. Record the source and rationale for consequential decisions. Distinguish a framework recommendation, a third-party maintainer recommendation, and a Barectl-specific policy. Do not describe a third-party tool as Django-endorsed without evidence.

## Enforced now

| Area | Gate | Scope |
| --- | --- | --- |
| Python types | mypy strict with django-stubs | First-party Python, including tests and migrations |
| Python static analysis | Ruff | Errors, imports, annotations, Django rules, bug patterns, security patterns, modernization, simplification |
| Python formatting | Ruff formatter | First-party Python |
| Python dead code | Vulture at 60% confidence | First-party Python, including functions, classes, tests and migrations |
| Django templates | djLint Django profile | Template formatting and lint rules |
| Frontend types | TypeScript strict, including checked JavaScript | First-party tooling (`tsconfig.json`) and browser source (`frontend/tsconfig.json`); declaration checking enabled |
| Frontend static analysis | typescript-eslint strict type-checked preset | Unsafe values, unhandled promises, exhaustive switches, explicit function returns |
| Stylesheets | Stylelint standard SCSS configuration | First-party Sass in `frontend/`, with zero warnings allowed |
| Frontend dead code | Knip | Unused JS/TS/Sass files, exports and npm dependencies |
| Asset build | `npm run build` | Vite production build, manifest and license notices |
| Dependency vulnerabilities | pip-audit and npm audit | Installed Python dependencies and the npm dependency tree |
| Django configuration | System checks | Installed apps and framework configuration |
| Schema consistency | Migration check | Model changes without corresponding migrations |
| Behavior | Django tests | Authentication, permissions, CSRF, HTMX responses, input validation, Vite manifest handling |
| Browser | Playwright tests tagged `browser` | Sign-in, server registration, editing and removal, connection-check progress, keyboard access, focus, responsive layout, HTMX 4 and USWDS lifecycle against production-built assets |

CI runs for pull requests and pushes to `main` or `release`. `main` contains current development and `release` contains stable releases. Every other branch is a feature branch. Direct pushes to those branches and tags do not trigger CI. Updates to a feature branch with an open pull request still run the pull-request checks.

Python 3.14 is the minimum supported version. The project metadata, Ruff and mypy all target that minimum. Development and CI use Python 3.14, and CI has no jobs for older Python versions. Separate Node 24, browser and dependency-audit jobs enforce frontend checks, the browser path and vulnerability auditing. Hosted CI runs after publishing the changes. Vulnerability checks require network access and can report newly disclosed issues without source changes.

### Python typing policy

- Annotate function inputs and outputs. Use precise domain types for application services and infrastructure adapters.
- Run mypy in strict mode with the Django plugin and strict settings/model checking. Reject explicit `Any`, types derived from unfollowed imports, unused ignores, and ignores without an error code.
- Reject decorators that erase annotations, unused awaitable results, incomplete matches, mutable attribute narrowing, and overrides without `@override`. Treat bytes strictly and report unreachable code.
- Do not use blanket `ignore_missing_imports`, module-wide error disabling, or casts merely to silence errors. A necessary boundary exception must be narrow and explained.
- Validate forms, configuration, JSON, and SSH output before converting them into trusted application types. `cast()` does not validate runtime data.
- Keep vendor code and generated asset bundles outside first-party lint scope. Generated Django migrations remain type-checked; their framework-generated class-level lists have a documented Ruff `RUF012` exception and their narrowed metadata has a mypy `mutable-override` exception. All other configured checks still apply.
- Add narrowly typed adapters or local stubs when a necessary third-party interface lacks types, after checking upstream support. Do not spread untyped values through application code.
- paramiko ships without inline types. The development group pins typeshed's `types-paramiko` release for paramiko 5.0.0; update both together.

django-stubs 6.1.1 documents support for Django 6.1 and mypy 1.13–2.3. This project uses its `compatible-mypy` extra and a locked mypy 2.3 release. This is third-party compatibility guidance, not a claim of Django endorsement.

The Django plugin loads application settings and models. Run it with the documented development environment or non-production CI settings, never with production credentials merely to run analysis.

Do not blindly enable every optional rule. For example, global `disallow_any_expr` rejects valid Django decorators, model classes, and generated migration structures because the upstream interfaces contain `Any`. The project uses strict checking without that global option, validates external input, and requires narrow typed application interfaces. Strict mode is not a claim that Django's dynamic internals have become statically proven. Ruff's explicit rule selection similarly avoids mutually incompatible style rules and pytest-only conventions in this Django unittest project.

### Local commands

```bash
uv sync --locked
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

The browser tests need a production build first. They collect static files into a temporary `STATIC_ROOT` and serve them without the Vite development server. If a compatible Chromium is already installed, set `BARECTL_BROWSER_EXECUTABLE` to its path instead of running `playwright install`. Playwright's sync API keeps an event loop running on the test thread, so the browser test class sets Django's documented `DJANGO_ALLOW_ASYNC_UNSAFE` switch for its own duration only. Test database calls remain synchronous.

## Dead-code checks

Run `uv run vulture` for Python and `npm run deadcode` for JavaScript and TypeScript. Both commands fail on findings and run in CI. `npm run check` includes the frontend command.

Vulture 2.16 scans the repository, including tests, settings and migrations. It excludes virtual environments, installed npm packages, Git and local agent metadata, collected static files and generated bundles. The 60% threshold includes unused functions, classes and attributes. Raising it to 100% would miss those cases. Ruff also reports unused imports and local variables.

`vulture_allowlist.py` records the current settings, deployment callables, URL configuration, app registration, middleware, system check, template tag, form fields and options, template-read attributes, ORM fields and constraints, migration metadata and test hooks that Django reads indirectly. Its references stay under `TYPE_CHECKING`, and mypy checks them. Review each addition against a real framework or template use. Do not generate and accept a blanket allowlist from the findings. Vulture also recognizes some unittest conventions itself.

Vulture compares names across scopes. A reference can hide an unrelated unused symbol with the same name, and dynamic calls can produce false positives. Passing the gate does not prove every Python file is reachable. Check URLs, templates, registrations and tests before deleting reported code. No application code needed removal in the initial scan.

Knip 6.38.0 checks unused files, exports and dependencies beyond TypeScript's unused-local checks. Its ESLint, Stylelint and Vite plugins discover the tooling entry files. `knip.json` registers the two Vite entries that templates load, `frontend/main.ts` and `frontend/uswds-init.ts`. The project glob includes first-party JS/TS and Sass throughout the repository, so adding an orphan file fails. Knip follows Sass `@use` and `@forward`, which is how it sees the Inter package. Vendor files and generated bundles are excluded. Register new template entry points in both `vite.config.ts` and `knip.json`. Do not mark every source file as an entry point. These checks do not establish whether CSS selectors or Django templates are unused.

These tools and the 60% threshold are Barectl choices based on their maintainers' documentation, not Django recommendations.

## Package security

Django's official system checks inspect framework configuration. `manage.py check --deploy` adds deployment checks, and Django recommends running it against production settings. It does not query package vulnerability advisories. The official documentation reviewed for this setup does not provide a Django-native dependency vulnerability scanner.

The existing `uv run pip-audit --strict` audits installed Python packages, including development tools. CI installs the locked environment first. pip-audit is a PyPA project, not a Django tool. `npm run audit:dependencies` audits the locked npm dependency tree, including development tools, and fails at low severity or higher. Both jobs require registry or advisory-service access. Keep their failures visible; do not use blanket vulnerability ignores or automatic fixes in CI.

An audit reports known advisories for the installed versions. It does not prove that a dependency is safe or that the application uses it securely. Run Django's deployment checks with the real deployment settings before hosting. The development CI settings deliberately enable debug mode and do not represent a production security review.

## Frontend policy

The checkers analyze the tooling configuration, the browser TypeScript in `frontend/` and the Sass theme. The source globs automatically include new first-party JS/TS and Sass files. See `docs/frontend-assets.md` for the asset pipeline.

- TypeScript enables `strict`, checked indexed access, exact optional properties, explicit overrides, return-path checking, unused-code detection, unreachable-code errors, side-effect import checking, and declaration-file checking. JavaScript tooling also uses `checkJs`. `frontend/tsconfig.json` extends those options with Vite's bundler resolution and client types. `npm run typecheck` checks both projects independently of asset bundling, because Vite only strips types.
- USWDS publishes its component behaviors as untyped CommonJS. `frontend/types/uswds.d.ts` declares only the lifecycle methods Barectl calls.
- ESLint uses typescript-eslint's `strictTypeChecked` preset and project service, with zero warnings allowed. Explicit `any`, unsafe values, floating promises, incomplete switches, and unexplained suppression directives are rejected. This stricter preset is a deliberate Barectl policy based on the user's request, not the upstream default for every project.
- TypeScript is locked to 6.0.3 because typescript-eslint 8.70.1 declares support for `>=4.8.4 <6.1.0`. Do not upgrade TypeScript independently beyond that compatibility range. Node 24 and matching Node declarations are pinned by major; package versions are exact and lockfiles are committed when the changes are committed.
- Stylelint uses `stylelint-config-standard-scss` for `frontend/**/*.scss`. Barectl changes one rule: class names may use the USWDS BEM form `block__element--modifier`. Generated bundles and third-party USWDS sources are not Barectl source.
- The browser tests exercise rendered pages, HTMX 4 requests and USWDS behavior against the production build. They check keyboard access, focus, error association and layout, but do not replace a full accessibility audit. Template linting does not prove context-variable correctness or accessibility.

These stricter flags and the selected Ruff rule families are Barectl policies chosen for the user's requirements, not universal upstream defaults. Future packages and versions must be verified against their official documentation before installation.

## Sources consulted

- [django-stubs setup and compatibility](https://github.com/typeddjango/django-stubs)
- [mypy configuration](https://mypy.readthedocs.io/en/stable/config_file.html)
- [mypy runtime generic-class guidance](https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime)
- [Ruff configuration](https://docs.astral.sh/ruff/configuration/) and [rule catalog](https://docs.astral.sh/ruff/rules/)
- [djLint configuration](https://djlint.com/docs/configuration/) and [lint rules](https://djlint.com/docs/linter/)
- [Django system checks](https://docs.djangoproject.com/en/6.1/topics/checks/)
- [TypeScript strict mode](https://www.typescriptlang.org/tsconfig/strict.html), [indexed access](https://www.typescriptlang.org/tsconfig/noUncheckedIndexedAccess.html), and [optional properties](https://www.typescriptlang.org/tsconfig/exactOptionalPropertyTypes.html)
- [Vite TypeScript behavior](https://vite.dev/guide/features.html#typescript)
- [Django LiveServerTestCase](https://docs.djangoproject.com/en/6.1/topics/testing/tools/#liveservertestcase) and [async safety](https://docs.djangoproject.com/en/6.1/topics/async/#async-safety)
- [Playwright for Python](https://playwright.dev/python/docs/intro) and [continuous integration](https://playwright.dev/python/docs/ci)
- [typescript-eslint typed linting](https://typescript-eslint.io/getting-started/typed-linting/)
- [Stylelint getting started](https://stylelint.io/user-guide/get-started/)
- [typescript-eslint strict presets](https://typescript-eslint.io/users/configs/#strict-type-checked)
- [PyPA pip-audit](https://github.com/pypa/pip-audit) and [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/)
- [Vulture usage, confidence levels and false positives](https://github.com/jendrikseipp/vulture)
- [Knip setup](https://knip.dev/overview/getting-started), [configuration](https://knip.dev/reference/configuration), and [entry files](https://knip.dev/explanations/entry-files)
- [Django deployment checks](https://docs.djangoproject.com/en/6.1/ref/django-admin/#cmdoption-check-deploy) and [deployment checklist](https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/)

For current Django documentation retrieval and the MCP finding, see `docs/documentation-sources.md`.
