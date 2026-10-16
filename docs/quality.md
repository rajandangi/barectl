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
| Frontend types | TypeScript strict, including checked JavaScript, type-checked by Vite+'s tsgolint in `vp check` | First-party tooling (`tsconfig.json`) and browser source (`frontend/tsconfig.json`); declaration checking enabled |
| Frontend formatting | Oxfmt through `vp check` | First-party TypeScript, JavaScript, JSON and Sass; templates, Markdown, TOML and generated files keep their own tools |
| Frontend static analysis | Oxlint through Vite+ with type-aware rules, ported from typescript-eslint's strict type-checked preset | Unsafe values, unhandled promises, exhaustive switches, explicit function returns |
| Stylesheets | Stylelint standard SCSS configuration | First-party Sass in `frontend/`, with zero warnings allowed |
| Frontend dead code | Knip | Unused JS/TS/Sass files, exports and npm dependencies |
| Asset build | `npm run build` (`vp build`) | Vite production build, manifest and license notices |
| Dependency vulnerabilities | pip-audit and npm audit | Installed Python dependencies and the npm dependency tree |
| Django configuration | System checks | Installed apps and framework configuration |
| Schema consistency | Migration check | Model changes without corresponding migrations |
| Behavior | Django tests | Authentication, permissions, CSRF, HTMX responses, input validation, Vite manifest handling |
| Concurrency | `servers.test_race` | Removal and discovery requests in separate processes on a SQLite database file, each order holding one transaction open while the other request starts |
| Browser | Playwright tests tagged `browser` | Sign-in, server registration, editing and removal, connection-check progress, plan preparation and review, keyboard access, focus, responsive layout, HTMX 4 and USWDS lifecycle against production-built assets |
| Native scenarios | Django tests tagged `scenario`, run by `disposable/scenarios.py` ([native layer](#native-layer)), on real offline servers booted from the L0 snapshot | Lifecycle outcomes on the target stack: discovery from a fresh controller now, the host foundation, sites, runtimes and reconstruction as later tickets add them |

CI's `Checks` workflow runs for pull requests and pushes to `main` or `release`; a newer commit on a pull request cancels the checks still running for the previous one, while every push to `main` or `release` completes its own run. `main` contains current development and `release` contains stable releases. Every other branch is a feature branch. Direct pushes to those branches and tags do not trigger CI. Updates to a feature branch with an open pull request still run the pull-request checks.

Python 3.14 is the minimum supported version. The project metadata, Ruff and mypy all target that minimum. Development and CI use Python 3.14, and CI has no jobs for older Python versions. Separate Node 24, browser and dependency-audit jobs enforce frontend checks, the browser path and vulnerability auditing. Hosted CI runs after publishing the changes. Vulnerability checks require network access and can report newly disclosed issues without source changes.

### Python typing policy

- Annotate function inputs and outputs. Use precise domain types for application services and infrastructure adapters.
- Run mypy in strict mode with the Django plugin and strict settings/model checking. Reject explicit `Any`, types derived from unfollowed imports, unused ignores, and ignores without an error code.
- Reject decorators that erase annotations, unused awaitable results, incomplete matches, mutable attribute narrowing, and overrides without `@override`. Treat bytes strictly and report unreachable code.
- Do not use blanket `ignore_missing_imports`, module-wide error disabling, or casts merely to silence errors. A necessary boundary exception must be narrow and explained.
- Validate forms, configuration, JSON, and SSH output before converting them into trusted application types. `cast()` does not validate runtime data.
- Keep vendor code and generated asset bundles outside first-party lint scope. Generated Django migrations remain type-checked; their framework-generated class-level lists have a documented Ruff `RUF012` exception and their narrowed metadata has a mypy `mutable-override` exception. All other configured checks still apply.
- Add narrowly typed adapters or local stubs when a necessary third-party interface lacks types, after checking upstream support. Do not spread untyped values through application code.
- paramiko ships without inline types. The development group pins typeshed's `types-paramiko` release for paramiko 5.0.0; update both together, and the `[tool.uv]` overrides that let pyinfra 3.10.0 use them. pyinfra ships inline types; its untyped `Inventory` and `Config` constructors are the only calls marked `no-untyped-call`.

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
shellcheck operations/bodies/*.sh
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

### Before every push

`.githooks/pre-push` runs the Python checks and the fast gate -- the non-browser, non-scenario tests, with Django's `--parallel` -- and `npm run check`. A failure aborts the push. When the pushed commits change a [native-affecting path](#native-affecting-paths), it ends by reminding you to run the native scenarios. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

The development group pins `tblib` so Django's parallel runner can return worker tracebacks and report ordinary assertion failures. Django installs its pickling support automatically. This follows [Django 6.1's parallel-test guidance](https://docs.djangoproject.com/en/6.1/ref/django-admin/#cmdoption-test-parallel); [tblib 3.2.2 declares Python 3.14 support](https://pypi.org/project/tblib/3.2.2/). Some exception objects remain unpicklable; rerun an affected test with `--parallel=1` when Django cannot serialize it.

It needs `.env` and `node_modules`. `git push --no-verify` skips it. The frontend build, browser tests and dependency audits run in CI on each pull request; GitHub Actions is free for public repositories on standard GitHub-hosted runners.

The fast gate runs in about 22 s of wall time on the reference host (2082 tests, `--parallel`), against a 90 s target; `docker/disposable-server/build.sh` reports it with the full build.

The browser tests need a production build and `npm ci` first. The production tests collect static files into a temporary `STATIC_ROOT` and serve them without the Vite development server. The development tests start the project's Vite server on a free port, selected with `BARECTL_VITE_DEV_PORT`, and check that modules, styles and fonts load from it and that USWDS binds once across HTMX fragment updates. If a compatible Chromium is already installed, set `BARECTL_BROWSER_EXECUTABLE` to its path instead of running `playwright install`. Playwright's sync API keeps an event loop running on the test thread, so the browser test classes set Django's documented `DJANGO_ALLOW_ASYNC_UNSAFE` switch for their own duration only. Test database calls remain synchronous.

## Recorded transcripts

The fast layer of [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md) meets the server at `RemoteShell.run` ([ADR 0002](adr/0002-keep-the-remote-shell-seam.md)) with real command output recorded from a real server. `discovery/recorded.py` holds both test adapters of the seam:

- `RecordingShell` wraps a real connection and keeps every command with its exit status, output, truncation flag and the SHA-256 of any standard input. Standard input itself is never kept. It refuses, without sending it, a command that names a path inside a site's private directory (`/var/www/<id>/private/`) or the confidential staging directory `/run/barectl/secrets` ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)), or that contains a known secret, and a refused recording can no longer produce a transcript. Known secrets in output are replaced with `<secret>`.
- `ReplayShell` answers exactly the commands a transcript holds. A repeated command replays its results in order and then keeps the last. A command the transcript lacks fails the test with `unrecorded command; re-record <state>`; it never becomes an empty success. Standard input whose digest differs from the recording fails the same way. A test may override the result of a recorded command, never invent one, and may pass a described filesystem (`FakeServer`) that answers the `test`, `cat` and `ls` probes under its contract test.

Each transcript is one JSON file per server state in `discovery/transcripts/<state>.json`, with the pins its server was built from. `docker/disposable-server/pins.json` holds the current pin set, which is the digest of the Ubuntu base image today; the Nix release, nixpkgs revision and catalog lock join it as they arrive. A fast test fails when any transcript was recorded with other pins, so moving a pin means recording again in the same change. Another fast test reads every transcript and fails if one holds the secret every recording seeds on its server or a command naming a secret location.

A plain state is recorded from the L0 snapshot at the L0 discovery scenario's checkpoint ([native layer](#native-layer)):

```bash
docker/disposable-server/run-scenarios.sh --env-file .env -- --record pristine-26.04
```

Scenario checkpoints of the native harness record the other states.

## Native layer

The native layer of [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md) runs lifecycle scenarios on real, offline servers, within a 10-minute target and a 15-minute limit. It replaces the old Nginx, Certbot and APT-PHP suites.

### Snapshots

L0 is the pinned Ubuntu 26.04 base image, by digest (`docker/disposable-server/pins.json`), with the server packages, rsyslog as a server forwards to it and the harness's fixture CA. `disposable/images.py` builds, caches and loads it, keyed by a hash of its inputs; CI restores it from `actions/cache` by that key. `L0-standing` is a native-test fixture with Nginx, Apache and APT PHP installed during image build; each isolated scenario removes the packages it is not exercising before discovery, so no network or package installation is needed in the offline lane. `L0-24.04` is the pinned Ubuntu 24.04 image used only to prove the unsupported-release judgment. These fixture layers do not qualify those hosts for management. L1 is the verified host foundation produced by the real S1 scenario. Its key hashes the engine-rendered payload and fixed native body, catalog lock and pinned base; missing L1 is prepared through S1 before dependent scenarios, and an existing matching image is reused. Later runtime scenarios extend the observed host through the same native change engine.

The accepted serving replacement in [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md) adds qualification obligations beyond the current shared-master suites: independent site admission and masters, both PHP switch directions with active and queued POSTs and delayed bodies, post-response worker drain, exactly-once effects, single-thread source-removability refusal, retained static backend state and restart restoration, target failure, reverse rollback, controller loss and fresh-controller reconstruction. Native socket/process security, unrelated-site continuity, amd64/arm64 and measured multi-site memory are required. Feasibility experiments do not satisfy the full acceptance gate.

### Fast snapshot validators

`run-scenarios.sh -- --validators` selects only the fast native validator class and runs it in one L1 container through the existing lane runner. It checks actual Caddy/PHP-FPM validators and before-effect scratch refusals, including a safe publication baseline before changed-preimage and unsafe-directory mutations. Ordinary lifecycle discovery, list, shard and recording selections exclude this class; validator mode refuses shard, recording and egress options. The class retains the `scenario` exclusion tag so ordinary controller tests never require Docker. A missing keyed L1 still goes through real S1 preparation, without reusing another key or raising the item/build limits.

The full build reports controller-fast and fast-validators separately and their joint elapsed time against ADR 0033's one-minute fast-stage target. The required Native workflow runs the validator stage on shard 1 before lifecycle checks; a validator failure fails the shard and required aggregate. Its logs are retained separately from lifecycle logs.

### The local mirror

`docker/disposable-server/mirror-manifest.json` lists every upstream file a build needs with its SHA-256: the Nix installer tarball, the Nix binary-cache closure of the runtime catalog lock (byte copies of each `narinfo` and NAR, as cache.nixos.org serves them) and the Ubuntu archive's frozen release pocket, the only pocket whose bytes are stable. `docker/disposable-server/mirror.sh -- fetch` downloads and verifies them into `~/.cache/barectl/native/mirror`; it needs the internet and runs only when asked. Nothing at scenario time reaches the internet: each lane serves the mirror under the real host names over HTTPS with the fixture CA, which L0 trusts, so every signature stays the upstream's own. `mirror.sh -- drift` reports any file whose upstream bytes changed, and the [drift job](#drift-and-the-weekly-jobs) opens an issue. A scenario proves the mirror end to end: L0's Nix client installs from the mirrored tarball, realises a catalog path with `max-jobs = 0` and reads the official `cache.nixos.org-1` signature back, with only ADR 0028's `nix.conf` in place.

### Lanes and scenarios

A scenario is a Django test class tagged `scenario` (excluded from the fast layer) declaring the snapshot layer it needs, whether it needs a server of its own, the name prefix for every resource it creates, and the checkpoint states it records. Non-exclusive scenarios share one server per lane in sequence, each prefixed and followed by a residue check; a failed scenario or residue check discards the server, so the next scenario gets a fresh one. A residue check waits for a removed pool's workers before deleting the account. A lane's server joins only an `--internal` network, so it has no egress and only Docker's aliased names resolve; the harness reaches its SSH through a dual-homed forwarder, and the runner refuses an item that asks for a name no mirror serves, naming the host. `run-scenarios.sh -- --check-egress` proves that refusal with a scenario that deliberately looks one up. The number of lanes is `min(floor(CPUs / 1.75), floor(Docker VM GiB / 0.5))`, or `--lanes` / `BARECTL_NATIVE_LANES`.

### Limits

An item is killed at 180 s ("over 3 minutes"); the build stops at 900 s naming the scenarios that did not finish; the summary reports the total against the 600 s target and the 900 s limit.

### Recording

`run-scenarios.sh -- --record <state>` runs the scenario that records `<state>` with a recording shell and writes each checkpoint's transcript to `discovery/transcripts/<state>.json`.

### Quarantine

A test that fails intermittently is never retried; it is marked with `disposable.quarantine.quarantine(issue, owner=..., since=...)` ([ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md)). Outside the weekly quarantined job the marked test is skipped, so an intermittent failure never turns the required checks red; the job sets `BARECTL_RUN_QUARANTINED` and runs the quarantined scenarios and browser tests. A meta-test fails when a marked test's issue is closed, is not labelled `flaky`, or was quarantined more than 14 days ago; it reads the issue with `gh`, authenticated locally or by `GH_TOKEN` in CI.

### Running them locally

```bash
docker/disposable-server/mirror.sh --env-file .env -- fetch
docker/disposable-server/run-scenarios.sh --env-file .env -- --validators
docker/disposable-server/run-scenarios.sh --env-file .env
```

`-- --help` lists the runner's options (`--validators`, `--lanes`, `--shard`, `--record`, `--list`, `--keep-failed`, `--quarantined`). Logs are kept under `~/.cache/barectl/native/scenario-logs` or `BARECTL_DISPOSABLE_LOGS`. `docker/disposable-server/build.sh` runs one full build: controller-fast with `--parallel`, fast snapshot validators, browser tests and native lifecycle scenarios concurrently, and reports each time and the wall time against the target and limit.

### The required check

The `Native` workflow (`.github/workflows/native.yml`) runs on every pull request without a label. Its `paths` job decides whether the change is native-affecting ([native-affecting paths](#native-affecting-paths)); a pull request with none is green at that step. Otherwise two `scenarios` shards run on GitHub's x86_64 `ubuntu-26.04` runners, restoring the mirror and the L0 snapshot from `actions/cache`, and the `native` job aggregates them. Branch protection for `main` requires the `native` check in place of both old `native (Ubuntu …)` commit statuses (24.04 and 26.04); changing it is a repository owner's step.

### Drift and the weekly jobs

`Native drift` (`.github/workflows/native-drift.yml`) runs daily and on dispatch: `mirror.sh -- drift` against the live upstreams, opening an issue when a manifest hash no longer matches. `Native weekly` (`.github/workflows/native-weekly.yml`) runs the scenarios on arm64 and the quarantined scenarios on amd64. Neither blocks a merge.

### Runtime catalog lock

`runtimes/catalog_lock.json` is the catalog lock of [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md): for each entry and architecture (`x86_64-linux`, `aarch64-linux`), the store path of the build's `out` output (the only output a server realises), its version, closure size and closure download size, plus the pinned Nix installer release and its SHA-256 for each architecture. It is generated, never edited by hand. Its only inputs are `runtimes/catalog_pins.json`, which names the Nix release, the pinned nixos release channel whose head the lock's freshness is judged against, and the nixpkgs revisions, oldest first, each with its source tarball's SHA-256 (from `nix-prefetch-url --unpack`) and its entries (kind and attribute path), and the evaluation in `runtimes/catalog.nix`.

`python -m runtimes.lock_generation generate` evaluates every pinned revision for both architectures with `nix-instantiate`, reads closure sizes from cache.nixos.org with `nix path-info --closure-size`, downloads both installer tarballs to hash them, and writes the lock. It needs Nix and runs in CI, or in the official `nixos/nix` container. The newest revision's builds are offered; a build only an earlier revision produces is retired, so it is still recognized and never offered. Builds are retired, never removed: generation refuses a lock that would drop a build the previous lock lists, so an older revision stays pinned for as long as its builds may be on servers. Changing the catalog means editing the pins and regenerating the lock in the same pull request.

`python -m runtimes.lock_generation freshness` judges the lock's nixpkgs revision against the pinned channel's head from channel and commit metadata, never file dates: the head comes from `channels.nixos.org/<channel>/git-revision` and both commits' dates from the [GitHub commits API](https://docs.github.com/en/rest/commits/commits#get-a-commit). It refuses a lock more than 14 days behind the head, so PHP and Caddy security fixes cannot wait unnoticed for a Barectl release. `python -m runtimes.lock_generation realise <architecture>` realises every offered build the way a server does, [`nix-store --realise`](https://nix.dev/manual/nix/latest/command-ref/nix-store/realise) with `max-jobs = 0` and `fallback = false`, then reports one line per build, the closure's store-path count, unpacked size, the summed per-entry downloads (shared closures counted per entry), wall time and that no derivation was built; success under those options proves the whole closure came from the cache.

The `Runtime catalog` workflow (`.github/workflows/runtime-catalog.yml`) runs on pull requests and pushes to `main` that change those files, on an x86_64 and an arm64 runner. It fetches the base branch, then installs Nix (`.github/install-pinned-nix.sh`): `python -m runtimes.lock_generation installer <architecture>` validates the lock under review, builds the release URL from its pinned version, and accepts its SHA-256 only if it equals the base branch's lock for the same release or, for a new release, the `.sha256` file published beside the tarball on releases.nixos.org; the script checks the download against that digest before running it. `check` then regenerates the lock and fails with a diff unless it is byte-identical to the committed one, which catches a hand edit, judging retirement against the base branch's lock, so dropping a revision and regenerating still fails. On failure the job uploads the regenerated lock as an artifact. `drift` checks every locked build, offered or retired: `nix path-info --recursive` and `nix store verify --no-contents --recursive` against cache.nixos.org with only its published key must find the whole closure with valid signatures. It prints one line per build and fails when one is missing. In the pull-request job `drift`, `freshness` and `realise` only report ([ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md)); the same workflow runs them daily and on dispatch as its own job, which fails the run when a closure loses its signed metadata, when the lock falls more than 14 days behind the channel head, or when the catalog cannot be realised on x86_64 without building, and gates no pull request. These two `nix` subcommands are experimental and run only in this tooling; servers never use them. Sources: [`nix path-info`](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-path-info), [`nix store verify`](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-store-verify), [`nix-store --realise`](https://nix.dev/manual/nix/latest/command-ref/nix-store/realise), [channels.nixos.org](https://channels.nixos.org), [the GitHub commits API](https://docs.github.com/en/rest/commits/commits#get-a-commit), [`builtins.fetchTarball`](https://nix.dev/manual/nix/latest/language/builtins#builtins.fetchTarball), [installing a binary distribution](https://nix.dev/manual/nix/latest/installation/installing-binary).

### Native-affecting paths

`.github/native-exempt-paths` lists the paths whose changes cannot affect the native suites, one shell pattern per line where `*` also matches `/`: Markdown files, `docs/`, `LICENSE`, `.gitignore`, the Git hooks and the lint-only configuration of Stylelint, Knip and Vulture. Every other path is native-affecting, so a new directory or file counts until it is listed. `docker/disposable-server/native-paths.sh` applies the list for both the pre-push reminder and CI.

The `paths` job of the `Native` workflow compares each pull request's head with its base. With no native-affecting change, the `native` check passes at the exempt-path step. Otherwise the `scenarios` shards run and the `native` job passes only when they do; that job is the one required check. The workflows use no path filters, because GitHub leaves the checks of a workflow skipped by path filtering pending, which blocks a pull request that requires them.

## Code comments

A comment is allowed only where the code cannot make the business logic clear: a rule, constraint or upstream behaviour that names and structure cannot express. Comments that restate the code, narrate steps, repeat identifiers or describe history are removed in review.

Business rules have one home: an ADR in `docs/adr/` or another document in `docs/`. When code depends on such a rule and a reader needs the pointer, reference the document, for example `# docs/adr/0006-use-native-bootstrap-execution.md`, rather than restating the rule in several files. Docstrings follow the same rule.

## Dead-code checks

Run `uv run vulture` for Python and `npm run deadcode` for JavaScript and TypeScript. Both commands fail on findings and run in CI. `npm run check` includes the frontend command.

For a managed worktree whose absolute path contains `.codex`, the metadata exclusion can match the whole checkout. Run Vulture against a clean tracked-file archive outside that path before treating its exit status as validation; retain the same configuration and confidence threshold.

Vulture 2.16 scans the repository, including tests, settings and migrations. It excludes virtual environments, installed npm packages, Git and local agent metadata, collected static files and generated bundles. The 60% threshold includes unused functions, classes and attributes. Raising it to 100% would miss those cases. Ruff also reports unused imports and local variables.

`vulture_allowlist.py` records the current settings, deployment callables, URL configuration, app registration, middleware, system check, template tag, form fields and options, template-read attributes, ORM fields and constraints, migration metadata and test hooks that Django reads indirectly. Its references stay under `TYPE_CHECKING`, and mypy checks them. Review each addition against a real framework or template use. Do not generate and accept a blanket allowlist from the findings. Vulture also recognizes some unittest conventions itself.

Vulture compares names across scopes. A reference can hide an unrelated unused symbol with the same name, and dynamic calls can produce false positives. Passing the gate does not prove every Python file is reachable. Check URLs, templates, registrations and tests before deleting reported code. No application code needed removal in the initial scan.

Knip 6.38.0 checks unused files, exports and dependencies beyond TypeScript's unused-local checks. Its Stylelint and Vite plugins discover the tooling entry files. `knip.json` registers the two Vite entries that templates load, `frontend/main.ts` and `frontend/uswds-init.ts`. The project glob includes first-party JS/TS and Sass throughout the repository, so adding an orphan file fails. Knip follows Sass `@use` and `@forward`, which is how it sees the Inter package. Vendor files and generated bundles are excluded. Register new template entry points in both `vite.config.ts` and `knip.json`. Do not mark every source file as an entry point. These checks do not establish whether CSS selectors or Django templates are unused.

These tools and the 60% threshold are Barectl choices based on their maintainers' documentation, not Django recommendations.

## Package security

Django's official system checks inspect framework configuration. `manage.py check --deploy` adds deployment checks, and Django recommends running it against production settings. It does not query package vulnerability advisories. The official documentation reviewed for this setup does not provide a Django-native dependency vulnerability scanner.

The existing `uv run pip-audit --strict` audits installed Python packages, including development tools. CI installs the locked environment first. pip-audit is a PyPA project, not a Django tool. `npm run audit:dependencies` uses exact-pinned audit-ci to audit the complete locked npm dependency tree, including development tools. It prints the full npm report and fails at low severity or higher, with one owner-accepted advisory ID ignored in the npm script. The only current assessment is [#221's braces non-applicability review](braces-advisory-review.md#required-audit-policy). Other advisories and registry errors remain failures. Both jobs require registry or advisory-service access. Keep their failures visible; do not use blanket vulnerability ignores or automatic fixes in CI. A policy pass does not mean the raw audit has zero findings.

An audit reports known advisories for the installed versions. It does not prove that a dependency is safe or that the application uses it securely. Run Django's deployment checks with the real deployment settings before hosting. The development CI settings deliberately enable debug mode and do not represent a production security review.

## Frontend policy

The checkers analyze the tooling configuration, the browser TypeScript in `frontend/` and the Sass theme. The source globs automatically include new first-party JS/TS and Sass files. See `docs/frontend-assets.md` for the asset pipeline.

- TypeScript enables `strict`, checked indexed access, exact optional properties, explicit overrides, return-path checking, unused-code detection, unreachable-code errors, side-effect import checking, and declaration-file checking. JavaScript tooling also uses `checkJs`. `frontend/tsconfig.json` extends those options with Vite's bundler resolution and client types. `vp check` type-checks both projects with each folder's own `tsconfig.json`, independently of asset bundling, because Vite only strips types. `knip.json` lists both projects for Knip's TypeScript plugin.
- USWDS publishes its component behaviors as untyped CommonJS. `frontend/types/uswds.d.ts` declares only the lifecycle methods Barectl calls.
- Vite+ runs Oxlint from the `lint` block of `vite.config.ts` with type-aware rules, every one an error. Oxlint's correctness category is enabled in full, including for TypeScript files; the explicit rules carry over the rest of typescript-eslint's `strictTypeChecked` preset, and the TypeScript override keeps its `no-undef`, `no-redeclare`, `no-var` and `prefer-*` adjustments. Unused disable directives are errors. Explicit `any`, unsafe values, floating promises, incomplete switches, and unexplained suppression directives are rejected. Oxlint does not implement `no-generated-empty-object-type`; `no-dupe-args` and `no-octal` are covered by strict mode. This stricter rule set is a deliberate Barectl policy based on the user's request, not the upstream default for every project.
- `vp check` also runs Oxfmt from the `fmt` block. Its `ignorePatterns` leave Django templates to djLint, Python's TOML to its own tooling, and Markdown unformatted.
- Type checking and Oxlint's type-aware rules run on the tsgolint bundled with Vite+, so the TypeScript version follows the `vite-plus` pin; there is no separate `typescript` package. Node 24 and matching Node declarations are pinned by major; package versions are exact and lockfiles are committed when the changes are committed.
- Stylelint uses `stylelint-config-standard-scss` for `frontend/**/*.scss`. Barectl changes one rule: class names may use the USWDS BEM form `block__element--modifier`. Generated bundles and third-party USWDS sources are not Barectl source.
- The browser tests exercise rendered pages, HTMX 4 requests and USWDS behavior against the production build, and startup and fragment updates against the Vite development server. They check keyboard access, focus, error association and layout, but do not replace a full accessibility audit. Template linting does not prove context-variable correctness or accessibility.

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
- [Vite+ migration](https://viteplus.dev/guide/migrate), [lint](https://viteplus.dev/guide/lint), [format](https://viteplus.dev/guide/fmt) and [check](https://viteplus.dev/guide/check)
- [Stylelint getting started](https://stylelint.io/user-guide/get-started/)
- [typescript-eslint strict presets](https://typescript-eslint.io/users/configs/#strict-type-checked), the origin of the ported rules
- [PyPA pip-audit](https://github.com/pypa/pip-audit), [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/) and [audit-ci 7.1.0](https://github.com/IBM/audit-ci/blob/v7.1.0/README.md)
- [Vulture usage, confidence levels and false positives](https://github.com/jendrikseipp/vulture)
- [Knip setup](https://knip.dev/overview/getting-started), [configuration](https://knip.dev/reference/configuration), and [entry files](https://knip.dev/explanations/entry-files)
- [Django deployment checks](https://docs.djangoproject.com/en/6.1/ref/django-admin/#cmdoption-check-deploy) and [deployment checklist](https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/)

For current Django documentation retrieval and the MCP finding, see `docs/documentation-sources.md`.
