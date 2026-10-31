# Coding standards

Rules a review applies to a diff. `AGENTS.md` keeps the architectural boundaries every implementer needs; this file holds the rest. Cite the rule and the document it points to in each finding.

## Checks and typing

- Follow `docs/quality.md`: strict Python typing, TypeScript and JavaScript checks, type-aware Oxlint through Vite+, CSS linting, template checks, dependency audits, and runtime validation at external boundaries. Keep Vite assets covered by the frontend checks; do not weaken checks to silence errors.
- Run Vulture and Knip for dead-code detection. Review Django/template uses before removing a reported symbol. Keep `vulture_allowlist.py` explicit and explained; do not raise the confidence threshold or add blanket ignores to hide findings. Register actual frontend entry files in Knip when adding browser assets.
- Require Python 3.14 or newer. Keep the development pin, CI and analysis targets on Python 3.14; do not add compatibility work for older Python versions.
- Target Python 3.14 syntax, including PEP 758's unparenthesized `except A, B:` form; Ruff and the test run enforce syntax.
- Django is pinned to 6.1.1. Keep remote operations behind application services and infrastructure adapters.
- New tests must not grow the suite's total time; see the [test time budget](docs/quality.md#test-time-budget).

## Dashboard and frontend

- The dashboard follows the user journeys of familiar server panels (Coolify first, then Laravel Forge and CloudPanel), as specified in [#179](https://github.com/rajandangi/barectl/issues/179). Before adding or changing a screen, check how those panels handle the same step and follow it. The default path shows tasks, not server internals: masters, pools, HAProxy, journals, standing evidence and stages belong under a resource's Logs or Advanced view. Never break or lengthen #179's journeys, and never weaken their browser tests; a change that would needs the maintainer's approval in #179 first.
- Keep Django authentication and permissions for the custom interface, with terminal-based account creation and password recovery (`createsuperuser`, `changepassword`). See `docs/dashboard-plan.md` for confirmed design decisions.
- Use USWDS for the design system and Django templates with HTMX 4 for interactions. Frontend dependencies are exact pins; `docs/frontend-assets.md` records the versions, sources and the USWDS/HTMX lifecycle contract. Verify upstream guidance before changing a pin.
- Apply Barectl's color palette through the USWDS theme. Use the semantic colors recorded in `docs/design-palette.md`.
- Use Inter for Barectl's English interface and Vite for the asset pipeline. Templates load assets with `{% vite_entry %}`; never link built files by hand. See `docs/frontend-assets.md` for typography and Django integration.

## Product-surface lists

- A count, order or set that names a product surface (check names, journey steps, section rows) lives in one exported value that tests and presentation read. Prose points at it; do not restate the count in a docstring, glossary entry or help text.

## Required evidence

- A required native test is never removed, skipped or weakened to fit an item limit or a time budget. Split the setup into a preparation scenario, or record the gap in the handoff and the qualification record; a missing test is not a pass.
- Prove the seam the test claims to cover. A staged-source substring is not proof that a body reaches its fence or restore step; drive the body with the reviewed document, or assert the observable effect.

## Recorded fixtures

- A file under any `fixtures/` directory is recorded from a real server, never authored by hand; name the recording state or run in the review handoff. A hand-written fixture can encode output the product will never see, so a passing fast test then proves nothing. See [recorded transcripts](docs/quality.md#recorded-transcripts).

## Code comments

Comment only business logic the code cannot make clear. Do not restate what code does, narrate steps or repeat names. Business rules belong in `docs/adr/` and the other Markdown docs; a necessary comment points to the owning document instead of explaining the rule again. See [code comments](docs/quality.md#code-comments).

## Public documentation

Keep personal filesystem paths, private project names, internal source references and proprietary implementation details out of the repository. Describe approved design choices as Barectl requirements. Preserve required third-party license notices and public repository identifiers.
