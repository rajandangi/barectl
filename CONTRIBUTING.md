# Contributing

Follow the README to run the app. Use the development checks there before opening a pull request, and enable the pre-push quality gate with `git config core.hooksPath .githooks` (see `docs/quality.md`). Include migrations for model changes and tests for changed behavior, especially authorization and remote execution boundaries. Test modules never import other test modules: support that tests share lives in non-test modules grouped by concept, such as `servers/testing.py` for the controller SSH configuration and `discovery/fakes.py` for `FakeServer`, recorded attempts and a stored snapshot.

Follow `docs/quality.md` for strict typing and static analysis. Check official framework and package documentation before proposing new dependencies or recommendations. Cite compatibility guidance and distinguish upstream recommendations from project-specific choices.

Keep changes focused. Discuss new infrastructure dependencies and additions beyond the roadmap before implementation. Use Django templates; keep remote operations behind application services and infrastructure adapters. Never add SSH calls directly to views.

Use disposable servers for infrastructure tests. Do not commit credentials, private server inventories, `.env`, or local databases. Documentation must distinguish implemented behavior from planned features.
