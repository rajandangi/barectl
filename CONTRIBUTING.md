# Contributing

Follow the README to run the app. Use the development checks there before opening a pull request. Include migrations for model changes and tests for changed behavior, especially authorization and remote execution boundaries.

Keep changes focused. Discuss new infrastructure dependencies and additions beyond the roadmap before implementation. Use Django templates; keep remote operations behind application services and infrastructure adapters. Never add SSH calls directly to views.

Use disposable servers for infrastructure tests. Do not commit credentials, private server inventories, `.env`, or local databases. Documentation must distinguish implemented behavior from planned features.
