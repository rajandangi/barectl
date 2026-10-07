# Contributing

Follow the README to run the app. Use the development checks there before opening a pull request, and enable the pre-push quality gate with `git config core.hooksPath .githooks` (see `docs/quality.md`). Complete the repository checks locally before pushing. For native-affecting changes, also run the affected native tests locally, for example `docker/disposable-server/run-tests.sh --env-file .env -- tls.test_issuance_remote`, and fix failures before pushing. A pull request then needs native statuses on its exact head commit: after pushing, add the `native-ci` label to run the full suites in CI, or run `docker/disposable-server/native-check.sh --env-file .env` locally ([native suites](docs/quality.md#native-suites)). Include migrations for model changes and tests for changed behavior, especially authorization and remote execution boundaries. Test modules never import other test modules: support that tests share lives in non-test modules grouped by concept, such as `servers/testing.py` for the controller SSH configuration and `discovery/fakes.py` for `FakeServer`, recorded attempts and a stored snapshot.

Follow `docs/quality.md` for strict typing and static analysis. Check official framework and package documentation before proposing new dependencies or recommendations. Cite compatibility guidance and distinguish upstream recommendations from project-specific choices.

Keep changes focused. Discuss new infrastructure dependencies and additions beyond the roadmap before implementation. Use Django templates; keep remote operations behind application services and infrastructure adapters. Never add SSH calls directly to views.

Follow the [core philosophy](README.md#core-philosophy) and [state and discovery requirements](docs/architecture.md#state-and-discovery). Configuration created by new management features must remain reconstructable from native server evidence without another device's database. Keep Barectl-specific history and tracking records in the application database. For mutations, verify coordination across independent devices using native facilities or established packages; a constraint in one application database is insufficient.

Use disposable servers for infrastructure tests. Do not commit credentials, private server inventories, `.env`, or local databases. Documentation must distinguish implemented behavior from planned features.

## Documentation and Wiki maintenance

Each topic has one maintained source in this repository. The [Wiki](https://github.com/rajandangi/barectl/wiki) provides short introductions and task-oriented links to those sources. Keep full instructions, capability lists, roadmap tables, specifications, ADRs and qualification evidence in repository documents, where changes receive review with the code.

| Topic | Maintained source | Wiki role |
| --- | --- | --- |
| Introduction, installation and current capabilities | [README](README.md) | Brief introduction and starting links |
| First-site walkthrough | [Host your first PHP site](docs/first-site.md) | Introduction and a link to the guide |
| Detailed operator tasks | Relevant document in `docs/` | Task-oriented documentation index |
| Milestone scope | [Roadmap](ROADMAP.md) | Links to the roadmap, Issues and Releases |
| Implementation priorities and ticket state | [GitHub Issues](https://github.com/rajandangi/barectl/issues) | Link to the tracker |
| Published versions | [Releases](https://github.com/rajandangi/barectl/releases) | Link to releases |
| Tests, revisions and limits | Relevant qualification record in `docs/` | Links to the evidence |

Update the owning document in the same pull request that changes behavior. Update Wiki navigation when a page, task or link changes. Avoid copying full sections between guides; link to their owner instead. Review documentation links and Wiki navigation when publishing a release. Use `main` links for current development documentation and release-tag links for version-specific instructions.

Wiki edits use its separate Git repository, `https://github.com/rajandangi/barectl.wiki.git`. Pull before editing, check links against published repository files, review the diff, commit with a descriptive message and push the Wiki's default branch. Keep editing restricted to collaborators and use fictional domains and sanitized screenshots. Follow [GitHub's Wiki editing guidance](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages).

If complete guides are later published inside the Wiki, generate them from repository sources through a one-way publishing workflow and edit only the source files. Such a workflow needs its own implementation and review; the current Wiki is maintained as navigation.
