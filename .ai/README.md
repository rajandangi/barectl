# Shared AI setup

Edit AI instructions, project skills and provider-specific profiles here. This is the
tracked source of truth. Provider directories are local, ignored symlinks.

```bash
uv run python .ai/cli.py setup
uv run python .ai/cli.py setup --check
```

Setup prepares Codex, Claude Code and OpenCode together. Repeat it after cloning or pulling;
edits to existing skills appear immediately through the links. To select one provider or
preview the plan:

```bash
uv run python .ai/cli.py setup --provider codex
uv run python .ai/cli.py setup --dry-run
```

| Source | Local layout |
| --- | --- |
| `instructions.md` | `CLAUDE.md`; the tracked root `AGENTS.md` points here for Codex and OpenCode |
| `skills/` | `.agents/skills`, `.claude/skills`, `.opencode/skills` |
| `providers/<provider>/` | Matching entries inside `.codex/`, `.claude/` or `.opencode/` |
| `evals/` | `evals/`, retaining the `python -m evals.runner` CLI |

The installer checks the complete plan before creating links. It preserves existing files,
directories and conflicting symlinks and reports their paths. Move local customizations into
the appropriate source directory or keep them elsewhere before retrying. There is no force
overwrite option. Unrelated provider settings are left alone.

Skill names use the same lowercase identifier as their directory. User-invoked skills retain
Claude's `disable-model-invocation` setting and Codex's
`agents/openai.yaml` invocation policy. The common body is shared unchanged.

`AGENTS.md` stays tracked as the bootstrap entry for a fresh checkout. Eval cases, prompts,
results and traces remain outside Git under `BARECTL_EVAL_HOME`; only their runner is tracked
here. See [harness evals](../docs/agents/evals.md).

## Provider contracts

- [Codex skills](https://learn.chatgpt.com/docs/build-skills): `.agents/skills` discovery and symlink support.
- [Claude Code skills](https://code.claude.com/docs/en/skills) and [instructions](https://code.claude.com/docs/en/memory): `.claude/skills` and `CLAUDE.md`.
- [OpenCode skills](https://opencode.ai/docs/skills/): `.opencode/skills` and compatibility locations.
- [Laravel Boost](https://laravel.com/docs/12.x/boost): the source-and-install workflow that motivated this setup. This CLI links repository sources; it does not install Boost or configure MCP servers.
