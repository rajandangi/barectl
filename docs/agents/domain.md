# Domain docs

Barectl uses a single context. Read root `GLOSSARY.md` and relevant decisions in `docs/adr/` before exploring a domain.

If those files do not exist, proceed silently. Do not create placeholders or suggest creating them merely because they are missing. `/domain-modeling`, used by `/grill-with-docs`, creates them as terminology and decisions are resolved.

## Layout

- `GLOSSARY.md`: the shared domain glossary.
- `docs/adr/NNNN-short-title.md`: architecture decision records.
- `docs/architecture.md`: existing architectural guidance.
- `docs/v0.1.md`: existing discovery acceptance criteria.
- `ROADMAP.md`: intended release scope.

Keep existing architecture and roadmap documents in place. Distinguish implemented behavior from planned capabilities.

## Vocabulary and decisions

Use terms from `GLOSSARY.md` consistently in issues, code, tests, and explanations. Note a real vocabulary gap for `/domain-modeling` rather than inventing competing synonyms.

If a proposal conflicts with an ADR, identify the conflicting record and explain why reopening it may be justified. Do not silently override it.
