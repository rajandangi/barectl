---
name: Barectl code review
description: Review a Barectl diff with the global code-review skill and this repo's must-fix/judgement triage. Use when reviewing a branch, PR, work-in-progress or a spec delivery.
---

Call the Skill tool with `code-review` first. Follow that skill in full, then apply these
Barectl rules on top of it.

- Tag every finding **must-fix** or **judgement**. A documented standard or a spec line that
  is clearly violated is must-fix. A reasonable alternative reading, or a baseline smell, is
  judgement.
- Quote the spec line or the standard file and rule for each finding. For a "looks wrong"
  finding, quote the current line from the reviewed commit and the command or file:line that
  proves it.
- Before any fix is dispatched, resolve every judgement against the spec and the owning
  document. A judgement that conflicts with a documented recovery path is recorded with its
  rationale, not forced through.
- Report must-fix and judgement separately. Do not let a noisy reviewer inflate the must-fix
  count.
- Grade outcomes and transcripts, not the exact tool path.
