# Convention recognition delivery checklist

Tracks specification #193 and ADR 0015. Required evidence stays separate from issue state. Live servers are read-only; all mutation and recovery tests use disposable environments.

## Tickets and dependencies

| Ticket | Depends on | Delivery | Evidence / remaining work |
| --- | --- | --- | --- |
| #195 exact site recognition | none | merged #226 | Recheck managed, partial, changed, unreadable states and page presentation in final audit. |
| #197 bounded foreign reads | #195 | merged #226 | Recheck foreign names only, blocked pools, removed cards/storage and conversion by hand. |
| #196 bootstrap profile components | none | merged #227 | Recheck exact packages and default PostgreSQL main cluster only. |
| #199 uniform site admission | #197 | merged #231 | Recheck domain clashes, foreign coexistence, managed-site TLS admission. |
| #201 finish HTTP site | #199 | in progress | Missing-only effects, authorized Finish, exact account IDs, publication/exit boundaries, native interruption recovery. |
| #198 exact database bindings | #196 | merged #230 | Recheck hand-made binding, ordered prefixes, foreign names, default authentication. |
| #200 finish binding | #198 | merged #232 | Recheck missing-only SQL, pool proof, altered-prefix refusal and native recovery. |
| #194 managed HTTPS candidates | none | merged #228 | Recheck complete candidates only and unavailable-request refusal. |
| #202 final reconstruction and cleanup | #194–#201 | implemented locally; delivery depends on #201 | Fresh controller on both releases, migration consolidation, local rebuild, docs/ADR/glossary sweep, dead code checks. |
| #193 parent audit | all children | open | Audit all 40 stories, decisions, exclusions and integration evidence before closing. |

## #201 acceptance

- [ ] Partly applied site offers Finish only with site plan permissions.
- [ ] Review lists missing resources only.
- [ ] Apply produces managed site, serving through its pool with identity proof.
- [ ] Changed resources and changed account attributes/IDs refuse finishing.
- [ ] Existing resources are never replaced or removed; native exit boundaries remain meaningful.
- [ ] Site recovery docs, Partly applied glossary and ADR no-resume wording updated.
- [ ] Several interruption boundaries finish on disposable Ubuntu 24.04 and 26.04.
- [ ] Full local gates, browser, audits, affected local native suites pass.
- [ ] Review findings fixed; required checks pass on exact PR head; merge and close with evidence.

## #202 acceptance

- [ ] Both disposable releases reconstruct managed, changed, partial site/binding, foreign and profile mismatch states from a fresh controller.
- [ ] Discovery and bootstrap migrations consolidated without compatibility code.
- [ ] Local databases rebuilt by hand with unrelated data protected.
- [ ] Vulture and Knip pass without new allowlist entries for removed code.
- [ ] Architecture, convention, database, site, TLS, ADR references and glossary agree with ADR 0015.
- [ ] Full local gates, browser, audits, affected local native suites pass.
- [ ] Review findings fixed; required checks pass on exact PR head; merge and close with evidence.

## Verification ledger

- Initial checkout: clean main matching origin/main before fetch. No unrelated changes found.
- GitHub issue tree and comments read; native dependency edges confirm #201 precedes #202.
- #232 merged with passing native statuses on both releases, but dependency-audit failed. Historical audit exceptions do not satisfy this task's required checks; current audit must pass before delivery.
- Docker engine available, version 29.4.0. No live server mutations authorized.
- Python dependency audit: exit 0, no known vulnerabilities found.
- Dependency fix: source-map-js locked 1.2.1 to patched 1.2.2; npm ci, frontend check including Stylelint/Knip, and production build exit 0. npm audit remains exit 1 on the unpatched braces advisory.
- Finish browser flow: one keyboard-driven production browser test passes, including missing-only review and removal of the action when preparation permission is removed.
- #201 final focused unit/discovery/workflow tests: 141 tests OK; Ruff, mypy, djlint and Vulture pass. HTTP-only action visibility refinement and integrated gates remain pending.
- #201 affected native check: FinishTests plus sites.test_apply_remote and sites.test_review_remote, 9/9 per release passed on disposable Ubuntu 24.04 and 26.04 aarch64. Final cleanup requires repetition. An earlier oversubscribed native run was stopped and is not passing evidence.
- #202 first native reconstruction run: FAILED both releases because consolidated migrations referenced ConfigurationPlan before creation. Fixed ordering; actual fresh SQLite migration succeeds. Reviewed reconstruction rerun: 1/1 PASS per release, aarch64, 25 seconds, including metadata, link targets, services/process IDs, catalog state and separate key-only controllers.
- #202 local ordinary suite: 1172 tests, OK, skipped 212 (unconfigured SSH/VM and platform fixtures; separate native evidence required).
- Integrated head 1675399: Ruff, formatting, mypy, Vulture, templates, Django, migration drift, frontend and build PASS. Full ordinary suite FAILED: 1187 tests, two TLS admission regressions, 218 skips. Fix and rerun required.
- Full native integration attempt stopped deliberately to fix those regressions and the newly identified probe-cleanup race. Interrupted/zero-test reports are not passing evidence.
- Integrated browser suite: 47 tests in 195.957 seconds, OK. Python audit exits 0; npm audit exits 1 with ten high affected records from the unpatched braces advisory.
- Full native attempt additionally exposed generated management fixture certificate missing Authority Key Identifier under Python strict verification: TLS fixture setup ran zero tests and failed. Correct the fixture certificate, retaining TLS verification, then repeat full native qualification.
- Pending: corrected full ordinary suite and final stable-head full native qualification.
- Local #202 checkpoint: 5aa57da; not pushed or merged.
- Primary controller database rebuild remains deferred until delivery: preserve its accounts/audit with a protected backup. Independent empty databases already prove the consolidated schema; rebuilding primary against unmerged code would disrupt unrelated local use.

## Completion

- [ ] Every child closed with merged PR and literal evidence.
- [ ] Parent requirements audited and gaps resolved.
- [ ] Final integration native qualification on both releases passes.
- [ ] Parent closed only with all acceptance evidence satisfied.
- [ ] Task-created branches removed, completed managed worktree archived, local main synchronized.

## Known gaps

- #201 and #202 remain open.
- Delivery is blocked by unpatched GHSA-vfj7-8cjw-p6xm through Stylelint. Current npm audit exits 1 with ten high-severity affected package records. Branch protection requires dependency-audit; no exception or bypass is authorized. See parent issue comment https://github.com/rajandangi/barectl/issues/193#issuecomment-6027381787.

## Parent audit corrections

- [ ] Limit package version queries and PHP service reads to exact release-profile packages. A separate bounded names/status inventory may report conflicting variants without interpreting them. Correction implemented with exact package/version and default-unit queries; 71 focused component/remote tests pass.
- [ ] Collapse residual MariaDB grant-exposure descriptions to one convention refusal while keeping admission safety. Correction implemented under #202; 82 binding/database tests pass.
- [ ] Offer rendered expected content for Nginx metadata-only drift. Focused regression passes; integration pending.
- [ ] Inaccessible observations never show Managed in detail facts. Focused page regression passes; integration pending.
- [ ] Preserve application content outside configuration hashing and avoid treating a changed/deleted placeholder as configuration drift. Finish regression passes; integration pending.

## Parent story coverage audit

All rows require final integrated qualification. Coverage identifies observable tests, not delivery approval.

| Story | Requirement | Owning behavior and evidence |
| --- | --- | --- |
| 1 | Hand-made exact sites managed | Site recognition; discovery/test_sites.py and test_convention_remote.py. |
| 2 | Foreign site one blocked item | Foreign names-only collection; discovery/test_sites.py. |
| 3 | Blocked file named | Site observation file and page; discovery/test_site_pages.py. |
| 4 | Expected convention guidance | Blocked viewer card and public convention link; new page regression. |
| 5 | Manual repair recognized next discovery | Exact recognition each cycle; discovery/test_sites.py. |
| 6 | Other managed sites remain usable | Per-candidate state; discovery/test_sites.py. |
| 7 | Same first/later rule | Stateless collection and independent controllers; test_convention_remote.py. |
| 8 | Creation next to foreign items | Admission finite foreign names; sites/test_admission.py. |
| 9 | Domain clash refusal | Site preparation seam; sites/test_admission.py. |
| 10 | Declaring file named | Admission refusal text; sites/test_admission.py. |
| 11 | No foreign values interpreted | Names-only collection; discovery/test_sites.py. |
| 12 | Changed file one state | Exact byte/metadata recognition; discovery/test_sites.py. |
| 13 | Changed site blocks plans | Shared complete admission; TLS readiness and database binding seams. |
| 14 | Show expected bytes | Changed site/pool and metadata-only file tests; discovery/test_sites.py. |
| 15 | Restored file automatically managed | Stateless exact recognition; discovery/test_sites.py. |
| 16 | Missing resources named | Partial observation/page; discovery/test_sites.py and test_site_pages.py. |
| 17 | Authorized Finish action | Site Overview and existing prepare authority; workflow/browser regression. |
| 18 | Only missing resources created | Filtered effects and nonreplacing payload; finish native recovery tests. |
| 19 | Differing resources refuse Finish | Review and under-lock digest; sites/test_faults_remote.py. |
| 20 | Same lock/publication/proof | Shared apply lifecycle, native finish interruptions and retained inode assertions. |
| 21 | Finish binding remaining SQL | databases/test_bindings.py and both engine native binding suites. |
| 22 | Hand-made exact binding | Database collect and fresh migrated controller native test. |
| 23 | Other named binding short refusal | Catalog comparison and residual exposure/reason correction. |
| 24 | Foreign database names ignored | Bounded named catalog read; discovery/test_databases.py. |
| 25 | Hand-installed profile accepted | Exact package queries; discovery/test_components.py. |
| 26 | Conflicting variants named | Bounded names/status inventory; test_components.py, no foreign service/configuration read. |
| 27 | Default PostgreSQL main only | Release profile collector and test_components.py. |
| 28 | Other cluster blocked | Native archive fixture and test_convention_remote.py. |
| 29 | Generic cards removed | Snapshot schema and page tests; consolidated migrations. |
| 30 | One site state | Typed state and presentation; test_snapshot.py/test_site_pages.py. |
| 31 | Managed, readable HTTPS candidates | TLS candidate outcome filter and worker/page refusal regression. |
| 32 | Fresh controller same states | New processes, SQLite databases and distinct keys; test_convention_remote.py. |
| 33 | No native manifest | Convention-only reads/writes and native before/after evidence hashes. |
| 34 | Independent controllers agree | Equal native reports from separate processes; test_convention_remote.py. |
| 35 | Unreadable is not drift | Observation outcomes, detail fact correction and native unprivileged observer. |
| 36 | Viewer sees blocked items | Viewer-only page and separate-controller tests, no plan authority granted. |
| 37 | Finite supported reading | Exact convention renders, foreign names-only parser and profile-limited components. |
| 38 | Uniform absent/exact/finish/refuse | sites/admission.py and worker tests. |
| 39 | Foreign interpreter tests removed | Generic tables/parsers removed by #226; current tests cover finite names and profile boundaries. |
| 40 | Consistent docs/glossary | Site, database, TLS, architecture, convention, recovery, ADR and glossary sweep. |

## Review findings and follow-through

- [ ] Protect site-user placeholder stage bytes before publication; native adversarial proof pending.
- [ ] Hide Finish for unreadable evidence and partially configured TLS resources.
- [ ] Preserve retained public application with index.php and no index.html; probe-based proof.
- [ ] Align locked-password prefixes across discovery and admission.
- [ ] Include socket metadata in under-lock drift evidence.
- [ ] Do not require free account IDs when retaining an exact account.
- [ ] Case-insensitive literal foreign domain clash refuses with named file.

Each slice remains unmerged while the required dependency audit fails. Keep completed implementation evidence separate from GitHub closure.

## Final integration review findings

- [ ] TLS challenge/readiness must continue requiring a complete managed site even though HTTP preparation now offers Finish. Two integrated unit failures reproduced; boundary correction in progress.
- [ ] Adversarial stage test must prove the reviewed-UID child actually executed before denying its write. Strengthened test prepared; native rerun required.
- [ ] Probe cleanup must preserve an application file swapped into its pathname between check and unlink. Use existing native rename/link operations with a trusted inode anchor and atomic no-copy quarantine; restore without replacement or retain recovery material and report exit 55. Implementation and adversarial native proof pending.
- Worktree controller database manually rebuilt from an asserted empty database; migrate exits 0, only bootstrap/discovery initial migrations recorded. Primary controller data remains protected until delivery.

- [ ] Generated native ACME management certificate must pass Python strict TLS chain verification; fix fixture extensions, prove with both-release TLS native tests, retain full certificate/hostname verification.

- Strict management fixture TLS correction passes a real local Python strict handshake and 7/7 native fixture tests on each disposable release.
- Native smoke exposed exact-method runner selection expanding to the whole class; retain exact count checks and fix dispatch.
- Native one-action HTTPS proof currently fails to create an installation; investigate readable managed-site evidence and admission rather than weakening unavailable-site refusal. Full qualification remains pending.
- Probe cleanup adversaries: 5/5 on each release passed, including preservation of raced bytes/inodes, no-overwrite restoration collision, post-capture application entry and cross-device no-copy refusal. Final full stable-head suite still required.

- Reviewed cleanup/TLS boundary native rerun: 64/64 on Ubuntu 24.04.5 and 64/64 on Ubuntu 26.04.1 aarch64, 236 seconds. This covers site apply/review/fault/journeys plus TLS challenge, not the full integration suites.
- TLS candidate smoke now explicitly proves initially inaccessible shadow evidence and, after scoped disposable access, observed managed evidence. Native/browser hosting journey fixture needs the same explicit read authority before HTTPS; qualification pending.
