# Convention recognition delivery checklist

Tracks specification #193 and ADR 0015. Required evidence stays separate from issue state. Live servers are read-only; all mutation and recovery tests use disposable environments.

Current delivery checkpoint: all children #194–#202 are closed. #201 merged in #233 (`d7b2d94`); #202 merged in #234 (`d9d64f4`). Every required exact-head check passed except the explicitly approved known npm audit failure. The #234 merge has the exact tested #202 tree; this final record changes only documentation. The primary controller has been manually rebuilt and verified, retaining unchanged accounts/password hashes and registrations while clearing cached state and history. All 40 parent stories are audited with no remaining implementation gap; the final qualification record precedes parent closure. Historical checkpoints below retain their literal results, including failures and the invalid worktree Vulture result.

## Tickets and dependencies

| Ticket | Depends on | Delivery | Evidence / remaining work |
| --- | --- | --- | --- |
| #195 exact site recognition | none | merged #226 | Managed, partial, changed and unreadable presentation pass the final audit and local integration. |
| #197 bounded foreign reads | #195 | merged #226 | Foreign names only, blocked pools, removed cards/storage and manual repair pass the final audit. |
| #196 bootstrap profile components | none | merged #227 | Exact profile packages and default PostgreSQL main queries pass the final audit and native reconstruction. |
| #199 uniform site admission | #197 | merged #231 | Domain clashes, foreign coexistence and readable managed-site TLS admission pass local integration. |
| #201 finish HTTP site | #199 | merged #233; closed | Missing-only effects, authorized Finish, exact account IDs, publication/exit boundaries, native interruption recovery. Required exact-head checks pass except the approved audit exception. |
| #198 exact database bindings | #196 | merged #230 | Hand-made bindings, ordered prefixes, foreign names and distribution authentication pass integration. |
| #200 finish binding | #198 | merged #232 | Missing-only SQL, pool identity proof, altered-prefix refusal and recovery pass native integration. |
| #194 managed HTTPS candidates | none | merged #228 | Complete readable candidates and unavailable-request refusal pass local/native integration. |
| #202 final reconstruction and cleanup | #194–#201 | merged #234; closed | Fresh controllers on both releases, valid initial schemas, primary rebuild, docs/ADR/glossary and dead-code checks pass. |
| #193 parent audit | all children | final qualification record | All 40 stories, decisions and exclusions audited against delivered main; close after final record delivery. |

## #201 acceptance

- [x] Partly applied site offers Finish only with site plan permissions.
- [x] Review lists missing resources only.
- [x] Apply produces managed site, serving through its pool with identity proof.
- [x] Changed resources and changed account attributes/IDs refuse finishing.
- [x] Existing resources are never replaced or removed; native exit boundaries remain meaningful.
- [x] Site recovery docs, Partly applied glossary and ADR no-resume wording updated.
- [x] Several interruption boundaries finish on disposable Ubuntu 24.04 and 26.04.
- [x] Full local gates, browser and affected local native suites pass; Python audit passes and the known failed npm audit has an explicit delivery exception.
- [x] Review findings fixed; required exact-head checks pass except the approved audit exception; #233 merged and #201 closed with evidence.

## #202 acceptance

- [x] Both disposable releases reconstruct managed, changed, partial site/binding, foreign and profile mismatch states from a fresh controller.
- [x] Discovery and bootstrap migrations consolidated without compatibility code.
- [x] Local databases rebuilt by hand with unrelated data protected.
- [x] Vulture and Knip pass without new allowlist entries for removed code.
- [x] Architecture, convention, database, site, TLS, ADR references and glossary agree with ADR 0015.
- [x] Full local gates, browser and affected native suites pass; Python audit passes, known failed npm audit explicitly excepted.
- [x] Review findings fixed; all other required exact-head checks pass; #234 merged and #202 closed with evidence.

## Verification ledger (chronological)

- Initial checkout: clean main matching origin/main before fetch. No unrelated changes found.
- GitHub issue tree and comments read; native dependency edges confirm #201 precedes #202.
- #232 merged with passing native statuses on both releases, but dependency-audit failed. Historical audit exceptions do not satisfy this task's required checks; current audit must pass before delivery.
- Docker engine available, version 29.4.0. No live server mutations authorized.
- Python dependency audit: exit 0, no known vulnerabilities found.
- Dependency fix: source-map-js locked 1.2.1 to patched 1.2.2; npm ci, frontend check including Stylelint/Knip, and production build exit 0. npm audit remains exit 1 on the unpatched braces advisory.
- Finish browser flow: one keyboard-driven production browser test passes, including missing-only review and removal of the action when preparation permission is removed.
- #201 final focused unit/discovery/workflow tests: 141 tests OK; Ruff, mypy, djlint and Vulture pass. At this earlier stage HTTP-only visibility and integrated gates were pending; final results are below.
- #201 affected native check: FinishTests plus sites.test_apply_remote and sites.test_review_remote, 9/9 per release passed on disposable Ubuntu 24.04 and 26.04 aarch64. Final cleanup requires repetition. An earlier oversubscribed native run was stopped and is not passing evidence.
- #202 first native reconstruction run: FAILED both releases because consolidated migrations referenced ConfigurationPlan before creation. Fixed ordering; actual fresh SQLite migration succeeds. Reviewed reconstruction rerun: 1/1 PASS per release, aarch64, 25 seconds, including metadata, link targets, services/process IDs, catalog state and separate key-only controllers.
- #202 local ordinary suite: 1172 tests, OK, skipped 212 (unconfigured SSH/VM and platform fixtures; separate native evidence required).
- Integrated head 1675399: Ruff, formatting, mypy, Vulture, templates, Django, migration drift, frontend and build PASS. Full ordinary suite FAILED: 1187 tests, two TLS admission regressions, 218 skips. Fix and rerun required.
- Full native integration attempt stopped deliberately to fix those regressions and the newly identified probe-cleanup race. Interrupted/zero-test reports are not passing evidence.
- Integrated browser suite: 47 tests in 195.957 seconds, OK. Python audit exits 0; npm audit exits 1 with ten high affected records from the unpatched braces advisory.
- Full native attempt additionally exposed generated management fixture certificate missing Authority Key Identifier under Python strict verification: TLS fixture setup ran zero tests and failed. Correct the fixture certificate, retaining TLS verification, then repeat full native qualification.
- At this earlier checkpoint, the corrected ordinary and stable-head native suites were pending; final results are recorded below.
- Local #202 checkpoint: 5aa57da; not pushed or merged.
- Primary controller database rebuild remains deferred until delivery: preserve its accounts/audit with a protected backup. Independent empty databases already prove the consolidated schema; rebuilding primary against unmerged code would disrupt unrelated local use.

## Completion

- [x] Every child closed with merged PR and literal evidence.
- [x] Parent requirements audited and gaps resolved.
- [x] Final integration native qualification on both releases passes; skips are recorded separately.
- [ ] Parent closed only with all acceptance evidence satisfied.
- [ ] Task-created branches removed, completed managed worktree archived, local main synchronized.

## Known gaps

- No remaining required implementation gap. Final qualification record delivery, parent closure and final active-worktree cleanup are the remaining administrative steps at this checkpoint.
- The known unpatched GHSA-vfj7-8cjw-p6xm through Stylelint has a maintainer-approved delivery exception; its audit failure remains visible. Current npm audit exits 1 with ten high-severity affected package records. Branch protection still requires dependency-audit; the maintainer now authorizes bypassing only this known failed check once every other required exact-head check passes. See the explicit exception: https://github.com/rajandangi/barectl/issues/193#issuecomment-6031305490.

## Parent audit corrections

- [x] Limit package version queries and PHP service reads to exact release-profile packages. A separate bounded names/status inventory may report conflicting variants without interpreting them. Correction uses exact package/version and default-unit queries; 71 focused component/remote tests and final ordinary gates pass.
- [x] Collapse residual MariaDB grant-exposure descriptions to one convention refusal while keeping admission safety. Correction implemented under #202; 82 binding/database tests pass.
- [x] Offer rendered expected content for Nginx metadata-only drift. Focused regression and final ordinary/browser gates pass.
- [x] Inaccessible observations never show Managed in detail facts. Focused page regression and complete integration pass.
- [x] Preserve application content outside configuration hashing and avoid treating a changed/deleted placeholder as configuration drift. Finish regression and reviewed 64-case native suite pass both releases.

## Parent story coverage audit

All 40 rows have been checked against merged #234, whose tree matches tested #202 head `ca420bb`. Complete native integration and exact-head CI pass; the known failed npm audit is separately excepted. Coverage identifies observable tests.

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

- [x] Protect site-user placeholder stage bytes before publication; reviewed-UID adversarial native proof passes both releases.
- [x] Hide Finish for unreadable evidence and partially configured TLS resources.
- [x] Preserve retained public application with index.php and no index.html; probe-based native proof passes both releases.
- [x] Align locked-password prefixes across discovery and admission.
- [x] Include socket metadata in under-lock drift evidence.
- [x] Do not require free account IDs when retaining an exact account.
- [x] Case-insensitive literal foreign domain clash refuses with named file.

Historical pre-exception state: slices remained unmerged while the required dependency audit failed. The approved exception and actual merged evidence are recorded below.

## Final integration review findings

- [x] TLS challenge/readiness must continue requiring a complete managed site even though HTTP preparation now offers Finish. Two integrated unit failures reproduced and corrected at shared admission; the final 1193-test ordinary suite passes.
- [x] Adversarial stage test must prove the reviewed-UID child actually executed before denying its write. Strengthened native adversary passes both releases, including the final exact-method repeat.
- [x] Probe cleanup must preserve an application file swapped into its pathname between check and unlink. Use existing native rename/link operations with a trusted inode anchor and atomic no-copy quarantine; restore without replacement or retain recovery material and report exit 55. Implemented; all five native cleanup adversaries pass both releases.
- Worktree controller database manually rebuilt from an asserted empty database; migrate exits 0, only bootstrap/discovery initial migrations recorded. Primary controller data remains protected until delivery.

- [x] Generated native ACME management certificate must pass Python strict TLS chain verification; fixture extensions corrected, real strict handshake and seven native fixture cases pass, full certificate/hostname verification retained.

- Strict management fixture TLS correction passes a real local Python strict handshake and 7/7 native fixture tests on each disposable release.
- Native smoke exposed exact-method runner selection expanding to the whole class; retain exact count checks and fix dispatch.
- Earlier native one-action HTTPS proof failed before installation because the fixture identity could not read locked-account evidence. Scoped disposable fixture authority was corrected; the final complete run passes without weakening unavailable-site refusal.
- Probe cleanup adversaries: 5/5 on each release passed, including preservation of raced bytes/inodes, no-overwrite restoration collision, post-capture application entry and cross-device no-copy refusal. Final full stable-head suite still required.

- Reviewed cleanup/TLS boundary native rerun: 64/64 on Ubuntu 24.04.5 and 64/64 on Ubuntu 26.04.1 aarch64, 236 seconds. This covers site apply/review/fault/journeys plus TLS challenge, not the full integration suites.
- TLS candidate smoke now explicitly proves initially inaccessible shadow evidence and, after scoped disposable access, observed managed evidence. Native/browser hosting journey fixture needs the same explicit read authority before HTTPS; qualification pending.

## Reviewed integration checkpoint (earlier)

- Runtime/test revision: edb360b, locally checkpointed and unpushed.
- Full ordinary suite: 1193 tests, 53.414 seconds, OK, skipped 221 (opt-in fixture/platform cases are not native proof).
- Ruff, formatting, mypy, Vulture, templates, Django, migration drift, npm ci, frontend and build: exit 0 on this revision.
- Final focused native proof: exact HTTPS one-action and stage cleanup adversary, 2/2 each release, exit 0, 68 seconds.
- Complete native integration running: 64 items / 220 selected cases per release, two lanes each. Inspect opt-in VM skips separately; a selected skipped case is not an executed passing case.
- Final browser repeat and dependency audits pending.
- Primary main clean and synchronized with origin/main. Reconstruction worktree archived after patch-equivalence check and checkpoint preservation; task-created intermediate qualification branch removed. Integrated worktree/branch retained for blocked delivery.

- Final reviewed local gates completed: ordinary 1193 tests OK (221 explicit fixture/platform skips), browser 47 tests OK in 196.893 seconds, Ruff/format/mypy239/Vulture/templates/Django/migrations/npm ci/frontend/build/Python audit all exit 0. Required npm audit remains exit 1 with ten high affected records from one unpatched braces advisory.
- HTTP-only Finish preserves the parent specification’s explicit exclusion of partly applied TLS setup/issuance/challenge recovery beyond existing reviewed plans. This excluded scope is not an unfinished required feature.

- Full native run exposed stale MariaDB fault expectation on both releases: divergent database correctly refused with not_following, native test still expected collision. Update observable refusal category while retaining partial/exit57 and sentinel assertions, rerun affected method, then complete final full qualification after corrections. Original failed run is not passing evidence.

- Corrected MariaDB refusal native method: 1/1 each release, exit 0, 37 seconds at fae197f. The full run at the earlier checkpoint remains failed until a complete corrected rerun passes.
- The earlier failed sweep passed both keyboard FirstSiteJourney browser workflows and failed only the stale MariaDB expectation. The corrected complete suite and exact skip totals are recorded below.

## Corrected full native qualification

- Earlier full sweep exits 1 after 1452 seconds: 64 items and 220 selected/ran cases per release; one stale database refusal assertion failed on each release. Ubuntu 24.04 evaluates 216 cases and skips four; Ubuntu 26.04 evaluates 218 and skips two. No other failures or unexpected skips. This is failed evidence.
- Corrected revision `fae197f` starts a complete repeat with three lanes per release; 64 items and 220 selected cases per release. That repeat was later interrupted for the acceptance findings below; it is not qualification. The runtime production revision then remained `edb360b`; the correction changes only the expected observable database refusal category and named resource assertion.

## Final acceptance review corrections

- [x] Preserve failed or truncated password-lock reads as inaccessible/unsupported instead of drift. The collect-seam regression reproduced all three incorrect outcomes before the narrow correction.
- [x] Require observed site identity before reporting an exact MariaDB/PostgreSQL binding as conforming. Both engine regressions failed before the correction; the complete site/page/database set runs 83 tests, OK.
- [x] Correct SSH discovery documentation: candidate origins are Nginx available/enabled names, orphan pool files are blocked without content reads, and foreign grant exposure uses the single convention refusal.
- The corrected full native repeat at `fae197f` was interrupted for these acceptance findings after 170 seconds. It does not qualify any revision. Restart complete native qualification after checkpointing the final corrections.

- Final reviewed runtime/test revision `42e2ede`: static/template/Django/migration checks exit 0, the ordinary suite runs 1195 tests in 57.392 seconds, OK (221 explicit fixture/platform skips), and npm installation/frontend/build checks exit 0. Browser, audits and complete native verdicts were pending at this checkpoint; final results are below.

- Final browser suite at `42e2ede`: 47 tests in 199.444 seconds, OK, exit 0. The formerly failing database fault class now passes 8/8 on both releases in the complete native repeat; the complete-run verdict remains pending.

- Required final gate pipeline completes at `42e2ede`: every listed local/static/frontend/browser/Python audit check exits 0; npm dependency audit exits 1, ten high affected records from unpatched braces. No check was weakened or bypassed. The complete native verdict was pending at pipeline completion; its passing result is recorded below.

- Stable full-run checkpoints at `42e2ede`: HTTP Finish recovery class passes 5/5 on both releases; hand-made-site HTTPS issuance, the native browser hosting journey, PostgreSQL binding journeys and fault recovery, and operator bootstrap journeys all pass. These item results do not replace the pending aggregate verdict.

- Final read-only acceptance audit covers all 40 parent stories and owning code/docs seams with no remaining actionable implementation findings after the recorded corrections. Delivery acceptance remains open for the audit blocker, exact-head PR checks/merges and primary controller rebuild.

## Final local qualification and delivery state

- Runtime/test revision `42e2ede`: complete native command exits 0 after 1059 seconds. Ubuntu 24.04.5 and 26.04.1 are both aarch64; each has 64 OK items and 220 unique selected/ran test IDs, with no duplicates, failures or unexpected skips.
- Ubuntu 24.04: 216 executed and passed, four skipped. Ubuntu 26.04: 218 executed and passed, two skipped. Both skip the two opt-in VM methods; 24.04 additionally skips the two 26.04-provider fixture methods. Skips do not extend real-kernel reboot qualification.
- Final ordinary suite: 1195 tests in 57.392 seconds, OK, skipped 221. Final browser suite: 47 tests in 199.444 seconds, OK, no skips.
- Ruff, format, mypy, Vulture, template checks, Django check, migration drift, npm ci, frontend checks including Knip, build and strict Python audit: literal exit 0.
- Required npm dependency audit: literal exit 1, ten high affected package records from unpatched braces. No failed or missing check is counted as passing, no threshold or allowlist is weakened, and no historical bypass is reused.
- All 40 parent stories have an implementation/evidence mapping; the final read-only audit has no remaining actionable implementation findings. The full native run includes fresh controllers, HTTP Finish, database Finish, hand-made-site HTTPS, authorization and recovery.
- No new push, PR, merge, issue closure or passing exact-head CI status is claimed. #201 and #202 are implemented locally; both and parent #193 remain open.
- Remaining delivery: resolve the dependency audit, deliver #201 then #202 with required checks passing on each exact PR head, safely rebuild the primary controller with its protected backup, close both children with merged evidence, repeat the parent delivered-head audit and close #193.
- Final primary checkout is clean at `5bf6a48`, matching freshly fetched origin/main. The completed reconstruction worktree is archived after patch-equivalence accounting; its task-created intermediate branch was removed. Keep the active integrated branch/worktree because it contains the blocked unmerged proposal. Unrelated data and work remain preserved.
- Next roadmap phase is not ready for delivery until these remaining gates are satisfied.

## Published delivery updates

- [x] Parent local qualification and blocker: https://github.com/rajandangi/barectl/issues/193#issuecomment-6028398373
- [x] HTTP Finish local evidence, unmerged state and closure gate: https://github.com/rajandangi/barectl/issues/201#issuecomment-6028406000
- [x] Fresh-controller qualification, schema reset and delivery gate: https://github.com/rajandangi/barectl/issues/202#issuecomment-6028407941

## Delivery resumed with approved audit exception

- [x] Maintainer explicitly authorizes ignoring the known dependency audit failure for delivery on 2026-10-07. Keep the literal failed audit visible; do not alter thresholds, dependency scans or branch protection. All other required checks remain merge gates.
- [x] Deliver focused HTTP Finish #201 PR from a separate branch, validate local affected suites and exact-head CI, then merge and close with evidence.
- [x] Deliver #202 reconstruction/schema/doc cleanup after #201, validate all remaining gates and exact-head native statuses, merge and close with evidence.
- [x] Back up and rebuild the primary controller database after schema delivery; preserve SSH credentials/configuration and unrelated files.
- [ ] Audit all parent requirements against delivered main, close #193, and archive task-created completed worktrees after accounting for all changes.

- Delivery #201 is separated at its focused branch; read-only review finds no actionable issues and confirms all runtime/security/UI files match the earlier qualified implementation. #202 is prepared as the remaining reconstruction/profile/schema/documentation slice, with the approved audit exception preserved.

## Focused delivery qualification

- #201 PR #233 opened at `742e536`; local 1188 ordinary tests OK (220 fixture/platform skips), 47 browser tests OK, 65/65 affected native cases per release with no skips. All other local gates exit 0; known npm audit remains failed under the approved exception.
- #233 CI found unused `site_plan_refused`. The earlier managed-worktree Vulture result was invalid: the existing `*/.codex/*` exclusion matched the checkout path. A clean tracked-file archive reproduced the finding; the unused helper/import were removed, without allowlist or threshold changes. Clean tracked-source Vulture now exits 0; ordinary tests and 4/4 affected native account cases per release pass at current #201 head `b7995ea`. Exact-head CI was running at that checkpoint; its successful delivery result follows below.
- #202 local pipeline at `14a3a96`: all listed gates exit 0 except the waived known npm audit. Its fresh-controller native test passes 1/1 on each release, no skips, exit 0 in 24 seconds. The same unused-helper correction is inherited from #201; clean tracked-source Vulture exits 0 and 239-source mypy is clean after the correction. The #202 runtime tree otherwise matches the earlier complete 1059-second integration qualification.
- Manual controller rebuild dry-run: unchanged operator accounts and local registrations retained exactly from a protected backup, no cached observations/jobs/plans/audit copied; initial migrations only, integrity and foreign-key checks pass. Primary database remains untouched until schema delivery.

- #201 delivered: PR #233 merged at `d7b2d944c2d1d9f633ad2cef123e32d19eed2229`, tested head `b7995ea61f122d9d781d970c7927ee136ca51284`. Check, frontend, browser and both full native commit statuses passed. Only the known dependency-audit failure was bypassed under the explicit exception. Closure evidence: https://github.com/rajandangi/barectl/issues/201#issuecomment-6031583724.
- Before final native completion, #202 PR #234 was open and ready against main at `ca420bbfa1726038996f832f4c0d3a2e305873d2`. Check/frontend passed; browser and the restarted native run remained pending at that checkpoint. Deleting the merged dependency branch closed the earlier dependent draft automatically; the same PR was reopened and retargeted without changing its head. Cancelled earlier native jobs do not count as evidence.
- Completed #201 worktree archived with all tracked changes accounted for by merged #233; its task-created local and remote branches removed. The protected controller backup remains outside task worktrees.

## Delivered integration and controller rebuild

- #202 delivered in PR #234, merge `d9d64f4357add378e307a9d9177b72d65d273589`, tested head `ca420bbfa1726038996f832f4c0d3a2e305873d2`. The merged source tree is identical to this tested head. Current [Checks](https://github.com/rajandangi/barectl/actions/runs/37576379636) show check/frontend/browser SUCCESS; current [Native](https://github.com/rajandangi/barectl/actions/runs/37576379513) shows all 14 shards and both native statuses SUCCESS. Only the known failed npm audit was bypassed under the maintainer exception. Closure evidence: https://github.com/rajandangi/barectl/issues/202#issuecomment-6031718922.
- Local #202 final pipeline: ordinary 1195 tests in 51.231 seconds, OK, skipped 221; browser 47 tests in 194.372 seconds, OK. Focused fresh-controller native proof: 1/1 on each actual release, no skips, exit 0 in 24 seconds. Runtime matches the recorded complete local native qualification except removal of the unused test helper; exact-head CI repeats the complete native suites successfully.
- Primary controller manually rebuilt after schema merge. A protected consistent backup and inactive SQLite sidecars are retained. Unchanged accounts/password hashes and registrations retained exactly; all 63 other state/session/job/history tables empty. No compatibility code or cached observations imported. Initial bootstrap/discovery migrations only; SQLite integrity OK, zero foreign-key violations, Django check/migration drift/migrate check exit 0. The guarded first replacement refused existing inactive sidecars; they were preserved separately before the successful atomic replacement. No live server was mutated.
- The earlier direct Vulture exit 0 in the managed worktree did not scan sources. The corrected clean tracked-source scan and exact-head CI pass with unchanged thresholds and no new allowlist. Historical claims above must be read with this correction.
- Final parent audit: all 40 stories and accepted decisions map to delivered behavior and observable evidence, with no remaining actionable findings. HTTP Finish, database Finish, independent reconstruction, authorization, failure recovery and hand-made-site HTTPS have integration evidence. Partly applied TLS recovery and per-site PHP versions remain the parent specification's explicit exclusions; #203 remains a separate decision.
- This completes #193's implementation qualification under the explicit known audit exception. It does not extend real-kernel reboot qualification or certify public ACME/release readiness. Final parent closure and cleanup evidence are recorded on the parent issue after this record merges.
