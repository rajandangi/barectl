# Handoff: #395 Pause and restore a site's background work

- Branch: `feat/357-395`
- Head: see `git log -1 --format=%H` on the branch (merged with `origin/feat/357-phase-c-automation` at `38e5c82`, which brought #265's Laravel scheduler, #390's object cache and the cache/logs work; the merge commit is the branch head)
- Worktree: `/private/var/folders/64/9bmxj8cn3mx00_vdnl9j0zmm0000gn/T/barectl-phase-c/wt-395`
- No pull request opened.

## The one fence/restore step

| Module | Role |
| --- | --- |
| `automation/fence.py` | `plan(shell, sites)` reads the automation evidence once and returns the reviewed document (`{"version": 1, "sites": [...one plan per site...]}`), or `None` when a named site's work cannot be read. `plan_from(value, sites)` is the pure half. `checked(document)` validates a stored plan for a kind that stages a closed payload. `FENCING`/`NO_FENCE` name the changes that fence and the ones that never do. `UNREADABLE_REFUSAL` is the review sentence. `FENCE_BUDGET_SECONDS = 30`; the resume set is a unit that was enabled and not left fenced; timers are listed after their service so they start last. |
| `automation/observation.py` | `role_show(row, role)` answers one installed role's timer and service properties. A read that carries every role under `show["roles"]` is used as-is; today's read answers the default role, and any other installed role with no properties refuses the plan. The plan is built from `barectl-site-<id>-<role>` unit names, not a role list, so the scheduler and queue roles #265/#266 add need no change here. |
| `automation/bodies/units.py` | `fence(document, identifier, gate=False)`, `restore(document, identifier)`, `reviewed_units`, `forget`, and `fence_dropin`. Included in every fencing body by `automation/bodies/source.py::AUTOMATION_SOURCE`. |
| `operations/engine.py` | `_planned(shell, draft)`: for a draft with a `Scope.SITE` effect, if the kind is in `FENCING`, read the plan and merge it into `document["automation_fence"]`; an unreadable read turns the draft into a refusal with no effects. No fifth `ChangeKind` member. New reasons `automation_fence` (refused) and `automation_restore` (partial) with plain sentences. |

**Fence order** (after the kind's site lock and its own preconditions, before its first mutation): runtime-mask every reviewed timer and service, write the runtime `RefuseManualStart=yes` drop-in for each, `systemctl daemon-reload`, (for a persistent gate) `systemctl disable` each timer, stop the timers, stop their services, stop the slice, and prove the slice empty within the budget. Refusal is `automation_fence` with nothing else changed.

**Restore** (only after the change verified): unmask, remove the drop-ins, `daemon-reload`, start exactly the reviewed resume set in the reviewed order (services before timers, timers `enable`d first), and prove each unit active. Any failure is `automation_restore` (partial) and the work stays stopped.

**A native finding that shaped this.** On systemd 259 (Ubuntu 26.04) `systemctl mask --runtime` is **inert for an already-loaded unit**: `LoadState`/`UnitFileState` do not change even after `daemon-reload`, and `systemctl start` still starts it. The mask still blocks every later load (a reboot, an unload, a fresh start after the unit leaves memory), so it remains the durable evidence, but it cannot be the whole "a manual start cannot start it" guarantee. The fence therefore also writes `/run/systemd/system/<unit>.d/50-barectl-fence.conf` with `[Unit] RefuseManualStart=yes` and reloads, which does block a manual start immediately (verified natively, `systemctl start` exits 4). Discovery reads `RefuseManualStart` and treats it as paused. This is native systemd configuration, not a Barectl marker; restore and removal remove it. ADR 0036's amendment records it.

## Callers wired

| Kind | Body | Placement |
| --- | --- | --- |
| `set_site_php` | `sites/bodies/php_runtime.py::switch_php` | fence after the lock and the `php_state` preconditions, before `start_target_php`; restore after the final `php_state`/`verify_readiness` |
| `set_site_node` | `sites/bodies/common.py::node_locked_change` | fence before `stage("links")`; restore after the link verification |
| `set_site_pool` (Change PHP settings) | `sites/bodies/common.py::pool_locked_change` | fence before `replace_site_file`; restore after the reloaded pool verifies (its own preimage restore on failure never restarts work) |
| `deploy_laravel_site` | `laravel/bodies/common.py::_deploy_release` + `_activate` | `gate=True` fence before `stage("gate")`; restore only after the new release answers `/up` and the gate is closed |
| `rollback_laravel_site` | `laravel/bodies/common.py::_rollback_release` + `_activate` | same as Deploy, no migrations |
| `edit_laravel_environment` | `laravel/bodies/settings.py::edit_environment` | fence before `stage("write")`; restore after `stage("verify")` |
| `edit_wordpress_settings` | `wordpress/bodies/settings.py::edit_constants` | fence before `stage("write")`; restore after `stage("verify")` |
| `remove_site` | `sites/bodies/remove.py::remove` | fence before the caddy/gate stages; `remove_automation` deletes the reviewed unit files and the slice in the `configuration` stage, clears the masks and drop-ins, and **never restores** |
| `update_catalog` | `runtimes/bodies/update.py::move_site` | per moved site, both directions of the move (fence at the start, restore after `verify_readiness`); `FenceStopped` maps to refused/partial with the fence reason |

`NO_FENCE` holds reset WordPress administrator password, verify core files, `set_wordpress_server_cron` and `set_laravel_scheduler` (the changes that own their units and stop, start and remove them in their own order). A change that names no site pauses nothing.

**#265's scheduler arrives for free.** A fenced PHP or Deploy change on a Laravel site now carries the scheduler's timer and service in its plan and restores them on the new release, because the plan is built from `barectl-site-<id>-<role>` unit names and the read's per-role properties (`row["roles"]`), not from a role list. #266's queue services will do the same.

## Paused / off-maintenance projection and recovery wording

- `automation/status.py`: `Paused by an unfinished change` and `Background work is off while the site is in maintenance`; both joined `ATTENTION_STATUSES`, and `attention_problem` gives one sentence for each. A deliberate Off is still not an alarm.
- The projection treats a runtime mask **or** the fence drop-in as paused, and a fenced timer as not enabled, so a fresh controller never resumes work it never saw run.
- `automation/presentation.py: fence_summary(document)` produces the confirm screen's **Pauses** / **Starts again** lines in plain words ("shop's scheduled tasks"), and `paused_change(server, identifier)` names the newest unfinished change to the site from this device's history when it has one. A fresh controller has none and shows only native evidence. `templates/operations/_change_status.html` renders the block with the check time.
- Recovery: `docs/recovery.md` gains a row for a paused site (and for a gate left by Deploy/Roll back). Turning work back on is the ordinary **Scheduled tasks** change, which asks what state it should have and preselects nothing — the smallest honest mechanism; #395 adds no separate "lift the gate" review.
- Serving isolation: the slice holds only automation units; HAProxy, PHP-FPM and (later) Valkey stay outside it. Proved natively (C3 keeps the proxy's `MainPID` and the home page across a fence).

## Tests and evidence

| Command | Result |
| --- | --- |
| `uv run --env-file .env python manage.py test --exclude-tag browser --exclude-tag scenario --parallel 8` | see the final run in "Commands" below |
| `uv run --env-file .env mypy` | Success, 461 source files |
| `uv run ruff check .` / `uv run ruff format --check .` | Pass |
| `uv run vulture` | Pass |
| `uv run djlint templates --lint --check` | Pass (79 files) |
| `uv run --env-file .env python manage.py check` / `makemigrations --check --dry-run` | Pass / no changes |
New fast tests:

- `automation/test_fence.py` — the plan from snapshot evidence: enabled/disabled/paused units, no automation, unknown site, unreadable read, a role with no properties, every installed role carried (scheduler + queue), a worker with no timer, several sites, a duplicate scheduler.
- `automation/test_fence_engine.py` — the engine records the plan, records an empty plan for a site with no automation, refuses with nothing planned when the read is unreadable, reads nothing for a no-change or server-wide draft, and pins `FENCING`/`NO_FENCE`.
- `automation/test_fence_body.py` — the body order (mask, drop-in, reload, timers, services, slice), gate boot-activation removal, a slice that cannot drain, a manual start refused by the drop-in, restore of exactly the reviewed set, a partial restore, a plan naming another site refused, and `forget`.
- `automation/test_fence_callers.py` — every fenced kind's staged program compiles, carries the helpers, calls fence/restore, and removal never restores; the plain words and the status sentences.
- `sites/test_fpm_admission.py` — a site master stays bound across a `daemon-reload` (the cleared `ExecStart` runtime fields), and a foreign or half-cleared command is refused. This is the minimum integration fix without which a PHP change after any unit-writing change (server cron, log rotation, runtime update) refused as "private native serving evidence unavailable" — the native C3 run found it.

## Commands run and results

| Command | Result |
| --- | --- |
| `uv run --env-file .env python manage.py test --exclude-tag browser --exclude-tag scenario --parallel 8` | **1402 tests, OK, 22.0 s** (90 s target), merged tree |
| `uv run --env-file .env mypy` | Success, 461 source files |
| `uv run ruff check .` / `uv run ruff format --check .` | All checks passed / 555 files formatted |
| `uv run vulture` | Pass |
| `uv run djlint templates --lint --check` | 81 files, 0 errors |
| `uv run --env-file .env python manage.py check` / `makemigrations --check --dry-run` | Pass / no changes |
| `docker/disposable-server/run-scenarios.sh --env-file .env -- --record fence-wordpress-26.04` | 5 tests, 92 s, OK; new transcript `fence-wordpress-26.04` |
| `docker/disposable-server/run-scenarios.sh --env-file .env -- --record <state>` for every other state (24) | all 28 recorded OK on the merged tree |
| `docker/disposable-server/run-scenarios.sh --env-file .env -- --validators` | 3 of 5 classes: **pre-existing** failure on the integration tip too (`ddcc065` fails the same 4 tests); each failing class passes alone, and `AutomationValidators`, `LogRotationValidators` and `RuntimeDefaultValidators` pass in the combined stage |

## What is not run, and risks

1. **arm64/amd64 split.** Everything here ran on this host (arm64, Ubuntu 26.04 containers). CI's `native` shard runs the same C3 class on x86_64; `disposable/shard_times.json` records 95.0 s for it (local 90–92 s).
2. **Browser suite not run locally.** `automation.test_browser` and `dashboard.test_browser` still need CI on this machine; the confirm-screen block uses only existing markup patterns and no new activations.
3. **The runtime-mask limitation is version-specific.** The drop-in exists because systemd 259 ignores a runtime mask for a loaded unit. If a later systemd applies the mask immediately, the drop-in is redundant but harmless; `docs/automation.md#fencing-site-changes` and the ADR say why it is there.
4. **Fencing wider than the enumerated callers.** `FENCING` is the specification's list. Readiness, Domains, the site database binding and the cache client do not fence; they change no code, schema, runtime or file a scheduled run reads. If a later ticket decides otherwise, add its slug and wire its body — the plan and the helpers are generic.
5. **A new role's evidence.** The plan carries any `barectl-site-<id>-<role>` unit. It refuses when an installed role has no properties in the read, so #265/#266 must extend `automation/bodies/observe.py` to answer per-role properties (`show["roles"]`); until then a site with an unreadable new role refuses site changes rather than guessing what was on.
6. **Removal's inventory.** Removal removes the *reviewed* automation units and the slice from the engine's plan, and verifies their files are gone in the body. It does not add them to its closed inventory, so its review document and digest are unchanged.

## What #397 and #398 must know

- **#397 live logs** read unit journals; the fence writes nothing to a journal of its own (stages are the change's). A fenced unit's journal is still readable (the units exist), and the drop-in lives in `/run/systemd/system/<unit>.d/`, outside `/etc`; the log reader should not list it.
- The site's log-rotation change (`logs/change.py`) writes a unit-free file but **does not fence**; if a reviewer wants it fenced, add `set_up_log_rotation` to `FENCING` and one fence/restore pair to its body.
- **#398** (restore/capture, Phase D) must call the same `automation/fence.py` plan and `automation/bodies/units.py` helpers around capture and restore, and never restore work a review did not declare.
- `disposable/change_testing.py: apply_change` now calls `engine._planned(...)`, so every native scenario applies the same review the worker would. That is the pattern for any new scenario that applies a fenced kind.
