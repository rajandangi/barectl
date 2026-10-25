# Automation

A site's scheduled tasks and queue workers run as native systemd units on the managed server, under that site's own account. Barectl reviews and applies a change; the server keeps running the work with every Barectl controller closed, and the next discovery reconstructs the setting and its last result. Accepted in [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md).

Phase C starts with **server cron** for a WordPress site ([#357](https://github.com/rajandangi/barectl/issues/357), [#394](https://github.com/rajandangi/barectl/issues/394)). The Laravel scheduler, queue workers and object cache are the later Phase C tickets and reuse the same convention, projection and fence.

## Units and the slice

One site's work is a root-owned system unit set named from its identifier:

- `barectl-site-<id>.slice` contains all of the site's automation and nothing else. HAProxy, PHP-FPM and Valkey stay outside it, so stopping automation never interrupts serving.
- `barectl-site-<id>-<role>.service` runs one role. WordPress uses `wpcron`; Laravel uses `schedule` and `queue1` to `queue4`.
- `barectl-site-<id>-<role>.timer` carries the same name as its service.

The identifiers `apply`, `site`, `repo` and `backup` are reserved, so a site can never collide with an apply unit. The rendered text lives in `automation/convention.py` and the native bodies publish it; a fast validator proves systemd loads it.

| Setting | Value | Why |
| --- | --- | --- |
| `Type` | `oneshot` | one bounded run per tick |
| `TimeoutStartSec` | `15min` for WordPress cron, `1h` for the Laravel scheduler | `RuntimeMaxSec` does not bound a oneshot service |
| `KillMode` | `control-group` | a forked child cannot outlive its tick |
| `User`, `Group` | the site account `s<id>` | the application runs exactly as it does on the web |
| `WorkingDirectory` | `/var/www/<id>/current` | the site's active release |
| `OnCalendar` | `*-*-* *:*:00` | every minute at second zero |
| `AccuracySec` | `1s` | the default one-minute wake-up would smear the schedule |
| `RandomizedDelaySec` | `0` | one deterministic tick |
| `Persistent` | `false` | no catch-up burst after downtime |
| `DeferReactivation` | `yes` | a slow run is followed by the next calendar elapse, never an immediate second start |
| `WantedBy` | `timers.target` | the timer is the only boot activation |

Ticks and workers never take the global mutation lock. Systemd's one-instance-per-unit rule is the overlap protection: a calendar elapse while the previous run is still active does not start a second one.

## Turning WordPress server cron on and off

A WordPress site normally runs due events during page loads. **Settings > Scheduled tasks** offers one reviewed change, with Site consent:

- **On** publishes the slice, service and timer, starts the timer, waits for one run to succeed, and only then writes `define( 'DISABLE_WP_CRON', 'true' );` into the site's private configuration. There is never a window in which neither page loads nor the server runs cron. A first run that does not succeed within the reviewed wait leaves the timer installed and the constant unset, and the run is reported as partly applied.
- **Off** removes the constant first, so page loads run cron again, then stops and disables the timer, stops the service and removes the three unit files.

The service runs the site's own WP-CLI wrapper (`/var/www/<id>/bin/wp`) with the site's public root as `--path`, so a PHP version switch changes the runtime without rewriting the unit. WP-CLI's own `doing_cron` lock prevents overlap with any remaining page-load cron.

`DISABLE_WP_CRON` is a Barectl-owned name in the private configuration, alongside the salts and database settings; the WordPress settings section cannot edit it. The grammar accepts exactly `true` or `false` for it, and reserves `WP_REDIS_SCHEME`, `WP_REDIS_PATH` and `WP_REDIS_PREFIX` the same way for the object cache. Discovery reads only that constant's value from the private file, never another line.

## Refusals

Turning on is refused, with the reason, when:

- the host is not on the target stack, or the site's native evidence is unavailable;
- the site is not a WordPress application, or its WordPress installation is not complete and verified (including a site whose maintenance page is up);
- a site-account or root crontab line, a Supervisor program, or a foreign service already runs WordPress cron for the site or in the site's account;
- an installed unit has settings Barectl did not write. A supported hand edit (a comment, or the same directives in another order) is adopted; anything else is reported once and blocks only the changes that depend on it.

Turning off is available whenever the site's own evidence is readable, even with a duplicate scheduler present.

## Status

One pure projection (`automation/status.py`) turns native evidence into the state every screen shows, with the time it was checked:

| State | Evidence |
| --- | --- |
| Off | no timer, no constant |
| On and waiting | timer active and enabled, no run yet |
| Running | the service is active |
| Last run succeeded | the last run exited successfully inside one calendar minute |
| Last run failed | the last run exited non-zero or was killed |
| Timed out | the last run hit `TimeoutStartSec` |
| Skipped | the last run's start and end span a calendar elapse, so the tick between them did not run |
| Paused by an unfinished change | the units are runtime-masked |
| Off during maintenance | a maintenance page is up and boot activation is off |
| No cron is running | `DISABLE_WP_CRON` is set but no timer exists |
| Could not confirm | the native read was unavailable or outside supported settings |

A deliberate Off is not an alarm. Paused, off-during-maintenance, failed, timed out, skipped, no-cron and unconfirmed states appear in the site's Overview line and in the server's Needs attention list with one next action: turning the work back on is the ordinary Scheduled tasks change, which asks for the state it should have and preselects nothing.

## Discovery and reconstruction

Full discovery runs one bounded root read ([`automation/observation.py`](../automation/observation.py)): the three unit files, `systemctl show` fields (states, result, exit status, start and exit timestamps, last trigger and next elapse, control group), the slice's process count, and the crontab, Supervisor and foreign-unit files used for duplicate detection. It never runs PHP, WP-CLI or Artisan, and it never reads a private site file.

The projected rows are stored in `automation_observation` (ADR 0003), so a controller with an empty database reconstructs the setting and its last result from the server alone. Repeated reviews propose no change.

## Fencing site changes

Every change to a site's code, schema, runtime, settings or files pauses that site's background work first ([#395](https://github.com/rajandangi/barectl/issues/395)). The step is owned by this module and called from each change's own body; no kind adds a member to the engine's seam.

**The review declares the plan.** When a fenced change is eligible and changes something, `operations/engine._prepare` reads the server's automation evidence once (the same bounded read discovery uses) and stores it in the review document under `automation_fence`: the slice, every `barectl-site-<id>-<role>` timer and service to mask and stop, the resume set and the stop budget. The resume set is exactly the units whose unit-file state was enabled when the review was prepared, timers first by their own service; a role the read added later is carried by its unit name, not by the fence. An unreadable answer refuses the review with nothing planned, because masking blind is worse than stopping.

The changes that fence are `automation/fence.py:FENCING`: the PHP and Node switch, Change PHP settings, Laravel Deploy and Roll back, Edit Laravel environment, Edit WordPress settings, Remove site and Update catalog builds (per moved site). Reset WordPress administrator password and Verify core files never fence, and neither does the change that owns the units itself. A change that names no site is server-wide and pauses nothing: host foundation, Add or Remove runtime, server defaults, the database engine, Install Valkey and cleanup.

**The body fences and restores.** `automation/bodies/units.py` is assembled into each of those bodies (`automation/bodies/source.py`). After the kind's site lock and its own preconditions, and before its first mutation, the body runtime-masks every reviewed timer and service, stops the timers, then their services, then the slice, and proves the slice has no processes within the budget; if it cannot, the run refuses `automation_fence` and nothing else changed. A change that enters a persistent maintenance gate (Deploy, Roll back) also removes the timers' boot activation, so a reboot during the gate cannot restart work: a stopped unit is not a reboot fence. After the change verifies — for Deploy and Roll back only after `/up` answers on the new release — the body unmasks and starts exactly the reviewed resume set, services before timers, and proves each one active. A restore that cannot prove it reports `automation_restore` and leaves the work stopped.

Site removal fences, then removes the reviewed unit files and the slice with the rest of the site, clears their runtime masks, and never starts anything again. Update catalog builds fences each moved site around its own move.

**Paused without a marker.** No file records a fence. A runtime mask reads as *paused by an unfinished change*; a maintenance page with boot activation off reads as *background work is off while the site is in maintenance*. The site's Overview and attention banner show that sentence and one safe next action: the ordinary Scheduled tasks change. The newest change to the site that did not finish is named from this device's own history when it has one; a fresh controller shows only native evidence and never guesses what was on, and the change that turns work back on asks for the state rather than restoring a remembered one.

Stopping the automation slice never stops the site's HAProxy, PHP-FPM or Valkey instance: they live outside the slice (ADR 0036, ADR 0030). Independent CI deploys that use the site's deployment lock without Barectl are outside this guarantee.
