# Automation

A site's scheduled tasks and queue workers run as native systemd units on the managed server, under that site's own account. Barectl reviews and applies a change; the server keeps running the work with every Barectl controller closed, and the next discovery reconstructs the setting and its last result. Accepted in [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md).

Phase C starts with **server cron** for a WordPress site ([#357](https://github.com/rajandangi/barectl/issues/357), [#394](https://github.com/rajandangi/barectl/issues/394)) and adds a Laravel site's **database queue workers** ([#266](https://github.com/rajandangi/barectl/issues/266)). The Laravel scheduler and object cache are later Phase C tickets and reuse the same convention, projection and fence.

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

## Laravel database queue workers

A Laravel site has one worker definition, edited under **Settings > Queue workers**: the database connection only, up to eight queue names in priority order, one to four processes, and a job timeout from 30 to 900 seconds (default 60). Start, Stop and Restart are ordinary reviewed Site changes.

Each process is a `Type=exec` service in the site's slice, running as the site account from `current`:

```
/var/www/<id>/bin/php artisan queue:work --connection=database --queue=<names> \
    --sleep=3 --tries=3 --max-time=3600 --timeout=<timeout>
```

| Setting | Value | Why |
| --- | --- | --- |
| `Restart` | `always` | a clean exit or a crash restarts the process |
| `RestartSec` | `5s` | a short pause between attempts |
| `StartLimitIntervalSec`, `StartLimitBurst` | `60s`, `5` | a crash loop stops instead of spinning |
| `KillMode` | `control-group` | no child outlives the process |
| `TimeoutStopSec` | timeout + 15 s | SIGTERM has room to finish the current job |

Start sets `DB_QUEUE_RETRY_AFTER` to the timeout + 30 seconds through the same private `.env` path as [Edit settings](sites.md), **before** any process starts. Laravel's default `config/queue.php` reads that variable, so `--timeout` stays several seconds below `retry_after`. The review states the assumption and that a crash or a forced stop can leave a job to be retried, so jobs must be safe to repeat. Start enables boot activation, so the workers return after a reboot; Stop disables it, so an explicit stop survives a reboot. Restart is `systemctl restart`, not `queue:restart`: each process receives SIGTERM and finishes its current job within its own stop budget.

Start and Restart are refused, with the reason, when:

- the site is not Laravel, is gated, partly deployed or not completely applied, or its current release did not pass `/up`;
- the current release has migrations that are not recorded, the database has no `jobs` table, or the site's PHP command-line build does not load PCNTL;
- a site-account or root crontab line, a Supervisor program, or a foreign service already runs `queue:work` for the site or in the site's account;
- an installed worker has settings Barectl did not write. A queue-list, process-count or timeout edit inside the bounds is adopted; anything else is reported once and blocks only Start and Restart.

Stop is available whenever the site's own evidence is readable, even with a duplicate worker or an unsupported edit.

Discovery reads the worker unit files and each process's `systemctl show` fields in one bounded root read, and stores the adopted definition and the aggregate state. A fresh controller reconstructs the definition and its state from the server alone.

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
| Paused by a change | the units are runtime-masked |
| Off during maintenance | a maintenance page is up and boot activation is off |
| No cron is running | `DISABLE_WP_CRON` is set but no timer exists |
| Could not confirm | the native read was unavailable or outside supported settings |

Queue workers use the same projection with their own states: Off, On and running, On and restarting after a crash, Stopped after repeated crashes (systemd's start limit), Paused by a change, Off during maintenance and Could not confirm.

Deliberate Off, Paused and maintenance states are not alarms. Failed, timed out, skipped, no-cron and unconfirmed states appear in the site's Overview line and in the server's Needs attention list with one next action.

## Discovery and reconstruction

Full discovery runs one bounded root read ([`automation/observation.py`](../automation/observation.py)): the three unit files, `systemctl show` fields (states, result, exit status, start and exit timestamps, last trigger and next elapse, control group), the slice's process count, and the crontab, Supervisor and foreign-unit files used for duplicate detection. It never runs PHP, WP-CLI or Artisan, and it never reads a private site file.

The projected rows are stored in `automation_observation` and `worker_observation` (ADR 0003), so a controller with an empty database reconstructs the setting, the worker definition and each state from the server alone. The recorded `automation-laravel-26.04` state proves it; repeated reviews propose no change.

## Fencing later changes

Every change to a site's code, schema, runtime or settings stops that site's automation first ([#395](https://github.com/rajandangi/barectl/issues/395)). `automation/fence.py` builds the review's plan from the stored snapshot: the slice, the timers and services to mask and stop, the resume set (what was on when the review was prepared) and the stop budget. `automation/bodies/units.py` applies it after the kind's site lock and before its mutation, and restores only after the change verifies. A change that cannot prove its slice empty within budget refuses with nothing changed; a failed or unknown change leaves the work fenced, and the run's sentence says so.

No marker records a fence. A runtime mask with no active change reads as *paused by a change*; a maintenance page with boot activation off reads as *off during maintenance*. A fresh controller never guesses which work was on before an interrupted change; the review that lifts the fence asks.
