# Run Laravel background work with native systemd

> Amended by [ADR 0036](0036-run-site-automation-in-per-site-slices-without-the-global-lock.md): scheduled ticks no longer take the global mutation lock; a site change stops the site's slice instead.

Accepted for [v0.5](../v0.5.md), with implementation and qualification pending. Native systemd units own Laravel's supported minute scheduler and database queue worker. They continue without Barectl and are reconstructable through operative unit configuration and native state. No scheduler/worker agent, custom management journal or persistent Barectl helper is installed.

## Alternatives and decision

Laravel documents minute cron scheduling and Supervisor queue management. Both are established alternatives. The existing server execution convention already uses systemd for native ownership, cgroups, bounded execution and outcome inspection. Choosing a minute timer and systemd worker keeps one native process authority, avoids a second supervisor and makes deployment draining inspectable through that authority. This is Barectl's choice, not a Laravel requirement. Supervisor and arbitrary crontabs are outside the initially recognized grammar, and duplicate unmanaged work blocks dependent mutations.

Use one finite scheduler service with nonblocking native exclusion and a site-identity child. A root-owned launcher may acquire the protected mutation lock, but application code never executes as root. No catch-up or detached background scheduling is promised. A worker never holds the global mutation lock for its lifetime; deployment stops and drains its exact unit under the existing reviewed operation. Recheck native process ownership and refuse timeout or ambiguous control groups.

## Restart and recovery consequences

Workers must restart after successful Laravel queue exits as well as failures. `Restart=always`, bounded restart delay/rate and an explicit stop budget supply that behavior; an operator's systemd stop remains stopped. Choose worker timeout below the queue retry interval and allow stop time longer than the qualified longest job. A crash or forced stop can leave a job available for retry, so application handlers remain responsible for idempotency. Neither Barectl nor systemd promises exactly-once business execution.

Native timer/service state and retained journal are observations, not complete historical audit. Scheduler lock refusal records a skipped tick, not successful application execution. Use independent-controller and real-kernel reboot qualification before claiming the native contract is delivered.

## Sources

[Laravel scheduling](https://laravel.com/docs/13.x/scheduling), [Laravel queue workers](https://laravel.com/docs/13.x/queues#running-the-queue-worker), [systemd service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [systemd timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html), [systemd kill policy](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html). Implementation checks the installed systemd series on each supported Ubuntu release; newest manuals are not qualification evidence.
