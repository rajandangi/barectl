# Native recovery

A target-stack server stays manageable with ordinary Linux tools when Barectl is unavailable. This guide lists where each part lives, how to inspect and restart it, and what to do after a change that stopped partway. Barectl never resumes a partial change by itself, never replays a lost request and never removes resources to clean up. Commands below run as root, or with `sudo`.

## Where things live

| Part | Configuration | Service | Logs |
| --- | --- | --- | --- |
| Caddy | `/etc/caddy/Caddyfile`, one site file per site in `/etc/caddy/sites/<id>.caddy` | `caddy.service` | `journalctl -u caddy`; each site's access log in `/var/www/<id>/logs/access.json` |
| Nix | `/etc/nix/nix.conf`; profiles in `/nix/var/nix/profiles/barectl/` | `nix-daemon.service` and `nix-daemon.socket` | `journalctl -u nix-daemon` |
| Runtime diagnostic master | `/etc/php-fpm/<runtime>/php.ini`, `php-fpm.conf`, `pools/diagnostic.conf` | `php-fpm@<runtime>.service` | `journalctl -u php-fpm@<runtime>` |
| A site's PHP-FPM master | `/etc/php-fpm/sites/<id>/<runtime>/` | `php-fpm-site-<runtime>@<id>.service` | `journalctl -u php-fpm-site-<runtime>@<id>`; the site's `logs/php-error.log` and `logs/php-slow.log` |
| A site's HAProxy | `/etc/haproxy/sites/<id>.cfg`; selection in `/var/lib/haproxy/sites/<id>.state` | `haproxy-site@<id>.service` | `journalctl -t haproxy-site-<id>` |
| A site's files | `/var/www/<id>`, served from `current/public` | | |
| Server default commands | links in `/usr/local/bin`; wrappers in `/usr/local/libexec/barectl/defaults/` | | |
| Barectl's runs | | `barectl-apply-<32 hex>.service`, transient, unloaded when it ends | `journalctl -u barectl-apply-<32 hex>` |
| Journal storage | `/etc/systemd/journald.conf.d/50-barectl.conf` | `systemd-journald.service` | |

`<runtime>` is `php84` or `php85`, and `<id>` is the site identifier. The [site convention](site-conventions.md) lists every path with its owner and mode.

## Inspecting

```sh
systemctl status caddy nix-daemon 'php-fpm@*' 'php-fpm-site-*' 'haproxy-site@*'
ls -l /nix/var/nix/profiles/barectl/          # installed runtimes and tools
/nix/var/nix/profiles/default/bin/nix-env --list-generations --profile /nix/var/nix/profiles/barectl/php84
/nix/var/nix/profiles/barectl/caddy/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
/nix/var/nix/profiles/barectl/php84/bin/php-fpm -t -y /etc/php-fpm/sites/<id>/php84/php-fpm.conf -c /etc/php-fpm/sites/<id>/php84/php.ini
python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"show servers state php\n"); print(s.makefile().read())' /run/haproxy/<id>/admin.sock
tail -n 50 /var/www/<id>/logs/php-error.log
journalctl -u 'barectl-apply-*' --since today
```

`caddy validate` loads the configuration's modules to check it, so run it against the live files only when you mean to. `caddy adapt` reads a file without validating it, which is how discovery reads site files. The HAProxy API socket is root-only; the command above uses the server's `python3` as its client, and `socat` from Ubuntu works as well. Nix commands are not on `sudo`'s path, so call them by their full path.

### Which PHP master serves a site

The site's **Settings** in Barectl is the readable answer: it shows the recorded selection, and **Finish or reverse the PHP change** when a switch stopped partway. Without Barectl, read the same evidence from HAProxy. `show servers state` prints the live state and `/var/lib/haproxy/sites/<id>.state` holds the persisted copy that `haproxy-site@<id>` restores when it restarts. Both have the same columns ([HAProxy 3.3 `show servers state`](https://docs.haproxy.org/3.3/management.html#9.3-show%20servers%20state)): the fourth, `srv_name`, is the runtime, the sixth is `srv_op_state` and the seventh is `srv_admin_state`.

| `srv_op_state` `srv_admin_state` | Meaning |
| --- | --- |
| `2 4` | Serves requests. `2` is `SRV_ST_RUNNING`. `4` is `SRV_ADMF_CMAINT` alone: the configuration declares the server disabled, which HAProxy keeps as a separate flag, and no forced maintenance is set ([3.3.11 source](https://git.haproxy.org/?p=haproxy-3.3.git;a=blob;f=include/haproxy/server-t.h;hb=refs/tags/v3.3.11)). |
| `0 5` | Receives nothing. `0` is `SRV_ST_STOPPED`, and `5` adds `SRV_ADMF_FMAINT`, forced maintenance, to `SRV_ADMF_CMAINT`. |

One runtime at `2 4` and the other at `0 5` is a completed selection. Both at `2 4` in the live state means a switch stopped while both masters were admitted; the persisted file then still names the previous selection, which a restart of `haproxy-site@<id>` would restore. The convention uses no other pair.

## Restarting

```sh
systemctl reload caddy                      # rereads the Caddyfile; a failed reload keeps the running configuration
systemctl restart php-fpm-site-php84@<id>   # restarts one site's PHP; FPM lets running requests finish first, and requests arriving meanwhile fail
systemctl restart haproxy-site@<id>         # restores the persisted runtime selection from its state file
systemctl restart php-fpm@php84             # the runtime's diagnostic master; no site is served by it
systemctl restart nix-daemon
```

Restarting one site's services never affects another site. Do not edit a site's HAProxy configuration to switch PHP; use the site's **Settings**, which drains the old master first. After `systemctl daemon-reload`, restart `php-fpm@<runtime>` once so discovery can verify the running master again ([runtimes](runtimes.md)), and restart each running `haproxy-site@<id>` so its loaded execution evidence is bound again. A restarted proxy loads its persisted server state and reports that server's check-health counter, which discovery accepts as an integer.

## After a change stopped partway

A run that has not finished shows **Outcome being reconciled**. Until it is closed, Barectl runs no discovery and accepts no new review for that server: the server's page says that Barectl is running another remote operation, and the site's **Settings** links the run. Follow these steps in order.

1. Open the run's page in Barectl and choose **Check outcome**. It inspects the original unit and its journal and submits nothing new. A result line in the journal ends the run as succeeded, refused before any change, partly applied or failed. When systemd no longer has the unit and the journal has no result line, the outcome stays unknown: missing evidence is never taken as proof that nothing ran. If the journal holds the run's stage lines, the page says that the run reached the server and names the last stage it reported.
2. Read the run's own record with `journalctl -u barectl-apply-<32 hex>`, the unit name on the run's page. Each run prints its stages as `barectl-stage <name>` lines and its result as one `barectl-result` line. A run that was killed shows its stage lines and systemd's `code=killed` line, without a result line. `systemctl status` shows the unit only while it runs.
3. Read the paths the change touches with `ls -l`, `stat` and `cat` before changing anything.
4. Close the run. A run whose outcome stays unknown closes only as **outcome unknown**, never as unchanged: choose **Close as outcome unknown** on its page. Barectl closes it only after it takes the mutation lock and proves that no barectl run has processes and that the run can no longer start, because the server restarted or the review's admission deadline passed on the server's clock. The page shows when the deadline passes; before then the run stays reconciling, and you acknowledge again afterwards.
5. Choose **Refresh observations** on the server's page. Discovery reads the server as it is now.
6. Prepare a new review. It proposes only what is missing; it never adopts or replaces a resource that differs from the convention. For a PHP selection, open the site's **Settings**, which shows **Finish or reverse the PHP change**, choose the runtime to keep and prepare the review.

The shared mutation lock is `/run/lock/barectl/mutation.lock`. It is empty, holds no state and disappears at reboot. Every run takes it with `flock`, whose helper process exits once the lock is taken, so `lslocks` and `/proc/locks` do not list the holder. This lists every process whose open lock file carries the lock, with its unit:

```sh
for fd in /proc/[0-9]*/fd/*; do
  [ "$(readlink "$fd")" = /run/lock/barectl/mutation.lock ] && grep -q '^lock:' "${fd%/fd/*}/fdinfo/${fd##*/}" && ps -o pid=,unit=,comm= -p "$(echo "$fd" | cut -d/ -f3)"
done 2>/dev/null; true
```

No output means no process holds it. Barectl's read-only commands take the lock shared for a moment, so a line can also name a discovery's or a review's short read in an SSH session.

| Change | What a stop leaves, and how to resolve it |
| --- | --- |
| Set up server | An Incomplete foundation. A new review keeps the stages that exist in their supported form and proposes the rest. A Nix installation that stopped inside the installer is refused as incomplete; follow the [official uninstall steps](https://nix.dev/manual/nix/2.35/installation/uninstall.html), then set up again. |
| Add runtime | The profile may exist without a running, verified master. **Server Advanced → PHP runtimes** names the problem, and a new review refuses while it remains. Check `systemctl status php-fpm@<runtime>`, fix the cause, restart the master and run discovery. A Node runtime starts no service. |
| Create HTTP site | Part of the site's accounts, directories, configuration and services. Discovery reports the site as partly applied, and a new review creates only what is missing. A failed Caddy reload already restored the previous files. |
| Site PHP selection | An incomplete transition: both masters may run, and HAProxy's state shows which serves ([which PHP master serves a site](#which-php-master-serves-a-site)). The site's **Settings** shows it; choose the intended runtime and prepare a fresh review to finish or reverse it. Barectl never kills remaining PHP work to complete a switch. |
| Site Node selection, server defaults | A mixed set of links. The page reports it as interrupted, and a new review repairs it. Barectl never overwrites a link or wrapper it does not recognize. |
| Any change that pauses background work | The site's scheduled tasks stay stopped. Discovery reads the runtime mask and the site's Overview says **Paused by an unfinished change**, with the newest change to the site that did not finish when this device recorded it; a fresh controller shows only that sentence. Lifting it is the ordinary **Scheduled tasks** change, which asks what state the work should have and preselects nothing. A run that reports **partial** with the site's work stopped is the same case. |
| A change inside the maintenance page (Deploy, Roll back) | Visitors keep the maintenance page and the site's background work stays masked with boot activation off for its timers and its worker services, so a reboot cannot restart it. Read the run's journal, then prepare a new Deploy or Roll back: it starts the work again only after `/up` answers on the switched release. Turning the work back on before the site serves again would run scheduled work against a half-migrated release. |

## Unknown outcomes and reboots

A run whose outcome is unknown, after a lost answer, a reboot or an unreadable unit, stays reconciling until **Check outcome** establishes it from the same unit and its journal. After a reboot, or once the review's admission deadline has passed, the run can no longer start, so Barectl closes it as outcome unknown once an operator allowed to apply it acknowledges that; it never records success or "no changes" for it. Run discovery afterwards: it reconstructs the foundation, runtimes and sites from native evidence and names anything it cannot read. A fresh controller with authorized SSH access reconstructs the same state, but not another controller's private history.

## What is never promised

Barectl never removes a site, account, runtime or file automatically, never replays a lost request, never adopts a resource that differs from the convention, and never rebuilds lost application data. When native evidence is gone, the outcome stays unknown and the repair is ordinary administration.
