# Native PHP site convention

This is the one layout Barectl creates for a PHP site on a target-stack host and the layout discovery recognizes, whoever made it. Every resource below is ordinary Linux, Caddy, HAProxy, PHP-FPM or systemd configuration; nothing on the server records Barectl's history. [Creating a PHP site](sites.md) describes the workflow, [runtimes](runtimes.md) the shared runtime builds, and [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md) the serving design.

Caddy serves the site's static files and sends PHP requests to a private HAProxy process of the site's own. HAProxy hands them to the site's own PHP-FPM master for its selected runtime over FastCGI. Sites share the read-only runtime builds in the Nix store, never a serving master or its OPcache.

## Identity

The site identifier is 3 to 24 lowercase ASCII letters and digits, starting with a letter ([names](sites.md#names)). It names every resource below and never changes.

| Account | Convention |
| --- | --- |
| Site user `s<identifier>` and its private group | Equal numeric UID and GID, reviewed before creation; home `/var/www/<identifier>`, shell `/usr/sbin/nologin`, locked password, no supplementary groups. PHP code runs as this user. |
| Proxy user `p<identifier>` and its private group | Home `/nonexistent`. The site's HAProxy process runs as this user. |
| `caddy` | Shared system user of the web server. It reads intended public files and connects to each site's HAProxy socket. |

## Site directory

| Path | Owner, group and mode | Purpose |
| --- | --- | --- |
| `/var/www/<identifier>` | root:root 0755 | Site boundary and the site user's home |
| `releases/`, `releases/initial/` | root:root 0755 | Root-controlled release directories |
| `releases/<commit>-<token>` | site user:site group 0711 | A classified Laravel release: directory traversal only, PHP source 0600, and `public/` at site user:caddy 2750 with static files 0640 |
| `current` | root-owned relative link to a release under `releases/` | Caddy and HAProxy serve only `current/public` |
| `current/public` | site user:caddy 2750 | Document root. PHP source is site user only (0600); intended static files are 0640 so Caddy can read them |
| `private/`, `private/sessions/`, `private/tmp/` | site user:site group 0700 | PHP sessions, uploads and temporary files, unreadable by other sites |
| `logs/` | caddy:site group 0750 | `access.json` (Caddy), `php-error.log` and `php-slow.log` (site user, 0640) |
| `bin/` | root:root 0755 | `php`, `composer` and `wp` wrappers bound to the site's PHP runtime, and optional `node`, `npm` and `npx` links |
| `.deploy.lock` | root:site group 0640 | Site deployment lock. Changes to the site hold it with `flock` |

A new site starts with a placeholder `index.php` and `hello.txt` in `current/public`. The `bin/` wrappers run Composer's PHP script and WP-CLI's phar with the site's selected PHP build. The three Node links point to one installed Node profile together; no links means the site has no Node selection, and a mixed set is an interrupted selection.

Barectl does not classify application source or repair permissions during discovery. Deployment must keep PHP source at 0600 and give 0640 only to intended public assets; source made readable to Caddy can be served as a static file. Deploy classifies the release it builds ([ADR 0040](adr/0040-classify-laravel-release-permissions.md)); discovery recognizes a released application by shape — `artisan` plus the shared `.env` and storage links in `current` — verifies that classification, and reports anything else as outside supported settings.

## Serving

| Resource | Path |
| --- | --- |
| Caddy site file | `/etc/caddy/sites/<identifier>.caddy`, root-owned |
| HAProxy configuration | `/etc/haproxy/sites/<identifier>.cfg`, root-only (0600) |
| HAProxy service | `haproxy-site@<identifier>.service`, from the foundation's template `/etc/systemd/system/haproxy-site@.service` |
| HAProxy sockets | `/run/haproxy/<identifier>/http.sock` (caddy:caddy 0600) and the root-only API `/run/haproxy/<identifier>/admin.sock` |
| HAProxy server state | `/var/lib/haproxy/sites/<identifier>.state` |
| PHP-FPM service | `php-fpm-site-<runtime>@<identifier>.service`, from the foundation's templates `/etc/systemd/system/php-fpm-site-php84@.service` and `php-fpm-site-php85@.service` |
| PHP-FPM configuration | `/etc/php-fpm/sites/<identifier>/<runtime>/php.ini`, `php-fpm.conf` and `pools/<identifier>.conf`, plus `pools/diagnostic.conf` |
| PHP-FPM sockets | `/run/php-fpm/sites/<identifier>/<runtime>/app.sock` (root:proxy group 0660), `status/listen.sock` and `diagnostic/listen.sock` (root-only) |

`<runtime>` is `php84` or `php85`. During a PHP switch the site briefly runs both masters; otherwise only the selected one runs.

The Caddy site file serves the site's names over HTTPS by default, using bare host names so Caddy issues and renews a certificate ([HTTPS](tls.md)); an HTTP-only site uses explicit `http://` addresses and requests no certificate. Its route:

- answers 404 for dotfiles and dot-directories except ordinary files under `/.well-known/`, for `wp-config.php` with or without path info, and for PHP-like names (`.php`, `.php7`, `.phtml`, `.phar` and similar) under `/wp-content/uploads/`;
- rewrites `/` to `/index.php`, sends paths containing `.php` to the site's HAProxy socket, and serves everything else as static files with zstd or gzip compression;
- writes a JSON access log to `logs/access.json`, rotated at 20 MiB with 5 files kept for 14 days, with `key`, `token` and `signature` query values replaced by `REDACTED`.

A WordPress site uses a front-controller variant of the route: it tries the requested path, then its `index.php`, then the front controller at `/index.php`, and passes the original request URI to the application in `X-Forwarded-Uri`, so pretty permalinks reach `index.php` while WordPress still sees the requested address. Its public PHP files are group-readable by Caddy so the path check can see them; WordPress core still runs only as the site user.

HAProxy runs one thread (`nbthread 1`) in the foreground with no master-worker mode and no reload. It declares two FastCGI servers, `php84` (ID 1) and `php85` (ID 2), each with at most two connections and disabled by default; the selected one is enabled through the API and the selection persists in the server state file, which HAProxy loads at start. It disables FastCGI keep-alive, sets no request timeouts, strips the `Proxy` header, and passes `REQUEST_URI` from `X-Forwarded-Uri`, `HTTPS` from `X-Forwarded-Proto` and `SERVER_PORT` from the connection, so a front controller can restore the original address.

The master's `php-fpm.conf` runs FPM in the foreground, logs to syslog, includes the site's pools and sets `process_control_timeout = 300s`, the longest `request_terminate_timeout` a pool may have. FPM's default of zero ends running requests as soon as the master stops or reloads; with the longer limit a stop or restart lets each running request finish, and a request still running after 300 s is ended. The unit's stop timeout, 310 s, covers FPM's own final signals after that limit, after which systemd kills what remains, so a change that stops or restarts a master holds the native lock for at most about five minutes, well within an apply's 30-minute limit ([SSH connections](ssh-connections.md)).

The pool runs as the site user with `pm = static`, two children, a cleared environment, `.php` as the only executable extension, a five-second slow-request log, a 300-second request limit and the private session and temporary directories above. `php.ini` enforces the OPcache protections every master needs: permission and root checks on, the OPcache API restricted to root-owned diagnostics, no file cache and no preload. The diagnostic pool runs as the locked `php-probe` user and lets Barectl read the loaded protections and the running PHP build.

## Supported configuration grammar

Discovery reads the site file through `caddy adapt` and compares the adapted JSON with the convention rendered for the same names, so formatting and comment changes are adopted and Barectl needs no Caddyfile parser. Changes inside these bounds to the site's pool are adopted as the administrator's:

| Setting | Supported values |
| --- | --- |
| `pm` | `ondemand`, `static` or `dynamic` |
| `pm.max_children` | 1 to 64 |
| `pm.start_servers`, `pm.min_spare_servers`, `pm.max_spare_servers` | 1 to `pm.max_children`, in that order, for `dynamic` |
| `pm.process_idle_timeout`, `request_slowlog_timeout`, `request_terminate_timeout` | 1s to 300s |
| `php_admin_value[memory_limit]` | 16M to 1024M |
| `php_admin_value[upload_max_filesize]`, `php_admin_value[post_max_size]` | 1M to 256M |

Every other pool setting, and every other file above, must equal the convention. These are reconstruction bounds, not workload sizing. A resource with another setting is [Outside supported settings](../GLOSSARY.md): discovery reports it once against its site and blocks only the changes that depend on it. An unsafe pool identity, socket, include or OPcache override blocks that site's PHP changes.

A site's readiness path is another supported setting in the Caddy file. The default `/` is implied by the absence of the directive. Another path is one `vars readiness_path "<path>"` entry, an absolute path without a query string, fragment or `.`/`..` segment; Caddy applies it to every request. Any other `vars` use is outside the convention.

## Reconstruction

Discovery reads configuration, accounts, directory metadata, service state, the HAProxy API, the server state file and Caddy's stored certificates. It does not request a site's HTTP endpoint or run application PHP. A fresh controller with authorized SSH access reconstructs each site's identity, names, runtime selection, Node selection, HTTPS setting, readiness path and certificate state, and any interrupted PHP switch from that evidence alone. A site with some convention resources missing is reported as partly applied; Barectl does not overwrite what exists.

All sites are read once and then each site's live PHP evidence in its own bounded command, so one unreadable site does not hide the others.

## Limits

Sites are separated by Unix accounts, private directories, their own PHP-FPM masters and admission sockets. They share the kernel, Caddy and the Nix store, and a site user can edit its own content. This is hosting for one owner or a trusted team, not hostile multi-tenancy. The Nix daemon admits only root, the Caddy admin socket is root-only, and Unix permissions deny a site user another site's sockets.
