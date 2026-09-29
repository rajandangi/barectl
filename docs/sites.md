# Creating a PHP site

An operator can prepare and review a plan that creates one HTTP PHP site following the [native site convention](site-conventions.md), then apply it. Preparing the plan only reads the server; applying runs the reviewed changes as one native unit and verifies the site serves. The accepted specification is [v0.3](v0.3.md); the evidence is in the qualification record for [review](v0.3-qualification.md#site-review) and [creation](v0.3-qualification.md#site-creation).

## Permissions

Site plans have their own permissions, separate from bootstrap's:

| Stage | Permissions |
| --- | --- |
| View site plans and their preparations | `servers.view_server` and `sites.view_siteplan` |
| Prepare a site plan | the above and `sites.prepare_siteplan` |
| Apply a site plan, and close a run whose outcome is unknown | the above and `sites.apply_siteplan` |

Bootstrap permissions grant none of these, and site permissions grant no bootstrap plan. An account that may view only bootstrap plans never sees a site plan, its preparation or its line in Activity, and the reverse also holds. An account with inventory access alone sees neither. The worker checks again, before it connects, that the requesting account is active and still allowed to prepare site plans.

## Preparing a site plan

Open the server and use **Site plans**. Enter:

- the **site identifier**, 3 to 24 lowercase ASCII letters and digits starting with a letter. It names the site user and group `s<identifier>`, `/var/www/<identifier>`, the pool and the files. Uppercase letters are refused rather than lowered, so the resources are exactly the ones typed.
- 1 to 10 **DNS names**, separated by spaces or new lines.

Pressing **Prepare site plan** queues a plan preparation; the page follows it and shows the review when the worker finishes. Invalid input is refused before anything is queued, with each problem next to its field.

### Names

- The identifiers `www` and `html` are the distribution's own pool and default document root. `default`, `php`, `fpm`, `nginx`, `root`, `admin`, `localhost`, `letsencrypt`, `acme` and `barectl` are reserved too, as are identifiers whose user would take the name of a system account that Ubuntu's base-passwd or a package in main creates (`sshd`, `syslog`, `statd`, `saned`, `sssd`, `snmp`, `squid`, `sddm`, `stunnel4`, `sasl`, `sgx`), such as `shd` for `sshd` or `yslog` for `syslog`.
- Each name is an explicit DNS name of at least two labels. Letters are lowered and one terminal dot is dropped. Wildcards, IP addresses, underscores and other characters, `localhost` and `invalid` names, and duplicates are refused. An international name must be entered in its punycode (`xn--`) form, which must decode and encode back to the same label.
- A name is at most **46 characters**. Nginx keeps server names in a hash whose bucket size is the CPU cache line, 64 bytes on the supported builds, and the stock `nginx.conf` does not change it. A 47-character name makes `nginx -t` fail with `could not build server_names_hash`. The disposable servers show, on both releases, that the stock configuration loads the default site beside two sites of ten 46-character names each, and not one 47-character name. The site convention forbids editing `nginx.conf` to raise the bound.
- This bound is per name. Applying runs `nginx -t` against the whole server's configuration before any reload, and many sites together may still exceed Nginx's `server_names_hash_max_size`; that check then refuses before the reload. Preparation does not predict it.

## Preparation

Preparation reads the server as root, as the SSH user when that is root or through noninteractive sudo of each fixed read-only command; the permission to prepare site plans is the explicit authority for that privileged read. Most of those commands are `/usr/bin/sh -c <fixed script>`, so the sudo authorization they need is equivalent to a root shell: an SSH user that may run them may run anything as root. Without root or such an authorization the plan is refused for privilege and nothing else is read.

Preparation changes nothing Barectl manages: it runs no `nginx -t` or `php-fpm -t`, which open logs and temporary files, sends no HTTP request, which a site would log, creates no account, stages no file and reloads no service, and the configuration, web, account and service state is unchanged afterwards. The operating system still records the SSH login and each sudo command in its authentication log and journal, as for any administrator. [SSH connections](ssh-connections.md#site-preparation) lists every read.

## Admission

Site admission is separate from the Nginx and PHP bootstrap profiles, which keep refusing any configuration tree that holds a site. A site plan is refused, with every reason and what ordinary administration resolves it, when:

- the server is not a supported release, Nginx or the release's default PHP-FPM and CLI are not installed and configured, another PHP release's packages are present, or `nginx.service` or the PHP-FPM unit is not the distribution's unit, enabled and running without drop-ins;
- anything under `/etc/nginx`, `/etc/php/<version>/fpm` or `/etc/php/<version>/mods-available` is outside the supported grammar: every entry must be a directory only root can write, an unmodified distribution file, a distribution link, a `<identifier>.conf` file that matches a site template byte for byte, or a site's enablement link, absolute or relative as discovery accepts it. An entry on another filesystem than its tree, such as a mount point, refuses too, since the listing cannot see below it. A hand-written site, a file in `conf.d`, a changed `nginx.conf` and a missing distribution file all refuse. The default site must stay enabled, and PHP-FPM must load the `posix` extension, which the serving probe uses;
- a parent directory of the site's paths is not a root-owned directory that only its owner can write (`/run/php` belongs to `www-data`);
- a process other than Nginx listens on port 80, or Nginx does not listen on every IPv4 address;
- the passwd or group database resolves through anything but local files, optionally with systemd, `/etc/default/useradd` sets anything but `SHELL`, `SKEL`, `HOME`, `GROUP` or `CREATE_MAIL_SPOOL=no`, or no normal UID or GID is free;
- another site file declares one of the names, or the TLS convention's certificate paths for the identifier already exist;
- evidence is missing, truncated or changed while it was read;
- the payload applying would submit is larger than 16 KiB.

### Existing resources

When the whole site already exists as the convention specifies, with exactly the requested names, the plan has no changes. This is a layout match, not a claim that the site serves requests. Otherwise Barectl never adopts, completes or removes an existing resource, and never suggests removing one it cannot prove belongs to this site:

- a resource at one of the identifier's derived names that does not follow the convention, such as an existing user `s<identifier>` with another home or an unlocked password, or an unrelated `/var/www/<identifier>`, is a collision: choose another identifier;
- when only part of the site exists and every existing part follows the convention, the plan is refused as an incomplete site, listing what exists and what is missing; check whether an application uses it, then complete it by the convention or remove what is not in use through ordinary administration;
- a complete site with other names or listeners is refused: changing a site's names is not supported in v0.3.

### Account allocation

The account is created by `useradd` with explicit flags, `--user-group --no-create-home --home-dir /var/www/<identifier> --shell /usr/sbin/nologin --no-log-init`, rather than by `adduser`, which reads `/etc/adduser.conf` and runs a local hook script. The review shows the UID and GID ranges from `/etc/login.defs`, how many are free, whether subordinate ID ranges are allocated, and the IDs the allocator would likely choose, which are not guaranteed.

## What a site plan reviews

A site plan shows the server, the action, the plan and convention revisions, when it was collected and its admission deadline, the required authority, the evidence fingerprints and:

- every generated file's complete bytes, path, owner, group and mode, its SHA-256 and that it is absent now: the Nginx site file, the pool, the placeholder page and the temporary probe, and the enablement link with its target;
- the three directories with their owners and modes;
- the account command, attributes and allocation policy;
- the effects: account, directories, files, service reloads (a PHP-FPM reload restarts every pool's workers, including `www` and other sites), HTTP routing, the temporary serving probe and its removal, the pool's fixed limits and the isolation limits, and that nothing is rolled back.

Only fingerprints and short summaries of the server's evidence are kept, never another file's bytes. A plan's deadline is 15 minutes after collection on the server's clock; afterwards the review says so and a new plan is needed.

## Applying

An eligible site plan with changes, before its admission deadline, shows **Apply plan** to accounts with `sites.apply_siteplan`. The CSRF-protected confirmation names the plan, the action, its convention revision, the server and alias, the effects listed above and the deadline. The request queues one apply run for that revision; repeating it shows the same run. It copies the reviewed files with their bytes, directories, account and effects to the run's audit, which stays in Activity after the server's registration is removed. The worker checks again that the account is active and allowed, that the host key is the reviewed one, and that root or noninteractive sudo authorizes both the exact submission and the read that verifies the site afterwards. The run is submitted like any apply run ([SSH connections](ssh-connections.md#applying-sites)), continues on the server if the controller disconnects, and is never submitted again.

The payload, as root under the mutation lock:

1. checks the boot, deadline, other runs and retained runs, and refuses without changes if any fails;
2. recomputes the site digest preparation recorded and refuses on any difference; rechecks that every destination is absent, that the parent directories are root's and writable by nobody else, and that `useradd`, `nginx`, `php-fpm<version>` and the PHP CLI exist;
3. creates the account with the reviewed `useradd` command, then reads back its IDs, entries, groups and locked password, which must match the review and the allocation ranges;
4. creates the directories, then publishes the placeholder and the probe while the document root is still root's, then gives the document root to the site user;
5. publishes the pool, runs `php-fpm<version> -t`, reloads PHP-FPM and waits for the socket, owned by `www-data` with mode 0600;
6. publishes the site file and the link, runs `nginx -t`, and reloads Nginx;
7. requests each name over each reviewed address family, a name no site declares, and the probe, whose answer must be the site user's IDs;
8. removes the probe.

Each file is staged beside its destination and linked into place only while the destination is absent, so nothing is replaced and no backup is made ([ADR 0012](adr/0012-publish-site-files-without-replacing-them.md)). A syntax check that fails is never followed by a reload.

After a successful run the worker verifies, with fresh reads as root: the account and group entries, the locked password and the IDs in range; every directory's and file's owner, mode and bytes; the link and its target; the socket; both services active and running; `nginx -t` and `php-fpm<version> -t`; that the probe is gone; and, unprivileged, that each name returns the placeholder over each family and an unknown name does not. It records the site user's IDs. Discovery is then queued, and shows the site complete when the SSH user can read everything it needs, the password lock included. A repeated review of the same request is a plan without changes.

## Recovering a partial site

A run that stopped after its first change is **partly applied**: the page names the boundary it reached, what exists, and what to check. Barectl never removes an account, a directory or content automatically, never resumes a run, and never adopts a partial site; a new review refuses it as incomplete until ordinary administration completes the site by the convention or removes what is not in use. Only the site's own resources are named below; `<id>` is the identifier, `<version>` the PHP version and `<token>` the probe's.

| Exit | Boundary | What exists, and ordinary administration |
| --- | --- | --- |
| 31 | Account databases locked | Nothing changed. Prepare again after the other tool finishes. |
| 40 | useradd failed after changing the databases | `s<id>` may exist: `getent passwd s<id>`, `getent group s<id>`. |
| 41 | Account unlike the review | `s<id>` exists: `id s<id>`; `userdel s<id>` only if nothing uses it. |
| 42 | Directories | The account, maybe `/var/www/<id>` and its subdirectories: `ls -ld /var/www/<id> /var/www/<id>/*`. |
| 43 | Content | Also the placeholder or probe, maybe a stage `.<name>.<unit>` in `public`: remove `probe-<token>.php` and stages. |
| 44 | Pool file | Maybe a stage `.<id>.conf.<unit>` in `/etc/php/<version>/fpm/pool.d`; PHP-FPM not reloaded. |
| 45 | Pool rejected and withdrawn | The account, directories and content; the configuration is valid. |
| 46 | Pool rejected | PHP-FPM not reloaded: `php-fpm<version> -t`; remove `pool.d/<id>.conf` if it is the cause. |
| 47 | PHP-FPM reload failed | The pool is published: `systemctl status php<version>-fpm`, `journalctl -u php<version>-fpm`. |
| 48 | Socket missing | PHP-FPM reloaded: `ls -l /run/php/s<id>.sock`, `journalctl -u php<version>-fpm`. |
| 49 | Site file | The pool is active; maybe a stage `.<id>.conf.<unit>` in `/etc/nginx/sites-available`; the site is not enabled. |
| 50 | Link | `sites-available/<id>.conf` exists: `ls -l /etc/nginx/sites-enabled/<id>.conf`. |
| 51 | Site rejected and link withdrawn | The site file remains, not loaded; the configuration is valid. |
| 52 | Site rejected | Nginx not reloaded: `nginx -t`; `rm /etc/nginx/sites-enabled/<id>.conf` if it is the cause. |
| 53 | Nginx reload failed | Everything is published: `systemctl status nginx`, `nginx -t`. |
| 54 | Not serving as reviewed | Everything is published and reloaded; the probe was removed. Check permissions and `journalctl -u nginx`. |
| 55 | Probe left | The site may serve, but verification is incomplete: inspect and `rm /var/www/<id>/public/probe-<token>.php`. |

A run that timed out, was killed or was lost to a reboot has no boundary; its outcome may be unknown ([outcome unknown](ssh-connections.md#applying-reviewed-plans)). Prepare a new plan to see what exists.

### Limits

The mutation lock is cooperative: it excludes runs from every controller and alias that uses it, and the payload rechecks each destination and its directory immediately before publishing, but a root administrator writing outside the lock between that check and the publication is not serialized. A PHP-FPM reload restarts every pool's workers; an Nginx reload lets old workers finish their requests. Nginx's server name hash is checked by `nginx -t` for the whole server; many sites together may exceed its maximum size, which then refuses before the reload (exit 51 or 52).
