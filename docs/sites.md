# Reviewing a PHP site

An operator can prepare and review a plan that would create one HTTP PHP site following the [native site convention](site-conventions.md). Preparing the plan only reads the server. Barectl does **not** apply site plans yet: no page offers an apply action, and a request to apply one is refused. The accepted specification is [v0.3](v0.3.md); the evidence for this slice is in the [qualification record](v0.3-qualification.md#site-review).

## Permissions

Site plans have their own permissions, separate from bootstrap's:

| Stage | Permissions |
| --- | --- |
| View site plans and their preparations | `servers.view_server` and `sites.view_siteplan` |
| Prepare a site plan | the above and `sites.prepare_siteplan` |
| Apply a site plan (not offered yet) | the above and `sites.apply_siteplan` |

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

Not offered. Preparation builds the complete payload applying would submit, with the actual boot and deadline, to prove it fits one 16 KiB submission, and records its size; the longest admitted request, ten 46-character names and a 24-character identifier, leaves more than 2 KiB. The disposable servers run its file publication helpers as root against a scratch tree: a file is published only into a root-owned directory that neither its group nor others can write, whose group may be the document root's `www-data`, only while the destination is absent and only when the staged bytes match the reviewed digest. The payload rechecks, as root under the mutation lock, the same digest command preparation recorded. The apply path, its fault boundaries and its qualification are separate work.
