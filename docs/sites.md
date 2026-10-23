# Creating a PHP site

On a target-stack host with at least one verified PHP runtime, an operator can create a plain PHP site served over HTTPS by Caddy's automatic HTTPS. The site follows the [native site convention](site-conventions.md): its own Linux account, directories, PHP-FPM master, private HAProxy admission and Caddy site file. Preparing reads the server; applying runs the reviewed change as one native unit and verifies that the site serves. Databases and application installation are not available yet ([roadmap](../ROADMAP.md)).

## Creating a site

Open the server's **Sites** section, or the global **Sites** page, and use **Create HTTP site**. Enter:

- **DNS names**: the primary domain first, then up to nine aliases, separated by spaces or new lines.
- **Site identifier**: derived from the primary domain and editable; see [names](#names).
- **PHP runtime**: an installed runtime whose master the current observation verified, `php84` or `php85`. The form preselects the server's default PHP when the current observation verifies it ([server defaults](runtime-defaults.md)). Add a runtime from **Stack** first if none is listed ([runtimes](runtimes.md)).

**More options** holds **Serve over HTTP only**, off by default. Leave it off to serve the site over HTTPS with a certificate [Caddy issues and renews](tls.md); turn it on only for a test site before DNS points here.

**Prepare HTTP site review** queues a preparation and changes nothing on the server. Invalid input is refused before anything is queued, with each problem next to its field and the entered values kept.

## Names

- The identifier is 3 to 24 lowercase ASCII letters and digits, starting with a letter. Uppercase is refused, not lowered.
- Reserved identifiers: `www`, `html`, `default`, `php`, `fpm`, `nginx`, `root`, `admin`, `localhost`, `letsencrypt`, `acme`, `barectl`, `diagnostic`, and `apply`, `site`, `repo` and `backup`, which the native unit names of [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md) need. An identifier is also refused when its site user `s<identifier>` would take the name of a system account that Ubuntu creates (`sshd`, `syslog`, `statd`, `saned`, `sssd`, `snmp`, `squid`, `sddm`, `stunnel4`, `sasl`, `sgx`), such as `shd` or `yslog`.
- Each name is an explicit DNS name of at least two labels and at most 253 characters. Letters are lowered and one trailing dot is dropped. Wildcards, IP addresses, underscores, `localhost` and `invalid` names, and duplicates are refused. Enter an international name in its punycode (`xn--`) form.
- A name belongs to one site. A name another site on the server already serves refuses the review.

## The review

Preparation reads the server as root, or through noninteractive sudo of each fixed read; without that privilege the review is refused. It runs Caddy's validation of the whole site tree with the candidate file swapped in, and PHP-FPM's syntax check of the candidate pool, in private scratch copies that change nothing live.

The review shows the site account and its reviewed numeric UID and GID, the directory layout and permissions, the command wrappers, the PHP pool, the Caddy site file, the HTTPS setting and both validation results. For an HTTPS site it resolves each requested name through the server's own resolver: a name that does not resolve to the server is a warning the operator acknowledges, never a refusal, because a proxy or CDN is legitimate ([HTTPS](tls.md#dns)). Its consent level follows its effects ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)):

- The first site on a server is a **Site** change: it touches only that site's resources.
- When other sites exist, publishing the new Caddy file is a **Shared** effect, because Caddy reloads its configuration for every site. The review lists those sites; Caddy keeps serving them and no other site's HAProxy or PHP-FPM restarts.

A review is refused, with each reason, when the host is not Target stack, the runtime is not installed and verified, a name or account is taken, an existing resource differs from the convention, the server's validators are unavailable, or the evidence changed while it was read. A review of a site that already exists in the convention's form proposes no changes.

## Applying

A Site operator applies a Site review; a Shared review needs an Administrator and an explicit acknowledgement of the listed sites ([operator accounts](../README.md#operator-accounts)). The review must be applied within 15 minutes of preparation. The run is a transient systemd unit under the shared mutation lock and continues if the controller disconnects. It reports the stages `preflight`, `account`, `layout`, `pool`, `caddy` and `verify`:

1. Under the lock, recheck the boot, the deadline, the reviewed evidence and the list of affected sites, and refuse without changes if any differ.
2. Create the site and proxy accounts with the reviewed IDs.
3. Create the directories, placeholder files and command wrappers, holding the site's deployment lock.
4. Write the PHP-FPM and HAProxy configuration, start `php-fpm-site-<runtime>@<identifier>` and `haproxy-site@<identifier>`, and enable the selected runtime's admission.
5. Validate the whole Caddy tree with the new file, publish it only if the live file is still what was reviewed, reload Caddy, and check that the running configuration equals the files on disk. A failed reload restores the previous state and keeps the old configuration serving.
6. Verify the site by requesting `index.php` from the server itself for each name through Caddy, over `https://` for an HTTPS site (waiting briefly for Caddy's first handshake to obtain the certificate) and over `http://` for an HTTP-only site, and checking that PHP answers as the site user. Reachability from the internet is not checked.

After a verified run Barectl queues discovery, and the run page links to the site's page once discovery observes it. A run that stopped after its first change is **partly applied**: what it created stays, and the run page names the stage it reached. Discovery reports the site as partly applied, and a new review proposes only what is missing; it never replaces an existing resource. See [native recovery](recovery.md).

## Readiness

A plain PHP site has a **Readiness path** on its Runtime page, `/` by default. After a change Barectl first proves PHP answers as the site's own account through its private admission path, then sends a `GET` for the readiness path with the site's primary Host through Caddy. At `/` any answer below a server error passes, because a home page may redirect or be absent; at another path the answer must be exactly 200. A missing response never passes. A site whose code answers 500 fails the run, and the run page says its readiness path did not answer as required.

A non-default path is written as a `vars readiness_path` entry in the site's own Caddy file, which Caddy applies to every request. It holds no Barectl marker, and discovery reconstructs it from that file alone. Changing it is one **Site** change through the review and confirm screen; the review names the previous and new paths, and the run includes a real request before it succeeds. Create PHP site, a PHP change and a later catalog update use the same check. Laravel sites keep their own `/up` readiness check during Deploy and Roll back.

## PHP settings

A site's Runtime page also holds its **PHP settings**. The form edits the pool tunables the [supported configuration grammar](site-conventions.md#supported-configuration-grammar) already recognizes: the process manager, its children and spare counts, the idle, slow-request and request timeouts, and the memory, upload and post limits. Values outside those bounds are refused before a review is queued and again when the review is prepared. The review is one **Site** change naming the previous and new values. Applying rewrites only the site's own pool file, validates the candidate, and sends a graceful reload to the site's own master, so requests already running finish and no other site's master is touched. The site page then reports the reloaded values from server evidence. A fresh controller reconstructs them from the same pool file; nothing is stored in the controller as authority.

## Removing a site

Open the site's **Settings** section and use **Remove site**. The page states plainly that
the site's files and database data are destroyed and that no backup exists before Phase D.
**Prepare removal review** queues a preparation and changes nothing on the server.

The review lists everything that will be deleted: the Caddy site file, the site's HAProxy
and PHP-FPM configuration and runtime directories, its `haproxy-site@` and
`php-fpm-site-<runtime>@` services, its database and principal, Caddy's stored certificate
for its names, the site directory with every release and private file, and the site and
proxy Linux accounts. It also names the other sites that keep serving while Caddy reloads
its whole configuration. It is Destructive consent, and applying it requires typing the
site's primary domain exactly; a request without that value changes nothing.

Applying is one run: it rechecks the reviewed inventory under the native lock, publishes
the maintenance gate, validates the remaining Caddy tree, removes the site file and reloads
Caddy, stops and disables the site's services, removes its FPM and HAProxy configuration,
drops the database and principal, removes the stored certificate, deletes the site
directory and its accounts, and verifies that nothing remains while the remaining sites
serve. A failure reports **partly applied**; a fresh review names only what remains and
finishes it. The database and all application data are not recoverable after the run.

## Site pages

Each site has **Overview**, **Runtime**, **Deployments**, **Database**, **Settings** and **Activity** pages at `/servers/<pk>/sites/<identifier>/<section>/`. Overview shows the observed names, account, convention conformity, the HTTPS setting and the certificate state ([HTTPS](tls.md#certificate-state)) with the collection time. Runtime offers [PHP selection](runtimes.md#site-php-selection), [PHP settings](#php-settings) and [Node selection](runtimes.md#site-node-selection) for the site. Deployments lists the Laravel releases discovery reconstructed from the server. Activity lists the changes this controller recorded for the identifier; it is history, not proof of the current site.

## Creating a WordPress site

Open the server's **Sites** section and use **Create WordPress site**. It asks for the site's **Primary domain**, **Site title**, **Administrator username** and **Administrator email**, and the PHP runtime; **More options** holds the **Site identifier** and **Serve over HTTP only**. PostgreSQL servers show the tile disabled with the reason that WordPress needs MariaDB.

**Prepare WordPress site review** queues a preparation and changes nothing on the server. The review shows the pinned core release with its size and SHA-256, the site's MariaDB binding, the private configuration path and its permissions, the HTTPS setting and the administrator details. The administrator password is asked for on the confirm screen, not here: it is sent only over the confidential channel and is never stored ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)). The review offers a browser-generated value.

Applying creates the site as a plain PHP site, creates its MariaDB binding, downloads and verifies the pinned WordPress archive, extracts it as the site user, writes the fixed public loader and the private configuration with eight server-generated salts, runs `wp core install` with the password on standard input, stores pretty permalinks, opens the site and verifies the home, login and REST pages over its own HTTPS address. Until verification passes the site is gated. A fresh review of an interrupted install finishes only what is missing and never reinstalls into existing tables ([WordPress](wordpress.md)).

## Creating a Laravel site

Open the server's **Sites** section and use **Create Laravel site**. It asks for the site's **Primary domain**, its **Repository** and its **Branch or tag** (default `main`); **More options** holds the **Site identifier** and **Serve over HTTP only**. The server's database engine is never asked for: a Laravel site needs one, and the review names the engine the server already runs.

The **Repository** is a credential-free `https://` URL or an SSH locator such as `git@github.com:acme/shop.git`. A public HTTPS repository needs no credentials; an SSH repository gets an ed25519 **deploy key** generated on the server as the site user, and only its public half is shown so no private key leaves the server. Paste the repository host's host key fingerprint from your Git host's documentation into **Repository host key fingerprint** ([GitHub's SSH key fingerprints](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)); the review reads the host key the server presents and trusts it only when its fingerprint matches exactly ([ADR 0034](adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md)). A mismatch refuses the review. The review also refuses credentials in a URL, an unsafe reference or Git option, and any transport other than a plain `https://` URL or a fixed `user@host:path` SSH locator.

**Prepare Laravel site review** queues a preparation and changes nothing on the server. The review refuses, with each reason, when the host is not Target stack, the runtime is not installed and verified, a name or account is taken, the server has no database engine, the engine is Outside supported settings, the repository host key does not match, a name already belongs to another site, or the reviewed evidence changed. It shows the repository and branch, the deploy key, the database statements, the private `.env` the site will hold and the first release's Git metadata.

Applying creates, in one run:

1. The site, exactly as a plain PHP site — account, directory layout, PHP-FPM master, private HAProxy admission and Caddy site file.
2. Laravel's shared state in the site's private area: `private/laravel.env`, `private/storage` and `private/cache`.
3. The private `.env` from Laravel 13's production defaults, with `APP_ENV=production`, `APP_DEBUG=false`, the site's `APP_URL`, the socket database connection (`DB_CONNECTION`, `DB_SOCKET` for MariaDB or the socket directory for PostgreSQL, `s<id>` database and user, no password), `LOG_CHANNEL=daily` and `LOG_DAILY_DAYS=14`. The `APP_KEY` is generated once on the server from 32 random bytes and never reaches the controller; a later Deploy never rotates it.
4. For an SSH repository, the ed25519 deploy key pair in `private/`, and the trusted repository host key in `private/known_hosts`, used with strict host checking.
5. The site's database and principal, both `s<id>`, over the local socket, composed from the site-database convention (ADR 0010).
6. A first release, `releases/bootstrap-<token>`, whose Git metadata carries the reviewed repository and branch, with `current` switched to it. It serves a placeholder until the first Deploy; the site is a recognized Laravel application, so **Deploy** is offered on its page.

A review of a site that already exists in this form proposes no changes. A fresh controller reconstructs the site, its repository and branch, its `.env` key names and server-computed digests (never a secret value) and the deploy key's public half from the server alone. The Environment section edits only reviewed keys ([settings](settings.md)).

## Deploying a Laravel site

**Deployments** shows a site's current release and its retained releases, each with its commit, creation time, state and whether it is serving. The list comes from the server's own release layout: a release directory under `releases/`, the `current` link, and each release's Git metadata. A release created by CI in the same layout under the same site lock is listed like Barectl's own. Nothing is read from a Barectl marker, and reading releases never runs PHP, Composer, Git hooks or Artisan.

**Deploy** is one reviewed change. Its read-only review resolves the branch to an exact commit as the site user, states the commit, the free disk the build needs, the releases it will remove and whether pending migrations will run. Pending migrations are computed at apply time by comparing the release's migration files with the migrations table through the site's database principal, without Artisan. The apply fetches exactly the reviewed commit, installs from the committed lock with the site's own Composer and PHP, links the shared environment, storage and cache, builds Laravel's caches, classifies the release so Caddy reads only its public root ([ADR 0040](adr/0040-classify-laravel-release-permissions.md)), and switches `current` under the maintenance page. While the gate answers visitors, the readiness check goes to the site's private HAProxy socket; the gate is lifted only when `/up` answers 200, and a failed check restores the gate and reports which release is serving. Until a native scenario proves code pickup, every Deploy that switches code runs inside the maintenance window. The review removes releases beyond `current` plus the newest five and names them. A `composer.json` requiring a PHP version the site's runtime does not meet is refused at review, naming the requirement.

**Roll back** reactivates a retained release: no fetch, no build, no migrations. Its review states plainly that schema, data, storage, settings and jobs are not reversed, and an apply without that acknowledgement changes nothing.

**Deploy settings** on the same page hold this controller's per-site switches. Turning **Run pending migrations during Deploy** off makes a Deploy report the migrations it finds in the run's journal and leave them unrun. The switch is Barectl's own behavior and lives in Barectl's database ([ADR 0039](adr/0039-keep-per-site-deploy-switches-on-the-controller.md)); a fresh controller starts from the default, migrations run, and every review states the state it will apply.

The Deploy native body is written and the offline fixtures it needs (a Composer mirror, a Git server and an ACME server) exist; a scenario that deploys a Laravel site end to end is [Phase B](https://github.com/rajandangi/barectl/issues/259). Barectl removes sites from **Settings**, and still does not rename them or change their names ([roadmap](../ROADMAP.md)).
