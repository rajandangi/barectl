# Creating a PHP site

On a target-stack host with at least one verified PHP runtime, an operator can create a plain PHP site served over HTTP. The site follows the [native site convention](site-conventions.md): its own Linux account, directories, PHP-FPM master, private HAProxy admission and Caddy site file. Preparing reads the server; applying runs the reviewed change as one native unit and verifies that the site serves. HTTPS, databases and application installation are not available yet ([roadmap](../ROADMAP.md)).

## Creating a site

Open the server's **Sites** section, or the global **Sites** page, and use **Create HTTP site**. Enter:

- **DNS names**: the primary domain first, then up to nine aliases, separated by spaces or new lines.
- **Site identifier**: derived from the primary domain and editable; see [names](#names).
- **PHP runtime**: an installed runtime whose master the current observation verified, `php84` or `php85`. The form preselects the server's default PHP when the current observation verifies it ([server defaults](runtime-defaults.md)). Add a runtime from **Stack** first if none is listed ([runtimes](runtimes.md)).

**Prepare HTTP site review** queues a preparation and changes nothing on the server. Invalid input is refused before anything is queued, with each problem next to its field and the entered values kept.

## Names

- The identifier is 3 to 24 lowercase ASCII letters and digits, starting with a letter. Uppercase is refused, not lowered.
- Reserved identifiers: `www`, `html`, `default`, `php`, `fpm`, `nginx`, `root`, `admin`, `localhost`, `letsencrypt`, `acme`, `barectl`, `diagnostic`, and `apply`, `site`, `repo` and `backup`, which the native unit names of [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md) need. An identifier is also refused when its site user `s<identifier>` would take the name of a system account that Ubuntu creates (`sshd`, `syslog`, `statd`, `saned`, `sssd`, `snmp`, `squid`, `sddm`, `stunnel4`, `sasl`, `sgx`), such as `shd` or `yslog`.
- Each name is an explicit DNS name of at least two labels and at most 253 characters. Letters are lowered and one trailing dot is dropped. Wildcards, IP addresses, underscores, `localhost` and `invalid` names, and duplicates are refused. Enter an international name in its punycode (`xn--`) form.
- A name belongs to one site. A name another site on the server already serves refuses the review.

## The review

Preparation reads the server as root, or through noninteractive sudo of each fixed read; without that privilege the review is refused. It runs Caddy's validation of the whole site tree with the candidate file swapped in, and PHP-FPM's syntax check of the candidate pool, in private scratch copies that change nothing live.

The review shows the site account and its reviewed numeric UID and GID, the directory layout and permissions, the command wrappers, the PHP pool, the Caddy site file and both validation results. Its consent level follows its effects ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)):

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
6. Verify the site by requesting `index.php` from the server itself for each name through Caddy, and checking that PHP answers as the site user. Public DNS and reachability from the internet are not checked.

After a verified run Barectl queues discovery, and the run page links to the site's page once discovery observes it. A run that stopped after its first change is **partly applied**: what it created stays, and the run page names the stage it reached. Discovery reports the site as partly applied, and a new review proposes only what is missing; it never replaces an existing resource. See [native recovery](recovery.md).

## Site pages

Each site has **Overview**, **Runtime**, **Deployments** and **Activity** pages at `/servers/<pk>/sites/<identifier>/<section>/`. Overview shows the observed names, account and convention conformity with the collection time. Runtime offers [PHP selection](runtimes.md#site-php-selection) and [Node selection](runtimes.md#site-node-selection) for the site. Deployments lists the Laravel releases discovery reconstructed from the server. Activity lists the changes this controller recorded for the identifier; it is history, not proof of the current site.

## Deploying a Laravel site

**Deployments** shows a site's current release and its retained releases, each with its commit, creation time, state and whether it is serving. The list comes from the server's own release layout: a release directory under `releases/`, the `current` link, and each release's Git metadata. A release created by CI in the same layout under the same site lock is listed like Barectl's own. Nothing is read from a Barectl marker, and reading releases never runs PHP, Composer, Git hooks or Artisan.

**Deploy** is one reviewed change. Its read-only review resolves the branch to an exact commit as the site user, states the commit, the free disk the build needs, the releases it will remove and whether pending migrations will run. Pending migrations are computed at apply time by comparing the release's migration files with the migrations table through the site's database principal, without Artisan. The apply fetches exactly the reviewed commit, installs from the committed lock with the site's own Composer and PHP, links the shared environment, storage and cache, builds Laravel's caches, classifies the release so Caddy reads only its public root ([ADR 0040](adr/0040-classify-laravel-release-permissions.md)), and switches `current` under the maintenance page. While the gate answers visitors, the readiness check goes to the site's private HAProxy socket; the gate is lifted only when `/up` answers 200, and a failed check restores the gate and reports which release is serving. Until a native scenario proves code pickup, every Deploy that switches code runs inside the maintenance window. The review removes releases beyond `current` plus the newest five and names them. A `composer.json` requiring a PHP version the site's runtime does not meet is refused at review, naming the requirement.

**Roll back** reactivates a retained release: no fetch, no build, no migrations. Its review states plainly that schema, data, storage, settings and jobs are not reversed, and an apply without that acknowledgement changes nothing.

**Deploy settings** on the same page hold this controller's per-site switches. Turning **Run pending migrations during Deploy** off makes a Deploy report the migrations it finds in the run's journal and leave them unrun. The switch is Barectl's own behavior and lives in Barectl's database ([ADR 0039](adr/0039-keep-per-site-deploy-switches-on-the-controller.md)); a fresh controller starts from the default, migrations run, and every review states the state it will apply.

The Deploy and Roll back native bodies are written but not yet qualified: the test harness has no offline Composer mirror, Git server or ACME server, so no native lifecycle scenario has run. Barectl still does not delete sites, rename them or change their names, and Laravel creation, databases and HTTPS are later slices ([roadmap](../ROADMAP.md)).
