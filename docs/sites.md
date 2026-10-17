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

Each site has **Overview**, **Runtime** and **Activity** pages at `/servers/<pk>/sites/<identifier>/<section>/`. Overview shows the observed names, account and convention conformity with the collection time. Runtime offers [PHP selection](runtimes.md#site-php-selection) and [Node selection](runtimes.md#site-node-selection) for the site. Activity lists the changes this controller recorded for the identifier; it is history, not proof of the current site.

Barectl does not delete sites, rename them, change their names or deploy application code yet.
