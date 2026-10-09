# WordPress

WordPress arrives on a server in reviewed steps: the authenticated WP-CLI command-line tool, a prepared convention site's PHP runtime baseline, and then the site's WordPress application itself. Barectl also reconstructs a site's WordPress application from the server without running it. This guide covers the [WP-CLI tool setup](#wp-cli-setup), the [PHP runtime](#php-runtime), [passive application discovery](#passive-application-discovery) and the [installation review](#installation-review), which proposes the application's installation in full but cannot yet execute it; the [v0.4 specification](v0.4.md) owns the complete design, and the [native design](wordpress-native-design.md) owns the literal pins and command constraints it enforces.

The tool setup prepares only the tool. It installs no PHP extension, no WordPress and no site resource, and it does not run WordPress or the tool at any point. The PHP runtime plan prepares only the selected site's PHP extensions; it installs no tool, no WordPress, no database and no certificate.

## WP-CLI setup

Open the server's **Advanced** section and press **Prepare WP-CLI setup plan** in the **WordPress** section. The worker reads the server as root or through noninteractive sudo and changes nothing. The review pins one exact release, currently WP-CLI 2.12.0:

- the official PHAR and its detached signature, downloaded from the release's own GitHub URLs during apply, never at review time;
- the published release signing key and the approved primary fingerprint `63AF7AA15067C05616FDDD88A3A2E8F226F0BC06` ([WP-CLI's verification guide](https://make.wordpress.org/cli/handbook/guides/verifying-downloads/)); the fingerprint, not the download location, is the trust anchor;
- the authenticated artifact's SHA-256 `ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c`, which GitHub also records; and
- the protected installation: `/usr/local/lib/wp-cli/wp-cli-2.12.0.phar`, root:root 0644, under root-owned non-writable ancestry.

A new pin (a security release, or a legitimately rotated signing key) is a reviewed change to Barectl, not something apply resolves; `latest` is never resolved on the server.

### What the review refuses

Preparation refuses rather than repairs:

- **Foreign tools.** The reviewed path exists with other bytes, another mode or owner, a foreign directory layout, or files in the installation directory that Barectl did not publish. Barectl never overwrites another tool, adopts its files or self-updates WP-CLI; correct or remove them through ordinary administration, then prepare again.
- **Missing native tools.** `/usr/bin/gpg` and `/usr/bin/curl` must exist; the run authenticates and downloads with them. Install them through ordinary administration; the setup installs no package.
- **Unsafe ancestry.** The installation path's directories must be root-owned and non-writable by others.
- **Incomplete evidence.** A read that fails, or a state that changes while it is read, prepares again later.

### Applying

Apply submits one transient systemd unit under the shared mutation lock, exactly as every bootstrap change ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). In order, the unit: rechecks the reviewed tool state (drift refuses), checks `gpg` and `curl`, fetches the published key into a private temporary keyring under `/run` and requires exactly one key with the approved primary fingerprint, neither revoked nor expired; downloads the PHAR and its signature; verifies the signature natively, requiring the actual signer to be the approved primary or one of its bound signing subkeys, and the artifact's SHA-256 to be the reviewed one; and only then creates the installation directory (root:root 0755) when absent, stages the authenticated artifact beside its destination and links it into place while the destination is still absent. The artifact is never executed in any step, including verification, which reads its bytes, owner and mode instead of running it. The run's journal records the signing identity that authenticated the release; the run's audit keeps the reviewed pins.

A matching installation an administrator created by hand is accepted without changes: identity is the reviewed path, owner, mode and digest, not a Barectl record.

The refusals that stop before any change (exit statuses 31–34 in the unit's journal) mean: the native tools are missing; the published key did not authenticate as the approved identity (an unapproved key rotation refuses); the artifacts did not authenticate; or an artifact could not be downloaded. Nothing is installed; prepare again after correcting the cause.

### Recovering a partial tool setup

A run that stopped at the publication boundary (exit status 35) may leave a staged file named `.wp-cli-2.12.0.phar.<unit>` beside the destination, and the run's private directory under `/run` survives only until the server restarts; both are safe to remove through ordinary administration. Nothing else is left: no package, service or site changed. A new plan reviews what exists and installs only what is missing.

## PHP runtime

Open a site's **WordPress** section (`/servers/<pk>/sites/<identifier>/wordpress/`) and press **Prepare WordPress PHP runtime plan**. The section shows the PHP branch the site's own native configuration selects, links the hosting prerequisites that are not observed (the site's MariaDB database and HTTPS, and the server's authenticated WP-CLI setup), and keeps the time and result of the last capability read. A prerequisite link only opens its own workflow; nothing here installs WP-CLI, WordPress, a database or a certificate.

The worker reads the server as root or through noninteractive sudo and changes nothing. It reads the site's native selection afresh and reviews, for that branch only, the Ubuntu packages `php<branch>-mysql`, `-curl`, `-xml`, `-mbstring`, `-zip`, `-gd` and `-intl` as one exact package transaction ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)). The review lists each package and its full dependency closure at exact versions, requests the missing packages at the installed `php<branch>-common` version so it never upgrades PHP, and keeps the existing authentication, drift checks and automatic-mark preservation of every bootstrap package plan. Already installed packages are not touched: a server that satisfies the baseline is a plan without changes, and nothing can be applied.

The baseline capabilities, as PHP's `extension_loaded` names them, are `mysqli`, `curl`, `dom`, `xml`, `mbstring`, `zip`, `gd` and `intl`, which the packages enable, and `json`, `hash`, `fileinfo` and `exif`, which the PHP build and `php-common` provide. The review shows each capability's package, whether the selected CLI (`php<branch> -m`, run with a clean environment) and PHP-FPM (`php-fpm<branch> -m`) load it now, and the state **Enabled**, **Installed by this plan** or **Not available**, with the time of the read. Imagick, Redis, external object caches, mail delivery and plugin-specific requirements are optional outside this baseline and are not shown as installed.

### What the review refuses

Preparation refuses rather than repairs:

- **An incomplete or changed site.** The site must be a complete convention site whose observation is current; a changed Nginx branch, pool or socket after review refuses the run before any package changes.
- **Missing PHP.** The PHP profile's FPM and CLI must already be installed and PHP-FPM running; the plan never installs PHP.
- **Missing build capabilities.** `json`, `hash`, `fileinfo` and `exif` must already load in the CLI and PHP-FPM. A plan cannot add them, so a build without them is refused and left to ordinary administration.
- **Disabled or customized modules.** A baseline package whose modules are not linked from both SAPIs, or are not loaded by the CLI or PHP-FPM, is refused, naming `phpenmod`; so is any file under the branch's configuration that is neither the distribution's nor a Barectl site pool, since the reload loads it into every pool.
- **Package changes.** Upgrades, downgrades, removals, held packages, other release's packages, other archives and a `php<branch>-common` the archive no longer offers the baseline for (the plan names the upgrade to run through ordinary administration) are refused.
- **Unqualified or third-party supply.** A branch, source or architecture that has not completed native qualification is refused, and so is a site that selects PHP from the approved unified PHP source: the WordPress baseline is reviewed only for Ubuntu's own packages and does not widen the third-party PHP allowlist.

### Applying a runtime plan

The run is a package run ([applying package profiles](ssh-connections.md#applying-package-profiles)): under the mutation lock it rechecks the APT, package and selected-site digests, installs exactly the reviewed transaction through the guard, runs `php-fpm<branch> -t` as root and reloads `php<branch>-fpm.service`, which restarts the workers of every pool of that branch and no other PHP branch. It then briefly publishes a probe, `/var/www/<identifier>/wpprobe-<token>.php`, owned by root and the site's group with mode 0640, outside the document root and never served by Nginx. As root it asks the site's own pool through its FastCGI socket, and the selected CLI `/usr/bin/php<branch>` run as the site user with a clean environment, which capabilities each loads, and requires both to report every baseline capability. Finally it removes the probe.

After a succeeded run Barectl reads the server again as fresh evidence: the packages at their reviewed versions, their automatic and manual marks, the active unit, the conf.d links, the baseline capabilities in `php-fpm<branch> -m` and `php<branch> -m`, and every reviewed pool's socket. The run page therefore shows the transaction's effects and its execution outcome first, and the verified readiness, with its time, separately.

| Exit | Meaning | Recovery |
| --- | --- | --- |
| 15 | The APT configuration, packages, marks, indexes, units, PHP configuration, sockets or the selected site changed after review; nothing was installed. | Prepare a new plan. |
| 20, 21, 23 | As for any package run: dpkg changed packages without completing, the guard refused APT's transaction, or APT failed before dpkg. | As [bootstrapping a server](bootstrap.md) describes. |
| 24, 26 | The packages were installed, but the configuration check failed or the reload failed. | As for a [driver plan](databases.md#applying-a-driver-plan). |
| 41 | The packages were installed and the pools reloaded, but the probe could not be published or its preconditions no longer held. | Inspect the unit's journal and the site directory, then prepare again. |
| 42 | The packages were installed and the pools reloaded, but the site's pool or the selected CLI did not report every baseline capability. | Inspect the pool's configuration and the unit's journal through ordinary administration, then prepare again. |
| 43 | The capabilities were checked, but the probe could not be removed. | Remove the leftover `wpprobe-*.php` from the site directory through ordinary administration. |

A run that stopped after the package transaction is not rolled back and never resumed; a new plan reviews what exists and installs only what is missing. A missing unit record leaves the run reconciling, and **Check outcome** inspects the same unit and never submits it again.

The plan's preparation records the site's identifier in a typed request, so the site's Activity lists the plan and its run, and the run keeps its reviewed packages, capabilities, probe digest and verification after the server's registration is removed. Earlier site, database and WordPress plans are invalidated by the PHP configuration change: prepare them again.

### Permissions

The tool setup and the runtime plan use Barectl's bootstrap permission contract: viewing their plans needs `servers.view_server` and `bootstrap.view_configurationplan`, preparing them `bootstrap.prepare_configurationplan`, and applying them `bootstrap.apply_configurationplan`. The site's WordPress section needs `discovery.view_siteobservation` and shows the runtime card to accounts that may view configuration plans; the [application evidence](#passive-application-discovery) card needs its own permission, and neither permission shows the other's card. Its preparation endpoint and poll check the account's permissions again on every request, and a site the last complete observation does not show, or whose observation a later connection check doubts, is neither prepared nor shown as current. None of these grants any WordPress execution; inspection and maintenance permissions, on the site's page, are defined separately when those workflows land.

## Passive application discovery

Every discovery that reads a convention site also reads its WordPress application, whoever created it: an application an administrator made by hand is recognized when its resources match the [WordPress private configuration](site-conventions.md#wordpress-private-configuration) and [forms](site-conventions.md#wordpress-forms), and a fresh controller reconstructs it without the first controller's database. The evidence is the **WordPress** section of the site's page, for accounts with `servers.view_server`, `discovery.view_siteobservation` and `discovery.view_siteapplicationobservation`. Each of the three is required. The application permission alone shows nothing, and the site and server pages, Activity and discovery history never carry application information without it.

The section shows one state, the time the evidence was collected, the facts behind it, the resources that block dependent actions and the evidence Barectl could not read:

| State | Meaning |
| --- | --- |
| Absent | No WordPress file, private configuration, core table or routing form exists. |
| Candidate, unverified | WordPress release files exist and nothing else does. File presence, or a `version.php` literal, is never proof of an installation. |
| Partial | Some operative resources exist and the evidence is incomplete: for example the private configuration without core tables, tables without files, or the gate or WordPress routing in the site file alone. |
| Installed | The release files, the fixed public loader, the private configuration in its supported grammar, a satisfied MariaDB binding, every required core table and column, and equal canonical `siteurl` and `home` options all match. |
| Blocked | A resource was edited or is ambiguous, such as a public `wp-config.php` that is not the loader, a private configuration beyond the grammar, a core table missing a column, a second WordPress table prefix in the database, a PostgreSQL binding or options that are not the site's canonical HTTPS name. Dependent actions stay blocked until ordinary administration restores the supported form. |
| Unreadable | Barectl could not read evidence it needs: a lesser SSH identity, an unreadable directory, a stopped database or an answer in another format. Unreadable is neither absence nor proof of an installation. |

The application state is independent of the site's infrastructure state. Changed WordPress content never makes the site's Nginx, PHP-FPM, account or certificate resources look changed, and an edited loader never marks the site itself changed. The section also shows the site file's routing (generic PHP, the provisioning gate or WordPress), the canonical name the file declares, the core version, and how it compares with the qualified WordPress 7.1.3 and WP-CLI 2.12.0 pair. A newer core than the qualified one is reported as found: it is never downgraded, and installation, Finish and maintenance need the qualified pair.

Discovery reads only bounded native evidence:

- the entry names of the site's `public` and `private` directories, and the owner, group, mode and link count of the two `wp-config.php` files;
- one fixed script (`python3 -I -c`, with the validated identifier as its argument) that runs on the server. It opens the public loader, the private configuration and `wp-includes/version.php` as data without following links, compares the loader with its fixed bytes, checks the private configuration line by line against its grammar, and prints only fixed tokens: the loader's and configuration's state, the configuration's SHA-256 digest when supported, the first refused line number otherwise, and the version literal. The private configuration, its salts and its refused content never leave the server; and
- fixed, read-only MariaDB queries as root: the names and columns of the twelve `wp_` core tables, the count of other table prefixes with their own users and options tables, and the `siteurl` and `home` options. No user, content, salt or other option row is read, and tables a plugin adds to the same database are neither listed nor read.

Discovery never runs WP-CLI, includes application PHP, evaluates the configuration, uses sudo or reads an earlier snapshot in place of evidence it could not get. The private configuration and the catalogs are readable only to root or the site user, so a lesser SSH identity sees an unreadable application, with the reason, and an account allowed to prepare plans does not make ordinary discovery read more. A configuration or loader that would run code if evaluated is read as text, found beyond the grammar and reported as blocked.

This is the opposite of an explicit inspection. Passive evidence reports what the files and database hold at the time of the last connection check, as a snapshot; it does not load plugins, list them or check core integrity. Inspecting the application, which runs its PHP, is a separate operation that needs its own authorization.


## Installation review

An installation review is the complete, immutable proposal to install WordPress at the root of one HTTPS name of a prepared site. It reads the server and changes nothing, runs no WordPress, WP-CLI or application PHP, and cannot be applied yet: no apply action is offered, and the plan page says so. A later installation consumes exactly the saved review rather than rebuilding it.

Open the site's **WordPress** section and use the **Install WordPress** card. It first lists the prerequisites as last observed, each with the time of its observation: the convention site, its MariaDB binding and its HTTPS certificate from the site's last connection check, and the PHP runtime and WP-CLI from the latest runtime and setup plans for accounts that may view configuration plans. These are snapshots, not live status; the review rereads every one of them and prepares none, so an unmet prerequisite links its own workflow.

### What you enter

The form asks for four bounded values and nothing else. There is no password, version, command or flag field.

| Field | Accepted |
| --- | --- |
| Canonical HTTPS name | One name the site serves and its certificate covers, as a bare name or `https://<name>/`. Credentials, ports, paths, queries, fragments, other schemes, IP addresses and wildcards are refused rather than trimmed. |
| Site title | 1 to 100 characters without control characters, `<`, `>` or backslashes. |
| Administrator login | 3 to 60 lowercase letters, digits, dots, underscores or hyphens. |
| Administrator email | A plain address of at most 100 characters. |

The form, the worker before it reads anything, and a later installation each validate these again. A request that was not recorded in its canonical form fails the preparation without a connection.

### What the review admits and refuses

The worker reads as root or through noninteractive sudo. Each prerequisite is judged by the workflow that owns it; the review adds the facts below. Every refusal names its reason and what to do, and leaves the server and every file and table as they were:

- **A complete, qualified HTTPS site.** The site follows the site convention exactly, serves HTTPS with its HTTP redirect (the redirect form of the site file), has an issued certificate lineage covering exactly its names, and selects the release's own PHP branch from Ubuntu packages on amd64 or arm64 (PHP 8.3 on Ubuntu 24.04, PHP 8.5 on Ubuntu 26.04). Other branches, sources and architectures are refused; Barectl never changes a site's PHP selection. A site file that already routes WordPress is an existing application.
- **A satisfied MariaDB binding.** PostgreSQL and a missing or partial binding refuse, naming the database workflow; Barectl converts no engine.
- **The runtime baseline and the tool.** The selected CLI and the site's PHP-FPM must load every [baseline capability](#php-runtime), and the authenticated [WP-CLI](#wp-cli-setup) must be installed with its reviewed bytes. A missing extension or tool refuses and names the plan to prepare and apply; the review installs no package or tool. The pool itself is proven when installing, because proving it needs a temporary file.
- **No existing application.** The public tree holds nothing or only the site's exact placeholder `index.html`, the private directory is empty, and nothing else sits beside them in `/var/www/<identifier>`. WordPress files, a private configuration, foreign content and a changed placeholder refuse as an existing application, without adoption, conversion or deletion.
- **A wholly empty database.** The site's database holds no table, view, routine, event or trigger. Any content, including a partial WordPress schema, refuses; core installation is never replayed into existing tables.
- **Supply and capacity.** `curl`, `tar` and `sha256sum` exist, the filesystem has room for the archive and a staged and a published tree within the reviewed limits, and the pinned archive is reachable over trusted HTTPS and announces the reviewed size. The review makes one HTTP HEAD request for that size and downloads nothing.
- **Consistent evidence.** A read that fails, an answer in an unexpected format, or a tree or site that changes while it is read refuses as incomplete evidence; it is never an empty finding.

### What the review contains

A saved review binds, with the plan's boot identifier and fifteen-minute monotonic admission deadline:

- the site identity, user, numeric IDs, selected PHP branch and socket, covered names, canonical name and the HTTPS certificate's public identity;
- the account metadata you entered;
- the authenticated WP-CLI's version, path and SHA-256, and the pinned WordPress archive: `https://wordpress.org/wordpress-7.1.3.tar.gz`, 35,368,461 bytes, SHA-256 `d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5`, locale `en_US`, with the archive, extracted tree, entry, per-file, memory and runtime limits the installation will run under;
- the exact bytes and SHA-256 of the provisioning gate and the ready Nginx form, the SHA-256 of the current site file kept as the recovery preimage, the placeholder, the fixed loader and the private configuration's path;
- the effects, each worded in full: the pinned acquisition, the files, the schema, the network access, the public exposure (gate before any file or table, ready form after verification, restoration only while the bytes still match), the administrator account, the limits and fencing, and the absence of rollback;
- fingerprints of the site, certificate lineage, MariaDB binding, driver, WP-CLI, capabilities, files and database evidence, all rechecked when applying.

It holds no password, salt or credential, and neither does the saved request: the initial administrator password and the eight salts are generated on the server when installing.

### First login

Installation will not deliver a usable password and relies on no email. The review therefore shows **Administrator password setup required** and the terminal step, targeted at the site user and the selected CLI, for an authorized administrator to run on the server after installation:

```
sudo -u s<identifier> /usr/bin/php<branch> /usr/local/lib/wp-cli/wp-cli-2.12.0.phar --path=/var/www/<identifier>/public --url=https://<name> user update <login> --prompt=user_pass --skip-email
```

The command reads the password from the terminal, so it never enters shell history, a process argument or the environment ([ADR 0018](adr/0018-generate-wordpress-secrets-on-the-server.md)). Sign in over HTTPS afterwards.

### Review permissions

The review has its own permissions, separate from the bootstrap, site, database and TLS permissions, none of which grants any of them: viewing a review and its polls needs `servers.view_server` and `wordpress.view_wordpressplan`; preparing also needs `wordpress.prepare_wordpressplan` and, because the request starts from a site's page, `discovery.view_siteobservation`; `wordpress.install_wordpress` is the permission the installation requires. The endpoint, the poll, the worker before it connects (the account must still be active and hold the preparing permissions) and the plan page, Activity and the site's history check the account again every time. A site the last complete observation does not show, or whose observation a later connection check doubts, is neither prepared nor shown as current.
