# WordPress

WordPress arrives on a server in reviewed steps: the authenticated WP-CLI command-line tool, a prepared convention site's PHP runtime baseline, and then the site's WordPress application itself. Barectl also reconstructs a site's WordPress application from the server without running it. This guide covers the [supported combinations](#supported-combinations), the [WP-CLI tool setup](#wp-cli-setup), the [PHP runtime](#php-runtime), [passive application discovery](#passive-application-discovery), the [installation review](#installation-review), [applying an installation](#applying-an-installation), [finishing a partial installation](#finishing-a-partial-installation), [explicit inspection](#inspecting-wordpress), [maintenance](#maintaining-wordpress) and what [stays yours after installation](#after-installation); the [v0.4 qualification record](v0.4-qualification.md) lists the tested revisions, environments and limits, the [v0.4 specification](v0.4.md) owns the complete design, and the [native design](wordpress-native-design.md) owns the literal pins and command constraints it enforces.

The tool setup prepares only the tool. It installs no PHP extension, no WordPress and no site resource, and it does not run WordPress or the tool at any point. The PHP runtime plan prepares only the selected site's PHP extensions; it installs no tool, no WordPress, no database and no certificate.

## Supported combinations

Barectl qualifies one exact pair, WordPress 7.1.3 with WP-CLI 2.12.0, with the release's own PHP branch from Ubuntu packages and its default MariaDB:

| Ubuntu | PHP | MariaDB | arm64 | amd64 |
| --- | --- | --- | --- | --- |
| 24.04 | 8.3 | 10.11 | Qualified | Not qualified, disabled |
| 26.04 | 8.5 | 11.8 | Qualified | Not qualified, disabled |

The site's WordPress section shows this matrix with the combination the last observation found, and the reviews enforce it: installation, Finish, inspection and maintenance refuse a combination that is not qualified, and so does the PHP runtime plan. Another PHP branch or source, PostgreSQL, a newer core release and any architecture without recorded native statuses refuse rather than pass by omission. An architecture is enabled only after the [qualification record](v0.4-qualification.md#supported-combinations) names the native statuses recorded for it on an exact published revision. That record owns the tested revisions, environments, failures, skips and limits; qualification is evidence about tests, not release availability, and v0.4 is not released.

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

The tool setup and the runtime plan use Barectl's bootstrap permission contract: viewing their plans needs `servers.view_server` and `bootstrap.view_configurationplan`, preparing them `bootstrap.prepare_configurationplan`, and applying them `bootstrap.apply_configurationplan`. The site's WordPress section needs `discovery.view_siteobservation` and shows the runtime card to accounts that may view configuration plans; the [application evidence](#passive-application-discovery) card needs its own permission, and neither permission shows the other's card. Its preparation endpoint and poll check the account's permissions again on every request, and a site the last complete observation does not show, or whose observation a later connection check doubts, is neither prepared nor shown as current. None of these grants any WordPress execution; the [inspection](#permissions) and [maintenance](#maintenance-permissions) permissions are separate.

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

An installation review is the complete, immutable proposal to install WordPress at the root of one HTTPS name of a prepared site. It reads the server and changes nothing, and runs no WordPress, WP-CLI or application PHP. [Applying](#applying-an-installation) consumes exactly the saved review rather than rebuilding it.

Open the site's **WordPress** section and use the **Install WordPress** card. It first lists the prerequisites as last observed, each with the time of its observation: the convention site, its MariaDB binding and its HTTPS certificate from the site's last connection check, and the PHP runtime and WP-CLI from the latest runtime and setup plans for accounts that may view configuration plans. These are snapshots, not live status; the review rereads every one of them and prepares none, so an unmet prerequisite links its own workflow.

### What you enter

The form asks for four bounded values and nothing else. There is no password, version, command or flag field.

| Field | Accepted |
| --- | --- |
| Canonical HTTPS name | One name the site serves and its certificate covers, as a bare name or `https://<name>/`. Credentials, ports, paths, queries, fragments, other schemes, IP addresses and wildcards are refused rather than trimmed. |
| Site title | 1 to 100 characters without control characters, `<`, `>` or backslashes. |
| Administrator login | 3 to 60 lowercase letters, digits, dots, underscores or hyphens. |
| Administrator email | A plain address of 6 to 100 characters, the range WordPress accepts. |

The form, the worker before it reads anything, and a later installation each validate these again. A request that was not recorded in its canonical form fails the preparation without a connection.

### What the review admits and refuses

The worker reads as root or through noninteractive sudo. Each prerequisite is judged by the workflow that owns it; the review adds the facts below. Every refusal names its reason and what to do, and leaves the server and every file and table as they were:

- **A complete, qualified HTTPS site.** The site follows the site convention exactly, serves HTTPS with its HTTP redirect (the redirect form of the site file), has an issued certificate lineage covering exactly its names, and selects the release's own PHP branch from Ubuntu packages (PHP 8.3 on Ubuntu 24.04, PHP 8.5 on Ubuntu 26.04) on a [qualified architecture](#supported-combinations). Other branches, sources and architectures are refused; Barectl never changes a site's PHP selection. A site file that already routes WordPress is an existing application.
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
- fingerprints of the site, certificate lineage, MariaDB binding, driver, WP-CLI, capabilities, files and database evidence, all rechecked when applying;
- the SHA-256 and size of the native body the run executes and of the payload that carries it. Preparation builds the payload exactly as applying builds it and refuses a review whose payload would exceed the 16 KiB Barectl submits in one run; the largest admitted review (ten names, the longest title, login and email) needs 14,619 bytes of the 16,384.

It holds no password, salt or credential, and neither does the saved request: the initial administrator password and the eight salts are generated on the server when installing.

### First login

Installation does not deliver a usable password and relies on no email. The review therefore shows **Administrator password setup required** and the terminal step, targeted at the site user and the selected CLI, for an authorized administrator to run on the server after installation:

```
sudo -u s<identifier> /usr/bin/php<branch> /usr/local/lib/wp-cli/wp-cli-2.12.0.phar --path=/var/www/<identifier>/public --url=https://<name> user update <login> --prompt=user_pass --skip-email
```

The command reads the password from standard input, so it never enters shell history, a process argument or the environment ([ADR 0018](adr/0018-generate-wordpress-secrets-on-the-server.md)). WP-CLI echoes the characters you type and then prints the command it assembled, including the password, to the terminal: run it where nobody can read the screen and clear the terminal afterwards, or feed the prompt from a hidden read, `read -rs PASSWORD && printf '%s\n' "$PASSWORD" | sudo -u ...`. Sign in over HTTPS afterwards. A successful run never claims that a password was delivered, that email works or that the account is ready to sign in.

### Review permissions

The review has its own permissions, separate from the bootstrap, site, database and TLS permissions, none of which grants any of them: viewing a review and its polls needs `servers.view_server` and `wordpress.view_wordpressplan`; preparing also needs `wordpress.prepare_wordpressplan` and, because the request starts from a site's page, `discovery.view_siteobservation`; `wordpress.install_wordpress`, with the two viewing permissions, is the permission applying requires. The endpoints, the polls, the worker before it connects (the account must still be active and hold the preparing permissions, or for a run the installing ones), Check outcome, acknowledging an unknown outcome and the plan page, run page, Activity and the site's history check the account again every time. A site the last complete observation does not show, or whose observation a later connection check doubts, is neither prepared nor shown as current.

## Applying an installation

The plan page of an eligible review offers **Apply** to accounts with `wordpress.install_wordpress`. Applying uses the one native execution path every reviewed change uses: the worker submits one finite transient systemd unit under the shared nonblocking mutation lock through the controller's SSH connection ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)), the unit continues on the server if the page or the controller disconnects, and the run is never submitted twice. The run page follows it from queued through running, reconciling and terminal, offers **Check outcome** for a run whose outcome is not established, and keeps the finished audit when the server is removed; an active run protects the server from removal.

### What the unit does

Under the lock, before anything changes, the unit refuses when the server restarted since the review, the review's admission deadline passed, another Barectl run or a certificate renewal has processes, or any of these differs from the review: the complete site evidence, the certificate lineage, the MariaDB package, driver and catalog, the WP-CLI tool, the site's directory entries, the database's catalog and the site file's exact bytes. Native tools and free space are checked next. It then:

1. **Acquires and admits the archive without touching the site.** In a private staging directory `/var/www/<identifier>/.wp-<unit>` owned by the site user, WP-CLI `core download --no-extract` fetches only the pinned URL, as the site user with the selected `/usr/bin/php<branch>`, a cleared environment (`PATH`, `LC_ALL`, a private `HOME` and `TMPDIR`, a fresh empty cache, package and configuration location) and `--skip-packages`; no `--allow-root`, no cached or custom downloader. The unit runs under systemd `LimitFSIZE` (64 MiB) and `MemoryMax` (512 MiB, no swap), set when it is submitted. The archive's size and SHA-256 must be the pinned ones before anything else reads it. The site user then reads the member headers with Python's standard library: only regular files and directories under the sole `wordpress/` prefix, safe names, no special mode bits and at most 10,000 entries, 256 MiB in total and 64 MiB per file are admitted. GNU `tar` extracts into an absent tree with no owner or permission restoration, modes are normalized (directories 0755, files 0644), and `core verify-checksums` for 7.1.3/en_US must pass. Any refusal here has changed nothing and no downloaded code has run.
2. **Publishes the provisioning gate.** The site file's exact bytes are kept as a root-only preimage in `/var/backups/nginx`, then replaced by the reviewed gate (`nginx -t` must accept it before the reload). The gate answers 503 for the site and every PHP path, including `/wp-admin/install.php`, and keeps the ACME route. The unit proceeds only after HTTPS answers 503 for `/`, `/index.php`, `/wp-login.php` and `/wp-admin/install.php`, the HTTP challenge route answers 404 and the served certificate is the reviewed one. Otherwise it puts the preimage back while the gate's bytes are still there.
3. **Publishes the release files.** Each top-level entry of the extracted tree is renamed into the public root only where the destination is absent; nothing is overwritten and no existing ownership is changed recursively. The exact placeholder, kept as a root-only preimage, is the only file replaced. The files are owned by the site user, directories 0755 and files 0644.
4. **Creates the configuration.** The fixed public loader (`site-user:www-data` 0640) and the private configuration (`site-user:site-user` 0600) are linked into place only where absent. The configuration holds the passwordless MariaDB socket literals and eight salts generated on the server from `/dev/urandom`; the supported grammar is validated on the server before anything uses it.
5. **Installs the schema.** One site-user process generates a 32 character password from `/dev/urandom`, feeds it to the documented `core install --prompt=admin_password --skip-email` prompt and discards it. WP-CLI's output, which echoes the assembled command, is discarded; nothing secret appears in a command line, environment, systemd text or the journal.
6. **Verifies while gated.** The database holds exactly the twelve core tables with their required columns and the canonical `siteurl` and `home`; `core verify-checksums` passes on the published tree; WP-CLI as the site user finds the installation and exactly one administrator with the reviewed email; and a private FastCGI request to the site's own pool loads WordPress as the site user and reports it installed.
7. **Publishes the ready routing and verifies HTTPS.** The gate's bytes are replaced by the reviewed ready form. The unit then requires HTTPS `/` and `/wp-login.php` to answer 200 (with the login form), the public configuration, uploaded PHP and dotfiles to answer 403, HTTP to redirect to the canonical name with the ACME route intact, every alias to redirect to the canonical name and the served certificate to be the reviewed one. If serving does not verify, the unit restores the exact gate, but only while the site file's bytes still equal this run's ready form, validates and reloads it, and proves HTTPS answers 503 again.

The unit finally removes its own staging directory. A run killed without its cleanup leaves only `/var/www/<identifier>/.wp-<unit>`, which later reviews refuse and name; remove it through ordinary administration.

### Outcomes and verification

Execution and verification are separate. Execution comes from systemd's unit and control-group evidence, never from the submission's acknowledgement or the journal. After a succeeded run the worker reads the server as root and records whether it matches the review: the ready site file and the preimages, the loader and private configuration with their owners and modes, the core version, no placeholder, no leftover in the site directory, the complete schema and options, and Nginx's acceptance of its configuration. A difference fails the run as verification failed, with the differences listed; nothing is repaired.

| Execution | Meaning |
| --- | --- |
| Succeeded | Every step above completed. |
| Refused: the artifact or toolchain was not admitted | Exit statuses 31 to 37. Nothing changed. |
| Refused: the gate was not verified | Exit statuses 38 and 40. The site file was restored. No application file or table exists. |
| Stopped after changing the server | Exit statuses 39 and 42 to 50. Files, tables, salts and accounts are kept; see below. |
| Installed, but HTTPS did not verify; the gate was restored | Exit status 51. The application is installed and the exact gate is back and verified. |
| Installed, but HTTPS did not verify; the gate is not proven back | Exit status 52. The site may be reachable in an unverified state. |
| The shared refusals | Another lock holder, a restart, an expired deadline, another run's processes, a renewal, too many retained runs, or changed evidence. Nothing changed. |

### Recovering a partial installation

Installation is not transactional. After a stop Barectl keeps every file, table, salt and account the run created, never drops a database, removes content, rotates a salt or resets the administrator, and never replays core installation; a new review refuses a site that holds application files or tables. Inspect the server through ordinary administration; the run's journal, `journalctl -u <unit>`, names the last step, and the run page names the state for the exit status:

| Exit | Boundary | State left behind |
| --- | --- | --- |
| 31 to 37 | Tools, staging, download, archive, entries, extraction, checksums | Nothing but the staging directory, which the unit removes. |
| 38, 40 | Gate | Site file as it was (a root-only preimage copy remains). |
| 39 | Gate not proven restored | Read `/etc/nginx/sites-available/<identifier>.conf` and `nginx -T`; the preimage is `/var/backups/nginx/<identifier>.conf.<unit>`. |
| 42 | Release files | Some release files in the public root, behind the gate. A foreign file at a destination is kept, unchanged. |
| 43 | Placeholder | Release files published; a changed placeholder is kept, unchanged. |
| 44, 45 | Loader, private configuration | Release files published, no table. A foreign file at the destination is kept. |
| 46 | Core installation | Files and configuration in place; the database may hold some tables and the administrator may or may not exist. The gate stays. |
| 47 to 49 | Schema, integrity, access | WordPress is installed behind the gate. |
| 50 | Ready routing | Installed, behind the restored gate. |
| 51 | Serving verification | Installed, behind the verified gate. |
| 52 | Serving verification and restoration | Potentially exposed: read the site file and `nginx -T` now. A site file an administrator edited after the ready form was published is never overwritten. |

After a partial installation, [Finish](#finishing-a-partial-installation) creates the missing resources it can verify and publishes the ready routing. State it cannot verify, such as edited release files, a schema that is not exactly empty or exactly installed, or a site file that is not the gate, needs ordinary administration, which also removes what is there if you want it gone.

### Concurrency, loss and boundaries

The lock coordinates cooperating Barectl controllers and guarded certificate renewal: a second controller with its own database, alias and key either finds the lock held and stops before changing anything or, once the first run finished, finds the changed evidence. It does not stop web requests, application cron, WordPress's updater or an administrator's own commands. A lost answer to the submission, a lost connection while watching and a stopped worker leave the run reconciling; **Check outcome** inspects the same unit and invocation with a new connection and never submits again. A unit that systemd no longer knows leaves the outcome unknown until an authorized account acknowledges it ([ADR 0006](adr/0006-use-native-bootstrap-execution.md#unknown-outcomes)); a run that did not start can never be taken as a replay, because its payload refuses a changed boot or an expired deadline under the lock.

## Inspecting WordPress

An installed application can be inspected and checked against the official checksums from the site's WordPress section. This is an explicit operation, separate from the [passive application evidence](#passive-application-discovery): passive discovery never runs WordPress or WP-CLI, while an inspection runs WP-CLI against the installed application as the site user, which can execute application code. Each diagnostic is reviewed first and applied from its plan page, like every reviewed action, and none of them changes the server through Barectl. WordPress itself may write its own transients and caches to its database whenever it loads, which Barectl neither prevents nor reviews.

| Diagnostic | Fixed WP-CLI commands | Application code that runs | Network |
| --- | --- | --- | --- |
| Inspect WordPress | `core is-installed`, `core version`, `plugin list --fields=name,status,version --format=json`, `theme list --fields=name,status,version --format=json` | WordPress core, the private configuration through the fixed loader, every must-use plugin and every drop-in WordPress loads by itself | None asked for: the `update` field is not requested |
| Verify core checksums | `core verify-checksums --version=<observed> --locale=en_US` | None observed on the pinned WP-CLI: it runs before WordPress loads | One HTTPS request to the WordPress.org core checksum API |
| Verify repository plugin checksums | `plugin verify-checksums <slug> --format=json`, once per observed plugin directory with a WordPress.org slug | As the inventory | One HTTPS request per slug to `downloads.wordpress.org/plugin-checksums` |

The commands are fixed. There is no field for a command, flag, script, path or URL, and no diagnostic installs, repairs, updates, flushes or edits anything. Loading WordPress can make the application write its own transients and caches (for example the theme roots) to its database; that is the application's behaviour, not a change Barectl makes. `--skip-plugins` and `--skip-themes` skip ordinary plugins and themes, but they are not isolation: must-use plugins, drop-ins and WordPress itself still run, and the review names the must-use plugins and drop-ins it found. That `core verify-checksums` loads no WordPress code is Barectl's observation of WP-CLI 2.12.0, not an upstream guarantee; the review says so.

### The review

Preparing a review reads the server as root and runs no application code. It refuses, and saves no row to apply, when:

- the site does not follow the convention, does not serve WordPress over HTTPS, or is still behind the [provisioning gate](#applying-an-installation) of an installation that did not finish;
- the selected PHP and architecture are not a [qualified combination](#supported-combinations), the CLI does not load the WordPress baseline, or the authenticated WP-CLI is not installed;
- the WordPress loader or private configuration is not Barectl's supported form, which WP-CLI's bootstrap relies on, the core release carries a language package, is older than the qualified 7.1.3 or is unrecognized, the database does not hold exactly the complete core schema with prefix `wp_`, or `siteurl` and `home` are not the site's canonical address;
- an inventory would hold more than 128 plugins, must-use plugins, drop-ins and themes, or a plugin verification finds no plugin directory with a WordPress.org slug.

A core release **newer** than the qualified one is diagnosed with the qualified WP-CLI when its loader, configuration and schema match the qualified forms; the review and result say so, and Barectl enables no installation, Finish or maintenance for it. Plugin tables beside the core schema are neither read nor part of the review.

The review binds the evidence the run rechecks: the complete site evidence, the WP-CLI tool, and the application state, which is one digest of the loader and private configuration (its SHA-256, never the file), the core release, the schema signature and canonical options, the names of the plugin, must-use plugin and theme entries and the SHA-256 of every must-use file and drop-in. It records the commands, the application code that runs, the network requests, the limits, the admission deadline and the reviewed native body's SHA-256 with its payload size.

### Applying

The plan page offers **Apply** to accounts with `wordpress.inspect_wordpress`. The unit follows [the shared execution path](#applying-an-installation): one finite transient unit under the mutation lock with systemd `LimitFSIZE` (16 MiB) and `MemoryMax` (512 MiB, no swap), at most 30 minutes. Before running any application code it refuses when the server restarted, the admission deadline passed, another run or a certificate renewal has processes, or the site, the tool or the application state differs from the review, or a `wp-cli.yml` or `wp-cli.local.yml` exists in the site's public root, the site directory, `/var/www`, `/var` or `/`. It then:

1. Creates a private staging directory `/var/www/<identifier>/.wp-<unit>` owned by the site user with a private home, temporary, cache and package location and an empty WP-CLI configuration file.
2. Runs each fixed command as the site user through `runuser -u` with the selected `/usr/bin/php<branch>`, `--skip-packages --skip-plugins --skip-themes`, the reviewed `--path` and `--url`, a cleared environment (`PATH`, `LC_ALL`, `HOME`, `TMPDIR` and the WP-CLI cache, package and configuration locations only), standard input closed, a 120 second limit and a file-size limit, leaving each command's standard output, standard error and status in private files. Nothing a command prints reaches the journal. A plugin verification stops starting new checks after 600 seconds in total and reports the rest as skipped.
3. Runs a projection as the site user that accepts only the exact output forms of those commands and prints one record. It publishes that record as its single line of output, after checking its size and characters, and removes the staging directory.

### The result

The unit publishes one line of the fixed grammar `barectl-wordpress-result {json}`: a canonical JSON object with the operation, the server's clock when it was made, and either `"state":"ok"` with the operation's fields or `"state":"unavailable"` with one reason from a fixed vocabulary. It holds at most 128 items and 16 KiB. Anything else makes the result unavailable instead of being truncated or passed through:

| Reason | Meaning |
| --- | --- |
| `output` | A command printed something other than its exact expected output, such as debug text from a must-use plugin, a notice on standard error, malformed or duplicated JSON, an unknown status or a value outside its pattern. The text is never copied. |
| `overflow` | More than 128 items, a record over 16 KiB, a command output over its cap or a command stopped by the file-size limit. |
| `timeout`, `failed`, `skipped` | A command ran past its limit, failed or could not be read, or was not run because the time budget ended. |
| `catalog` | For a checksum check: the official catalog could not be fetched or has no entry for that release or version. |

Checksum results are never a false trust claim or a corruption claim:

- Core: **match** is WP-CLI's exact success message with nothing else; **mismatch** is a modified or missing file, or a file that should not exist, with up to 20 paths shown, validated against a strict pattern; **unavailable** is everything else, including a failed catalog request. `wp-content` is not checked. Checksums are public integrity evidence fetched over HTTPS, not a publisher signature or a malware scan, and a mismatch is evidence to investigate, not proof of compromise.
- Plugins: **match**; **mismatch** with the number of modified and added files; **unavailable** for a private or custom package, a plugin without a published catalog for its version, or any other output. WP-CLI does not detect a deleted plugin file.

The worker retrieves the result after a succeeded run with one fixed read as root (through `sudo -n` after `sudo -n -l` authorized exactly it): `journalctl -o json` filtered by the exact unit and the invocation the worker recorded, limited to the unit's standard-output stream and to entries journald attributes to user ID 0 (the site user's processes share the unit's cgroup and can open the journal's socket, but journald stamps their entries with their own user ID), together with whether the staging directory is gone. It accepts exactly one entry that carries the marker and passes the grammar; the invocation is data on the command's standard input, not part of the command line. Only the validated, typed result is stored: the item rows, the integrity counts and the validated paths, with the time the application's own run reported and the time Barectl retrieved it. The result is the application's report as of that time, not a live-security assessment, and Barectl never replays it as discovery: a later [connection check](#passive-application-discovery) stays the authority on what is installed.

Execution, verification and result are three separate outcomes:

- **Execution** comes only from systemd's unit and control-group evidence. Exit statuses 61 (a native tool or the WP-CLI file is missing) and 62 (staging could not be created, or a WP-CLI configuration file exists) are refusals before any application code ran; 63 means the projection produced no valid record; the shared refusals (lock held, restart, expired deadline, other run, renewal, retained runs, changed evidence) also ran no application code.
- **Verification** passes when the staging directory is gone; a leftover directory is named and safe to remove.
- **Result availability** is recorded beside them. A journal that was rotated or vacuumed, unreadable or holding more than one record, or a record outside the grammar, shows **Result unavailable** with its reason on the run and the site page, while the run stays succeeded and verified. A retrieval that cannot be read at all leaves the execution outcome and records verification as unavailable.

Check outcome after a lost response inspects the original unit and invocation, retrieves its result and never submits the inspection again. The finished audit and result survive the server's removal, and an active inspection protects the server from removal like any run.

### Permissions

An inspection has its own permission, separate from viewing or preparing plans, installing and every site, database, certificate and passive-evidence permission, none of which grants it. Viewing the card, a review, a run and their polls needs `servers.view_server` and `wordpress.view_wordpressplan`; the retained result lists application information, so showing it on the run page, the card and their polls also needs `discovery.view_siteapplicationobservation`; preparing also needs `wordpress.prepare_wordpressplan` and `discovery.view_siteobservation`; `wordpress.inspect_wordpress`, with the two viewing permissions, is the permission applying requires. The endpoints, the polls, the worker before it connects (the account must still be active and hold it), Check outcome, acknowledging an unknown outcome, the plan and run pages, Activity and the site's history check the account again every time.

### Boundaries

The lock coordinates cooperating Barectl controllers; it does not stop web requests, cron or an administrator. Suppression covers Barectl's command and result path, not hostile application code: a must-use plugin or drop-in runs as the site user and can itself log or transmit what it can read, as the review states. The result's validation does not prove the application told the truth, only that it told it in the fixed form.

## Finishing a partial installation

Installation is not transactional: a run that stops after the provisioning gate leaves the files, configuration and tables it had created. A **Finish** review completes it. It reads the server and proposes only the missing resources it can verify as exactly what the installation would have created, then the reviewed change from the gate to the ready routing. Eligibility comes from the server alone: Barectl consults no earlier request, review or run, no installation marker and no database of its own, so a controller that never saw the first run, or one with a rebuilt database, reviews and finishes the same site. A retained run record never authorizes recovery.

Open the site's **WordPress** section and use **Finish a partial WordPress installation**. The card takes no address, because the site file already routes it, and no password, version or command. Its site title, administrator login and email are optional: the review uses them only if it finds the site's database wholly empty, where core installation runs once; give all three or none, with the [same bounds](#what-you-enter). A review of an installed database stores none of them. Finish uses the installation's [permissions](#review-permissions): `wordpress.view_wordpressplan` to view, `wordpress.prepare_wordpressplan` with `discovery.view_siteobservation` to prepare, and `wordpress.install_wordpress` to apply. The endpoints, polls, worker, plan page, run page, Check outcome and acknowledgement check the account again every time.

### What Finish admits and refuses

The prerequisites are the installation review's: a complete, qualified HTTPS site with its certificate lineage, a satisfied MariaDB binding, the runtime baseline, the authenticated WP-CLI, the native tools and capacity, and a pinned archive that is reachable and announces the reviewed size. The review then reads every existing resource as root or through noninteractive sudo and judges it separately. A refusal names its reason, leaves the server and every file and table as they were, and saves no review.

| Resource | Finish creates | Finish keeps | Finish refuses |
| --- | --- | --- | --- |
| Site file | Nothing | The exact provisioning gate with the HTTP redirect, which becomes the ready form | Any other form: a generic site (use the installation review), the ready form (WordPress is already routed live), an edited or unrecognized file |
| Site directory | Nothing | `public` and `private` | Any other entry, such as a backup or a leftover `.wp-<unit>` staging directory of a killed run, which is named |
| Release entries | Each top-level entry of the pinned archive's release that the public root lacks, from a staged copy | An existing entry whose every path, type, mode, owner, link count and content equals the staged copy, which the run checks | The review refuses a public entry that is not a release entry, the loader or the placeholder, and a release entry of the wrong kind (a link, or a file where a directory belongs). The run refuses an edited, extra, linked, wrongly owned or wrongly moded path inside an entry |
| `wp-content` | With the release, for a first installation (an empty database), and then compared with the archive's own supplied files | The operator's content once WordPress is installed, which is not compared | A missing `wp-content` of an installed database: content is not release data, so it is never recreated |
| Placeholder | Replaces the exact known `index.html`, keeping a root-only preimage | An absent placeholder | Any other `index.html` |
| Loader | The fixed loader, when absent | The exact loader with its owner and mode | Any other `wp-config.php`, or another owner or mode |
| Private configuration | The supported file with eight new salts generated on the server, when absent | A supported file with its owner and mode, which is never replaced or rotated; its digest is recorded | A file outside the supported grammar (the first refused line is named), another owner or mode, or other private files |
| Database | Core installation, once, in a database that is wholly empty | The exact core schema with the canonical `siteurl` and `home` of the site file's address, plugin tables beside it allowed; no installation runs and no account changes | Partial or altered tables, a database holding any routine, event or trigger or a table that is not WordPress, an ambiguous second prefix, other site addresses |

The comparison of existing release files uses a fresh copy of the pinned archive, not the stock `core verify-checksums` catalog. The review cannot make it: reading the 35 MiB archive would exceed the 15 seconds one remote read may take on an ordinary network, and a review must not depend on download speed. It therefore judges only the top level, against the pinned archive's nineteen release entries and their kinds, and says so. The run compares every existing entry with its own staged and verified copy under the lock, as the site user, by path, type, mode, owner, link count and the SHA-256 of every file (`find` and `sha256sum`), and stops with exit status 54 before it changes anything if one differs; the unit's journal names the first such entry. Private configuration is judged by its supported grammar and its digest, read on the server, and no salt reaches the controller.

A saved review binds what the installation review binds and records, for the Finish, the release entries it publishes and the ones that exist and will be compared, whether `wp-content` is part of the comparison, whether it creates the loader and the configuration or keeps the existing configuration's digest, and whether it runs core installation. The review that needs the most (nothing created, existing entries to compare, an installation to run) submits about 14,900 of the 16,384 bytes one run carries; a review that would not fit is refused and never split.

### What the Finish unit does

The unit is the installation's: the same nonblocking mutation lock, boot and deadline fences, native limits, site-user identity and no-replay reconciliation. Under the lock, before anything changes, it refuses when the server restarted, the deadline passed, another run or a renewal has processes, or any evidence differs from the review: the installation's site, certificate, binding, driver and tool evidence, the site directory and trees' top level with the loader, private configuration grammar and digest and version literal, the database's counts, schema summary and canonical options, and the site file's exact bytes. It then:

1. **Acquires and admits the archive without touching the site**, exactly as an installation does: the pinned download as the site user into a private staging directory, the size and SHA-256, the member headers, bounded extraction and `core verify-checksums`.
2. **Compares** each release entry that exists with the staged copy, as the site user, by path, type, mode, owner, link count and content. Any difference stops the run with exit status 54 before it changes anything; a change to the top level or to any other reviewed evidence after the review stops it with exit status 15. `wp-content` of an installed database is only required to be the site user's directory.
3. **Verifies the gate.** HTTPS must answer 503 for `/`, `/index.php`, `/wp-login.php` and `/wp-admin/install.php`, the challenge route 404 and the served certificate be the reviewed one; otherwise the run stops with exit status 53 before it changes anything. The gate's bytes are kept as a root-only recovery preimage.
4. **Publishes only what is missing.** Each absent release entry is renamed into the public root where the destination is absent, without overwriting or changing existing ownership. The exact placeholder is replaced, the loader and the configuration are created only where the review found them absent, and core installation runs once only in a database the review found wholly empty, as the installation does it (a server-made password fed to the documented prompt and discarded).
5. **Verifies while gated**: the core schema and canonical options (the twelve core tables exactly, for a database this run installed), core integrity, and WP-CLI and a private FastCGI request through the site's pool as the site user. For a database this run installed, the one administrator with the reviewed email is also checked.
6. **Publishes the ready routing and verifies HTTPS**, restoring the exact gate only while the site file still equals this run's ready form, as an installation does.

The run never replaces an existing file, rotates a salt, resets an account, recreates `wp-content`, drops a table or removes anything but its own staging directory.

### Finish outcomes and verification

Execution and verification are separate and read as for an [installation](#outcomes-and-verification), with the installation's postconditions: after a successful run the worker reads the server as root and compares it with the review. A database that already held the installation may hold plugin tables beside the twelve core ones. The statuses are the installation's for the shared boundaries, plus one of the Finish's own:

| Execution | Meaning |
| --- | --- |
| Succeeded | Every step above completed and the application is served. |
| Refused: the application's artifact or toolchain was not admitted | Exit statuses 31 to 37. Nothing changed. |
| Refused: the site is not behind a verified provisioning gate | Exit status 53. HTTPS did not serve the reviewed gate when the run started, or its preimage could not be kept. Nothing changed. |
| Refused: existing release files differ from the pinned archive | Exit status 54. An existing release entry is not the staged copy. Nothing changed. |
| Refused: the reviewed evidence changed | Exit status 15. Nothing changed. |
| Stopped after changing the server | Exit statuses 39 and 42 to 50, with the installation's meaning for each boundary. Files, tables, salts and accounts are kept. |
| Complete, but HTTPS did not verify; the gate was restored | Exit status 51. |
| Complete, but HTTPS did not verify; the gate is not proven back | Exit status 52. The site may be reachable in an unverified state; read the site file and `nginx -T` now. A site file edited after the ready form was published is never overwritten. |
| The shared refusals | Another lock holder, a restart, an expired deadline, another run's processes, a renewal, too many retained runs. Nothing changed. |

A run that stopped is not an obstacle: the next Finish review reads what exists again and proposes what is still missing. After a run that installed, it finds an installed database and runs no installation; the password step of the run that created the administrator is unchanged.

### When Finish refuses

Ambiguous or edited state needs ordinary administration, because Barectl will not guess which changes ran. Read the site file (`/etc/nginx/sites-available/<identifier>.conf`) and `nginx -T`, `/var/www/<identifier>/public` and `/var/www/<identifier>/private`, `SHOW TABLES` in the site database and the earlier run's journal (`journalctl -u <unit>`). Correct or remove what is wrong with ordinary tools and your own backup, then prepare a new Finish review; Barectl never edits an application file, repairs a schema, drops a table or adopts content on your behalf. A site that was never installed here is installed with the [installation review](#installation-review), not Finish.

### Finish concurrency and boundaries

The lock, a second controller with its own database, alias and key, lost answers, Check outcome and the unknown-outcome acknowledgement behave as for an [installation](#concurrency-loss-and-boundaries). Two controllers that review the same stranded site and apply together finish it at most once; the other stops under the lock or finds changed evidence before changing anything. Web requests, application cron and WordPress's own updater stay outside the lock, so a Finish on a site that is gated has no live traffic to coordinate with, and one on a site whose files are being changed by an administrator at the same time is refused when the comparison or the evidence differs.

Upstream sources and the reuse assessment are in the [native design](wordpress-native-design.md#upstream-reuse-assessment).

## Maintaining WordPress

Two named maintenance actions change an installed application's state from the site's WordPress section. Like an [inspection](#inspecting-wordpress) they run WP-CLI against the application as the site user, which executes application code, are reviewed first and are applied from their plan page. Unlike an inspection they change application state, so they have their own permission and refuse a core release other than the qualified WordPress 7.1.3 with WP-CLI 2.12.0: a newer core can be diagnosed but is never maintained, and Barectl never downgrades it.

| Action | Fixed WP-CLI command | Application code that runs | What it changes |
| --- | --- | --- | --- |
| Flush rewrite rules | `rewrite flush`, never `--hard` | WordPress core, the private configuration through the fixed loader, the active plugins and theme, every must-use plugin and every drop-in WordPress loads by itself | The stored `rewrite_rules` option in the site's database, regenerated from the routes those components register |
| Flush object cache | `cache flush` | WordPress core, the private configuration through the fixed loader, every must-use plugin and every drop-in; ordinary plugins and themes are skipped | Nothing observable: it clears the object cache of its own command-line process |

The commands are fixed. There is no field for a command, flag, script, path or URL.

### Soft rewrite flush

A soft flush deletes WordPress's stored `rewrite_rules` option and regenerates it from the routes WordPress core, the loaded theme and the loaded plugins register in that command-line request, then stores it again; the next web requests use the refreshed rules. It never writes `.htaccess`, never edits the Nginx site file or any other file and never reloads Nginx, because Nginx already passes unknown paths to WordPress's front controller. Barectl does not use the diagnostic `--skip-plugins --skip-themes` flags for it: WP-CLI itself warns that rules are missing when they are set, and the routes of plugins and themes are the point of the flush. The review therefore names the must-use plugins and drop-ins, and the installed plugins and themes, whose hooks run: they can do anything the site user can, including writing application data or making network requests, which Barectl neither prevents nor observes. A route a plugin registers only under conditions that do not hold in a command-line request is not stored, and page caches are not cleared. WP-CLI stores no rules while the site uses plain permalinks; the result then reports that no rules are stored instead of claiming a flush.

### Object-cache flush

WordPress's [default object cache](https://developer.wordpress.org/reference/classes/wp_object_cache/) exists only in the memory of one request. The command therefore clears the cache of its own command-line process, which is empty. It clears nothing in the requests the web server is serving, no page cache, no browser or CDN cache and no persistent store, and the review and the result say so; it is not a live-site cache repair and Barectl claims no speed-up or stale-content fix from it.

No persistent cache provider is qualified. A site with a drop-in WordPress loads by itself that changes where the cache lives or what a flush reaches (`object-cache.php`, `advanced-cache.php` or `db.php`) is refused at review, and so is any other drop-in, because the scope of the flush would be unverified and might clear a store shared with other applications. A drop-in added after review is refused by the run before any application code runs. Remove the drop-in, or manage that cache through ordinary administration.

### The review

Preparing a review is the [inspection's](#the-review): it reads the server as root, runs no application code, and refuses, saving no row to apply, when the site does not serve WordPress over HTTPS, is behind the provisioning gate, uses a PHP other than the release's own Ubuntu branch, lacks the baseline or the authenticated WP-CLI, or its loader, private configuration, schema or canonical address are not the supported form. It also refuses a core release other than the qualified one, a plugin, must-use or theme directory listing more than 300 entries (more than the evidence binds), and for the cache flush the drop-ins above. It binds the same evidence the run rechecks: the complete site evidence, the WP-CLI tool and the application state, which includes the names of the plugin, must-use plugin and theme entries and the SHA-256 of every must-use file and drop-in. It records the command, the application code that runs, the effect on application state, the limits, the admission deadline and the reviewed native body's SHA-256 with its payload size.

### Applying a maintenance action

The plan page offers **Apply** to accounts with `wordpress.maintain_wordpress`. The unit is the [shared application execution](#applying): one finite transient unit under the mutation lock with the same `LimitFSIZE`, `MemoryMax` and 30-minute limits, the same revalidation and refusals before any application code runs, a private staging directory, a cleared environment and the command run as the site user with the selected PHP. It runs the one fixed command with a 120 second limit, and a trusted projection run as the site user accepts only the command's exact output:

| Action | Exact output accepted | Recorded as |
| --- | --- | --- |
| Flush rewrite rules | `Success: Rewrite rules flushed.` and nothing else | Done, rules stored |
| Flush rewrite rules | Only WP-CLI's warning that the rules are empty, with the plain-permalinks wording | Done, no rules stored |
| Flush object cache | `Success: The cache was flushed.` and nothing else | Done |
| Either | A non-zero status, a time or file-size limit | Not done: the unit publishes the record, then ends as failed (exit 64) |
| Either | Anything else, such as debug text from a plugin | Result unavailable (`output`) |

The unit publishes one record of the [inspection's grammar](#the-result), with the `rewrite` or `cache` operation, and Barectl retrieves it the same way. Anything outside the grammar is unavailable, never trusted, and then Barectl cannot say whether the command took effect.

Completion, postconditions and the result stay separate:

- **Execution** comes only from systemd's unit and control-group evidence. Exit statuses 61 and 62 are refusals before any application code ran, 63 means the projection produced no valid record, and 64 means the command did not complete. The shared refusals (lock held, restart, expired deadline, other run, renewal, retained runs, changed evidence) also ran no application code.
- **Verification** passes when the staging directory is gone.
- **Result availability** is recorded beside them. A rotated, unreadable or duplicated journal, or a record outside the grammar, shows **Result unavailable** with its reason while the run stays succeeded and verified.

Barectl never runs a maintenance action again on its own. A failed command, an unavailable result, a run stopped at its limit and a lost response all leave the decision to an operator, who can inspect the application and prepare a new review. **Check outcome** inspects the original unit and invocation and never submits it again. The finished audit survives the server's removal, an active run protects the server from removal, and a finished run queues a discovery refresh like any run that may have changed the server.

### Maintenance permissions

Maintenance has its own permission, `wordpress.maintain_wordpress`, separate from viewing or preparing plans, installing, inspecting and every site, database, certificate and passive-evidence permission, none of which grants it: an account that may inspect WordPress, or hold every other apply permission, cannot apply a maintenance plan. Viewing the card, a review, a run and their polls needs `servers.view_server` and `wordpress.view_wordpressplan`; the retained result lists application information, so showing it on the run page, the card and their polls also needs `discovery.view_siteapplicationobservation`; preparing also needs `wordpress.prepare_wordpressplan` and `discovery.view_siteobservation`. The endpoints, the polls, the worker before it connects (the account must still be active and hold the permission), Check outcome, acknowledging an unknown outcome, the plan and run pages, Activity and the site's history check the account again every time.

### Maintenance boundaries

The lock coordinates cooperating Barectl controllers; it does not stop web requests, cron, WordPress's updater or an administrator. A flush costs one command-line PHP process of CPU, memory and database queries while the site keeps serving. Native success verifies that the command completed; Barectl does not promise every plugin's hook effects or any performance recovery. Suppression covers Barectl's command and result path, not hostile application code. Upstream sources and the reuse assessment are in the [native design](wordpress-native-design.md#named-wp-cli-operations).

## After installation

Barectl installs WordPress and offers a small set of reviewed operations on it; the application is yours to run. These responsibilities stay with the operator and the ordinary tools of the server:

- **Patching.** WordPress's own updater, plugin and theme updates, security releases and application cron keep running as WordPress configures them; Barectl neither schedules, performs nor blocks them. An updated core is reported with its [qualification status](#passive-application-discovery) and is never downgraded; Barectl enables installation, Finish and maintenance only for the qualified pair. Operating-system and PHP package updates are ordinary administration, and the PHP runtime plan never upgrades or removes a package.
- **Backups and recovery.** Barectl keeps no copy of the application's files or database. A reviewed run keeps only the exact preimages it names (for example the site file in `/var/backups/nginx`), never user content, and none of its failure paths deletes files or tables. Back up `/var/www/<identifier>`, the site's database and the certificate lineage with your own tools and test restoring them; verified restore is a later milestone.
- **First login.** Installation delivers no usable password and relies on no email. An authorized administrator sets the first password in a terminal on the server, as [First login](#first-login) shows, and the result never claims a password was delivered.
- **What the dashboard cannot see.** Passive discovery reads only what the SSH identity may read: private configuration, database catalogs and files owned by the site user need root or the site user, and a lesser identity sees them as unavailable, never as absent. A run's result is retrieved from the native journal and is unavailable once the journal rotates, while the run's outcome stays what systemd recorded.
- **No broad isolation.** The shared lock coordinates cooperating Barectl controllers and guarded renewal. It does not stop web requests, application cron, WordPress's updater, plugins or an administrator, and it is not an application-wide transaction. The site user, its PHP-FPM pool and its database principal separate sites from one another as the [site convention](site-conventions.md) describes; Barectl promises no containment of hostile application code, which can read what its site user can read, write to its own tree and disclose its own data.

