# WordPress

WordPress arrives on a server in reviewed steps: the authenticated WP-CLI command-line tool, a prepared convention site's PHP runtime baseline, and later the site's WordPress application itself. This guide covers the first two steps, the [WP-CLI tool setup](#wp-cli-setup) and the [PHP runtime](#php-runtime); the [v0.4 specification](v0.4.md) owns the complete design, and the [native design](wordpress-native-design.md) owns the literal pins and command constraints it enforces.

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

The tool setup and the runtime plan use Barectl's bootstrap permission contract: viewing their plans needs `servers.view_server` and `bootstrap.view_configurationplan`, preparing them `bootstrap.prepare_configurationplan`, and applying them `bootstrap.apply_configurationplan`. The site's WordPress section also needs `discovery.view_siteobservation`. Its preparation endpoint and poll check the account's permissions again on every request, and a site the last complete observation does not show, or whose observation a later connection check doubts, is neither prepared nor shown as current. None of these grants any WordPress execution; inspection and maintenance permissions, on the site's page, are defined separately when those workflows land.
