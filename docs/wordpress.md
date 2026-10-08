# WordPress

WordPress arrives on a server in reviewed steps: first the authenticated WP-CLI command-line tool, then a prepared convention site's PHP runtime baseline, and later the site's WordPress application itself. Barectl also reconstructs a site's WordPress application from the server without running it. This guide covers the WP-CLI tool setup and [passive application discovery](#passive-application-discovery); the [v0.4 specification](v0.4.md) owns the complete design, and the [native design](wordpress-native-design.md) owns the literal pins and command constraints it enforces.

The tool setup prepares only the tool. It installs no PHP extension, no WordPress and no site resource, and it does not run WordPress or the tool at any point.

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

### Permissions

The tool setup uses Barectl's bootstrap permission contract: viewing its plans needs `servers.view_server` and `bootstrap.view_configurationplan`, preparing them `bootstrap.prepare_configurationplan`, and applying them `bootstrap.apply_configurationplan`. None of these grants any WordPress execution; inspection and maintenance permissions, on the site's page, are defined separately when those workflows land.

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

