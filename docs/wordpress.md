# WordPress

WordPress arrives on a server in reviewed steps: first the authenticated WP-CLI command-line tool, then a prepared convention site's PHP runtime baseline, and later the site's WordPress application itself. This guide covers the first step, the WP-CLI tool setup; the [v0.4 specification](v0.4.md) owns the complete design, and the [native design](wordpress-native-design.md) owns the literal pins and command constraints it enforces.

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
