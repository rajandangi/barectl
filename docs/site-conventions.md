# Native PHP site convention

Accepted v0.3 design. Discovery reconstructs sites that follow it ([site observations](ssh-connections.md#site-observations)); creating them is not implemented or qualified. This is the concrete counterpart of [the specification](v0.3.md), not a manifest format. Every file below is ordinary Linux or application configuration, content, or native service state. Discovery follows native references; it does not infer ownership from these names alone.

## Site identity and layout

An identifier is 3 to 24 lowercase ASCII letters/digits, starting with a letter. It cannot collide with another supported site or any derived resource. The Linux user and private group are `s<identifier>`; the database principal and database use that same alphanumeric name. Domain names are independently validated, explicit DNS names. Renaming is outside v0.3.

| Resource | Convention |
| --- | --- |
| Linux identity | Dedicated normal UID and private GID allocated by native account tools; locked password, `/usr/sbin/nologin`, no sudo, SSH keys or supplementary groups. Review the account allocation policy and bind the actual numeric IDs to the created account before file ownership changes. Existing identities refuse creation unless the entire supported site is already satisfied and the action becomes a no-op. Partial states require ordinary-administration repair; there is no automatic resume/adoption. |
| Site boundary and home | `/var/www/<identifier>`, root:root, mode 0755, also the native account's home. Application users cannot replace this directory or its siblings. |
| Document root | `/var/www/<identifier>/public`, site-user:www-data, mode 0750. Static content is readable by the web server; the site user owns application content. Initial non-secret placeholder is 0640. |
| Private content directory | `/var/www/<identifier>/private`, site-user:site-group, mode 0700; not under the document root. No secrets are initially written. |
| Nginx source | `/etc/nginx/sites-available/<identifier>.conf`, root:root, mode 0644. |
| Nginx enablement | One symlink `/etc/nginx/sites-enabled/<identifier>.conf` to that source, under root-controlled package directories. |
| FPM pool | `/etc/php/<default-version>/fpm/pool.d/<identifier>.conf`, root:root, mode 0644. Pool name is the site identifier. |
| FPM endpoint | `/run/php/s<identifier>.sock`; pool user/group are the site user/private group, socket owner/group www-data, mode 0600. Other site users must not connect to it. |
| HTTP-01 webroot | `/var/lib/letsencrypt/<identifier>`, root:www-data, mode 0750; only the explicit challenge location is served. Created by the separately reviewed TLS setup. |
| Certificate lineage | Certbot cert-name `<identifier>` and its normal `/etc/letsencrypt/live/<identifier>/` references, archives and renewal configuration. Existing lineages are inspected and collisions refused. |
| Recovery preimage | For a supported replaced Nginx file, a root-owned 0600 ordinary backup in `/var/backups/nginx/`, uniquely named for that replacement. It must not match an active include. Backup names, digests and effects are in the local plan/audit; there is no remote recovery manifest. |

The UID/GID allocation itself is native account creation, not a promise that a previously unallocated numeric ID stays free between review and apply. Review the permitted allocation range and native allocator configuration, revalidate it and name availability, invoke the account tool under its lock, then require the returned account to match the reviewed attributes. Failure never adopts an existing same-name user or recursively changes an existing tree's ownership.

## Supported configuration grammar

Use the distribution Nginx and default-version PHP-FPM main includes and packaged service units. Keep their default site and pool. The site convention admits only fixed templates plus supported literal values; it is not a general Nginx or PHP configuration editor. Effective include trees, symlink targets and service overrides must be inspectable and within the qualified grammar. The sole enabled-site symlink is expected; arbitrary symlinks inside application roots or configuration ancestors are not.

An HTTP server block has explicit names, port 80 IPv4/IPv6 listeners where the platform supports them, the literal document root, directory listing disabled and index files `index.php index.html`. Unknown Host names must not newly select this site as the default. Requests serve existing files or return 404; PHP requests require an existing script, use the packaged FastCGI parameters and resolve to the site's single Unix socket. There is no PATH_INFO or framework fallback in v0.3. Dotfiles are denied except the explicit ACME challenge location added by TLS setup. Uploaded application hardening and deployment permissions are later work.

The site's Nginx file is exactly this server block, with `<names>` its 1 to 10 explicit names and the IPv6 listener present only where Nginx listens on `[::]:80`:

```nginx
server {
	listen 80;
	listen [::]:80;
	server_name <names>;
	root /var/www/<identifier>/public;
	index index.php index.html;
	autoindex off;

	location / {
		try_files $uri $uri/ =404;
	}

	location ~ /\. {
		deny all;
	}

	location ~ \.php$ {
		try_files $uri =404;
		include fastcgi.conf;
		fastcgi_param HTTP_PROXY "";
		fastcgi_pass unix:/run/php/s<identifier>.sock;
	}
}
```

The packaged FastCGI parameters are included as `include fastcgi.conf;`, the `nginx-common` configuration file that sets `SCRIPT_FILENAME` from the document root and sets no `PATH_INFO`. `snippets/fastcgi-php.conf` splits `PATH_INFO`, and `fastcgi_params` needs a separate `SCRIPT_FILENAME`; neither is the convention, and no other include is. Clearing `HTTP_PROXY` keeps a client's `Proxy` header out of PHP's environment. The dotfile location precedes the PHP location, since Nginx checks regular-expression locations in order. Whitespace and comments are free; directives, their values and the three locations are not.

The pool uses `pm = ondemand`, `pm.max_children = 5`, `pm.process_idle_timeout = 10s`, `clear_env = yes`, `security.limit_extensions = .php` and a private runtime user/group. The review shows these fixed limits and explains that they are a small initial profile, not workload-based capacity sizing. No environment secrets, TCP FPM endpoint or status page is generated. Installation must verify that the actual packaged PHP releases accept the complete pool syntax and that observed socket ownership is correct. The pool file declares exactly:

```ini
[<identifier>]
user = s<identifier>
group = s<identifier>
listen = /run/php/s<identifier>.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0600
pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 10s
clear_env = yes
security.limit_extensions = .php
```

The distribution's `www` pool matches the identifier grammar, so `www` cannot name a site.

The review includes any temporary serving probe's exact bytes, name and removal, and qualifies cleanup failure as incomplete verification. Probe output contains only a bounded expected token and identity evidence; never expose phpinfo or configuration dumps. Application content subsequently changed by an operator is outside configuration drift hashing, but document-root identity, permissions and ancestry remain admission evidence.

Nginx workers can read public content across sites. Separate Linux users, private groups and database roles are an ordinary local access boundary, not container isolation or a guarantee against hostile multi-tenant kernel/runtime attacks. The distribution default pool remains and must not be described as an isolated tenant.

## Database convention

Use the distribution MariaDB instance or one release-default PostgreSQL `main` cluster. Keep distribution local administrative authentication. No new public listener is enabled. Record the actual engine major, socket path and cluster identity in the release qualification instead of guessing them from a process name. PostgreSQL's umbrella unit does not prove cluster readiness.

For MariaDB, create the alphanumeric principal at `localhost` with only unix_socket authentication and no mapped alternate username or password fallback. Limit privileges to the exactly named new database: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE TEMPORARY TABLES and LOCK TABLES. No GRANT OPTION, global privileges, FILE, routines, events or administrative powers. Use utf8mb4 and utf8mb4_unicode_ci when supported by the qualified distribution version; otherwise refuse pending an explicit convention revision. Alphanumeric database names avoid MariaDB grant-pattern wildcard semantics.

For PostgreSQL, the principal uses same-name peer authentication on the local Unix socket. It owns one UTF8 database created from an explicitly reviewed template/locale. Revoke CONNECT and TEMPORARY from PUBLIC on that new database, and PUBLIC rights on its public schema; retain the owner's application DDL/DML ability. No role membership, global privilege or altered access to unrelated databases. Verify the effective first matching authentication rule, not just the presence of any peer rule. Native maintenance databases may retain distribution public metadata access; the guarantee is denial of another site's data and administrative operations, not concealment of all database names.

PHP's engine-specific distribution driver is reviewed separately before binding readiness. Its actual socket connection under the site user is the acceptance check. A database binding is observed from the site's proven Linux identity, effective socket authentication and catalog ownership/grants. Existing databases or roles with partial or broader privileges are not silently adopted. A root SSH identity can inspect them without escalation; a lesser identity sees inaccessible evidence unless it explicitly starts an authorized privileged read-only preparation.

## TLS convention

Install only the distribution Certbot and its webroot requirements, through reviewed package admission. The webroot authenticator writes challenges beneath the per-site root in the table. The Nginx challenge location has a fixed filesystem mapping, never PHP execution, directory listing or an arbitrary alias. HTTP serving remains available until issuance and HTTPS activation succeed.

Use separate Certbot staging configuration/work/log locations under its normal administrator-controlled directories for rehearsals, with no staging lineage referenced by live Nginx. No private keys or account data are uploaded to the controller. Bound and review staging artifacts and their native cleanup; no production certificate is deleted by cleanup.

A production TLS plan fixes the CA endpoint, account/contact, exact names, certificate key policy supported on both qualified Certbot versions, renewal authenticator, paths and activation effects. Use ECDSA P-256 unless the installed qualified Certbot cannot support that policy, in which case refuse. Nginx references the native lineage's full chain and private key. Review two exact Nginx candidate states in the activation plan. The first enables HTTPS with unchanged HTTP; after real HTTPS verification, the second redirects HTTP to the literal canonical HTTPS name while retaining the HTTP-01 location. A second-stage failure remains partial completion. HTTPS accepts only the site's declared names. The first TLS activation creates a shared root-owned 0644 `/etc/nginx/conf.d/tls-default-reject.conf` with default IPv4/IPv6 443 listeners and `ssl_reject_handshake on`; later activations verify its exact supported state. Refuse custom competing defaults. Site TLS blocks enforce their explicit Host names, including a Host different from valid SNI; prove unknown/no SNI and unmatched Host do not serve a site. This guard does not change the distribution HTTP default. HSTS is excluded.

Use the packaged `certbot.timer` and a reviewed override for `certbot.service`, with a fixed bounded native command that safely opens the shared lock before invoking Certbot. Preserve the timer's native randomized schedule. On first setup, require no existing lineage/account and review a temporary native service inhibition before package installation; install and validate the guarded override before removing inhibition or enabling renewal. An interrupted setup must remain safely inhibited or have no renewable lineage. Refuse unknown existing automation instead of stopping it. No custom polling daemon is installed. The root-owned deploy hook checks Nginx syntax before reload and runs under its parent's already-held lock. Native service and journal evidence must expose a failed deployment separately from Certbot's certificate issuance result.

After taking the shared lock, renewal checks every apply control group; apply and unknown-outcome closure also check renewal's whole control group. These symmetric checks require compatible v0.3 controllers. Upgrade or stop v0.2 mutation clients before TLS setup; mixed-version mutation is unsupported and cannot be fenced by a local database. Do not run another scheduled renewal path or an unguarded interactive Certbot command through the dashboard. The same root-controlled empty lock inode and safety checks used for apply must be usable after reboot, when `/run` is empty. Lock ordering is shared mutation lock, then Certbot's locks. Test this contract with bootstrap, site writes, interactive issuance, timer renewal and unknown-outcome closure before enabling TLS.

Ordinary Certbot files, native systemd service overrides and finite deploy hooks are service configuration, not Barectl inventory or audit files. Backups and staged candidate files are never consulted as authoritative current state. The implementation must document its exact qualified override/hook configuration and refuse unknown native automation rather than rewriting it.
