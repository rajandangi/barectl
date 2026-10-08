# Native PHP site convention

Accepted v0.3 design. Discovery recognizes sites that follow it ([site observations](ssh-connections.md#site-observations)), and applying a reviewed site plan creates one ([creating a PHP site](sites.md)). This is the concrete counterpart of [the specification](v0.3.md), not a manifest format. Every file below is ordinary Linux or application configuration, content, or native service state. Discovery recognizes the convention exactly and reports anything else once instead of interpreting it ([ADR 0015](adr/0015-recognize-only-the-convention.md)).

## Selected-branch revision

Convention revision 4 encodes the selected PHP branch in operative native settings. Every HTTP, challenge, HTTPS and redirect form uses `/run/php/s<identifier>-php<version>.sock` in Nginx `fastcgi_pass`; the matching pool uses the same path in `listen` and lives under `/etc/php/<version>/fpm/pool.d/`. The branch is one of 8.3, 8.4 or 8.5, subject to package-supply and runtime qualification. This allows discovery to recover selection even when the pool is absent. A pool in another branch or a conflicting identifier refuses dependent management.

New HTML site requests explicitly select an installed branch and use revision 4. Released revisions 1 through 3 keep their original unversioned socket and release-default branch. The complete templates below describe those released forms; revision 4 changes their socket literals to the versioned form above and retains every other byte. TLS activation and Finish preserve the observed revision and branch. Neither operation rewrites a legacy site into revision 4 or switches PHP.

The [per-site PHP qualification record](php-versions-qualification.md) separates revision-4 checks on the existing Ubuntu-default supply from third-party runtime qualification. Recognizing an eligible branch is not admission to install or change it.

The planned [Laravel convention](laravel-native-design.md#operative-filesystem-and-routing) adds exact release/current/private-state links and front-controller routing under [ADR 0019](adr/0019-deploy-laravel-through-reviewed-native-releases.md). It is not implemented and does not relax the arbitrary-symlink prohibition or routing rules of the generic PHP forms below. Its implementation must preserve selected branches, site identity, database bindings, challenges and HTTPS across every supported form.

## Site identity and layout

An identifier is 3 to 24 lowercase ASCII letters/digits, starting with a letter. It cannot collide with another supported site or any derived resource. The Linux user and private group are `s<identifier>`; the database principal and database use that same alphanumeric name. Domain names are independently validated, explicit DNS names of at most 46 characters, the longest the stock Nginx configuration's server name hash admits ([names](sites.md#names)). Renaming is outside v0.3.

| Resource | Convention |
| --- | --- |
| Linux identity | Dedicated normal UID and private GID allocated by native account tools; locked password, `/usr/sbin/nologin`, no sudo, SSH keys or supplementary groups. Review the account allocation policy and bind the actual numeric IDs to the created account before file ownership changes. An exact existing identity is reused by a reviewed Finish plan, with its attributes and numeric IDs revalidated. Complete exact sites need no changes; exact resources with some absent may be finished. Any differing existing resource refuses the plan. |
| Site boundary and home | `/var/www/<identifier>`, root:root, mode 0755, also the native account's home. Application users cannot replace this directory or its siblings. |
| Document root | `/var/www/<identifier>/public`, site-user:www-data, mode 0750. Static content is readable by the web server; the site user owns application content. Initial non-secret placeholder is 0640. |
| Private content directory | `/var/www/<identifier>/private`, site-user:site-group, mode 0700; not under the document root. No secrets are initially written. |
| Nginx source | `/etc/nginx/sites-available/<identifier>.conf`, root:root, mode 0644. |
| Nginx enablement | One symlink `/etc/nginx/sites-enabled/<identifier>.conf` to that source, under root-controlled package directories. |
| FPM pool | `/etc/php/<version>/fpm/pool.d/<identifier>.conf`, root:root, mode 0644. Pool name is the site identifier. |
| FPM endpoint | `/run/php/s<identifier>-php<version>.sock` in revision 4, `/run/php/s<identifier>.sock` in released revisions 1 through 3; pool user/group are the site user/private group, socket owner/group www-data, mode 0600. Other site users must not connect to it. |
| HTTP-01 webroot | `/var/lib/letsencrypt/<identifier>`, root:www-data, mode 0750; only the explicit challenge location is served. Created by a reviewed [challenge route](#challenge-route) plan. |
| Certificate lineage | Certbot cert-name `<identifier>` and its normal `/etc/letsencrypt/live/<identifier>/` references, archives and renewal configuration. Existing lineages are inspected and collisions refused. |
| Recovery preimage | For a supported replaced Nginx file, a root-owned 0600 ordinary backup in `/var/backups/nginx/`, uniquely named for that replacement. It must not match an active include. Backup names, digests and effects are in the local plan/audit; there is no remote recovery manifest. |

The UID/GID allocation itself is native account creation, not a promise that a previously unallocated numeric ID stays free between review and apply. Review the permitted allocation range and native allocator configuration, revalidate it and name availability, invoke the account tool under its lock, then require the returned account to match the reviewed attributes. Failure never adopts an existing same-name user or recursively changes an existing tree's ownership.

## Supported configuration grammar

Use the qualified Nginx and selected PHP-FPM branch's packaged main includes and service units. The currently qualified package supply remains Ubuntu's release-default PHP; the approved source needs the separate per-branch qualification. Keep their default site and pool. The site convention admits only fixed templates plus supported literal values; it is not a general Nginx or PHP configuration editor. Effective include trees, symlink targets and service overrides must be inspectable and within the qualified grammar. The sole enabled-site symlink is expected; arbitrary symlinks inside application roots or configuration ancestors are not.

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

The packaged FastCGI parameters are included as `include fastcgi.conf;`, the `nginx-common` configuration file that sets `SCRIPT_FILENAME` from the document root and sets no `PATH_INFO`. `snippets/fastcgi-php.conf` splits `PATH_INFO`, and `fastcgi_params` needs a separate `SCRIPT_FILENAME`; neither is the convention, and no other include is. Clearing `HTTP_PROXY` keeps a client's `Proxy` header out of PHP's environment. The dotfile location precedes the PHP location, since Nginx checks regular-expression locations in order. Recognition compares the complete rendered bytes, including whitespace and comments. An administrator restores the expected content shown for a changed file before further plans.

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

The identifiers `www` and `html` are reserved: the distribution's own pool is `www` and its default site's root is `/var/www/html`. Site creation reserves further identifiers ([names](sites.md#names)). Other enabled site files and pool files may coexist with convention sites. Foreign enabled Nginx files are read only for declared server names; a declared domain clash names the file and refuses creation ([admission](sites.md#admission)). The supported distribution configuration and convention resources must still match; discovery judges each candidate by the same exact render and reports anything else once as not following the convention ([recognition](ssh-connections.md#site-observations)).

The review includes any temporary serving probe's exact bytes, name and removal, and qualifies cleanup failure as incomplete verification. Probe output contains only a bounded expected token and identity evidence; never expose phpinfo or configuration dumps. Application content subsequently changed by an operator is outside configuration drift hashing, but document-root identity, permissions and ancestry remain admission evidence.

Nginx workers can read public content across sites. Separate Linux users, private groups and database roles are an ordinary local access boundary, not container isolation or a guarantee against hostile multi-tenant kernel/runtime attacks. The distribution default pool remains and must not be described as an isolated tenant.

## Challenge route

Convention revision 2 adds the HTTP-01 challenge route: the site file with one more location, first among its locations, and nothing else changed. Convention revision 3 adds the [HTTPS activation](#https-activation) forms below. Site admission and discovery recognize both forms of a site file, so a site with its route is a complete, satisfied site, and it never blocks creating or reconstructing another site ([TLS](tls.md)). With `<names>` and the IPv6 listener as above, the file is exactly:

```nginx
server {
	listen 80;
	listen [::]:80;
	server_name <names>;
	root /var/www/<identifier>/public;
	index index.php index.html;
	autoindex off;

	location ^~ /.well-known/acme-challenge/ {
		root /var/lib/letsencrypt/<identifier>;
		try_files $uri =404;
	}

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

`^~` stops the regular-expression locations, so a challenge path is never refused as a dotfile or passed to PHP; `try_files $uri =404` without `$uri/` serves only files and never lists a directory. The webroot is `/var/lib/letsencrypt/<identifier>`, root:www-data 0750, below `/var/lib/letsencrypt`, root:root 0755 as Certbot creates it. The replaced file's preimage is kept as `/var/backups/nginx/<identifier>.conf.<32 hex digits of the run's unit>`, root:root 0600, in `/var/backups/nginx`, root:root 0700; it is recovery material, never read as current state.

## HTTPS activation

Convention revision 3 adds the activated forms. The activation's first candidate keeps the challenge route and the HTTP server block above and adds a second server block after it, referencing the site's ordinary Certbot lineage:

```nginx
server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name <names>;
	root /var/www/<identifier>/public;
	index index.php index.html;
	autoindex off;
	ssl_certificate /etc/letsencrypt/live/<identifier>/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/<identifier>/privkey.pem;

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

The second candidate replaces the HTTP server block with the redirect form, keeping the challenge location first so HTTP-01 still answers, and keeps the HTTPS block unchanged:

```nginx
server {
	listen 80;
	listen [::]:80;
	server_name <names>;

	location ^~ /.well-known/acme-challenge/ {
		root /var/lib/letsencrypt/<identifier>;
		try_files $uri =404;
	}

	location / {
		return 301 https://<canonical-name>$request_uri;
	}
}
```

`<canonical-name>` is the first of `<names>`. Neither form sets HSTS, and the HTTPS block serves only the block's own locations; there is no catch-all proxy or fallback. The file is recognized from its exact re-render with the same fixed locations, directives and literal values as every other convention form, so an activated site is a complete, satisfied site for admission and discovery.

The first activation creates the shared rejection server `/etc/nginx/conf.d/tls-default-reject.conf`, root:root 0644:

```nginx
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;
	ssl_reject_handshake on;
}
```

It owns both 443 defaults, so a client with an unknown or absent SNI receives no certificate at all; later activations verify its exact bytes and refuse a different file or another effective default on 443. The distribution's HTTP default, its default site and the port 80 `default_server` are unchanged. An SNI that matches a site but whose HTTP `Host` differs is served by the rejection server's (empty) context, not by the site. The shared file is one ordinary Nginx include, not a Barectl manifest. Admission and discovery accept it in `/etc/nginx/conf.d` only as a regular root:root 0644 file with one link and exactly the convention's bytes; any other `conf.d` configuration file, or this file in any other form, leaves sites unsupported.

## Guarded renewal

Renewal setup ([TLS](tls.md#certbot-renewal-setup)) publishes three root-owned files and never changes Certbot's packaged units or its `cli.ini`. `/etc/systemd/system/certbot.service.d/barectl.conf` (root:root 0644, in its directory root:root 0755) overrides `certbot.service`:

```ini
# Barectl guarded Certbot renewal: https://github.com/rajandangi/barectl/blob/main/docs/site-conventions.md#guarded-renewal
[Service]
ExecStart=
ExecStart=/usr/bin/sh /usr/local/sbin/barectl-certbot-renew
SuccessExitStatus=75 76
TimeoutStartSec=30min
TimeoutStopSec=60
KillMode=control-group
```

`/usr/local/sbin/barectl-certbot-renew` (root:root 0755) takes the mutation lock with the apply payloads' own steps, skips while a Barectl run has processes, renews, and fails when a renewed certificate is not the one Nginx serves:

```sh
#!/bin/sh
# Barectl guarded Certbot renewal: https://github.com/rajandangi/barectl/blob/main/docs/site-conventions.md#guarded-renewal
export LC_ALL=C PATH=/usr/sbin:/usr/bin
d=/run/lock/barectl
f=/run/lock/barectl/mutation.lock
mkdir -m 0700 "$d" 2>/dev/null
[ "$(stat -c '%F %u %a' "$d")" = 'directory 0 700' ] || { echo 'barectl-renew: unsafe lock'; exit 71; }
[ ! -L "$f" ] || { echo 'barectl-renew: unsafe lock'; exit 71; }
exec 9>>"$f" || { echo 'barectl-renew: unsafe lock'; exit 71; }
[ "$(stat -c '%F %u %h' "$f")" = 'regular empty file 0 1' ] || { echo 'barectl-renew: unsafe lock'; exit 71; }
flock -n 9 || { echo 'barectl-renew: skipped: another change holds the mutation lock'; exit 75; }
for e in /sys/fs/cgroup/system.slice/barectl-apply-*.service/cgroup.events; do
	[ -e "$e" ] || continue
	grep -qx 'populated 1' "$e" && { echo "barectl-renew: skipped: ${e%/cgroup.events} has processes"; exit 76; }
done
live() { for c in /etc/letsencrypt/live/*/cert.pem; do [ -L "$c" ] && printf '%s %s\n' "${c%/cert.pem}" "$(readlink -- "$c")"; done; }
b=$(live)
certbot -q renew --no-random-sleep-on-renew --no-directory-hooks --deploy-hook /usr/local/sbin/barectl-certbot-deploy
s=$?
a=$(live)
n=$(printf '%s\n' "$a" | grep -vxF -e "$b" | cut -d' ' -f1)
[ -n "$n" ] || exit "$s"
python3 -I -c 'import hashlib,socket,ssl,sys,time
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
ok=True
for d in sys.argv[1:]:
    c=x509.load_pem_x509_certificate(open(d+"/cert.pem","rb").read())
    want=hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest()
    names=c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    end=time.monotonic()+10
    while True:
        good=bool(names)
        for n in names:
            try:
                with socket.create_connection(("127.0.0.1",443),5) as s:
                    with ssl.create_default_context().wrap_socket(s,server_hostname=n) as t:
                        good=good and hashlib.sha256(t.getpeercert(True)).hexdigest()==want
            except OSError:
                good=False
        if good or time.monotonic()>end:
            break
        time.sleep(1)
    print("barectl-renew: %s %s"%("deployed" if good else "not deployed",d))
    ok=ok and good
sys.exit(0 if ok else 1)
' $n || exit 80
exit "$s"
```

`/usr/local/sbin/barectl-certbot-deploy` (root:root 0755) is the one deploy hook; it runs under the wrapper's lock and never takes it:

```sh
#!/bin/sh
# Barectl deploy hook, run under barectl-certbot-renew's mutation lock: https://github.com/rajandangi/barectl/blob/main/docs/site-conventions.md#guarded-renewal
export LC_ALL=C PATH=/usr/sbin:/usr/bin
f() { logger -t barectl-deploy -- "$1; $RENEWED_LINEAGE not deployed"; exit 1; }
nginx -t -q || f "barectl-deploy: nginx -t refused the configuration"
systemctl reload nginx.service || f "barectl-deploy: reloading nginx failed"
```

The packaged `certbot.timer` keeps its schedule: `*-*-* 00,12:00:00` with a random delay of up to 12 hours, caught up after downtime. The wrapper's exit statuses are listed in [renewal outcomes](tls.md#renewal-outcomes). Certbot's own lineages, accounts and logs stay where Certbot keeps them; nothing Barectl records is written on the server.

## Database convention

Use the distribution MariaDB instance or one release-default PostgreSQL `main` cluster. Keep distribution local administrative authentication. No new public listener is enabled. Record the actual engine major, socket path and cluster identity in the release qualification instead of guessing them from a process name. PostgreSQL's umbrella unit does not prove cluster readiness.

For MariaDB, create the alphanumeric principal at `localhost` with only unix_socket authentication and no mapped alternate username or password fallback: ``CREATE USER `s<id>`@`localhost` IDENTIFIED VIA unix_socket``, ``CREATE DATABASE `s<id>` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci``, and the grant below on `` `s<id>`.* ``, each as its own statement ([site databases](databases.md#database-bindings)). Limit privileges to the exactly named new database: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE TEMPORARY TABLES and LOCK TABLES. No GRANT OPTION, global privileges, FILE, routines, events or administrative powers. Use utf8mb4 and utf8mb4_unicode_ci when supported by the qualified distribution version; otherwise refuse pending an explicit convention revision. Alphanumeric database names avoid MariaDB grant-pattern wildcard semantics.

For PostgreSQL, the principal uses same-name peer authentication on the local Unix socket. It owns one UTF8 database created from `template0` with `template1`'s reviewed locale: the libc locale provider, with a collation and character type equal to each other and one of `C.UTF-8`, `C.utf8`, `en_US.UTF-8` and `en_US.utf8`. Each statement runs on its own, as `postgres` ([site databases](databases.md#database-bindings)): `CREATE ROLE "s<id>" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD NULL`, `CREATE DATABASE "s<id>" WITH OWNER "s<id>" TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE '<locale>' LC_CTYPE '<locale>'`, then the two revokes, the second in the new database. Revoke CONNECT and TEMPORARY from PUBLIC on that new database, and PUBLIC rights on its public schema; retain the owner's application DDL/DML ability. No role membership, global privilege or altered access to unrelated databases. Require the supported release's distribution `pg_hba.conf` rules, not a peer rule placed anywhere in a changed file. Native maintenance databases may retain distribution public metadata access; the guarantee is denial of another site's data and administrative operations, not concealment of all database names.

PHP's engine-specific distribution driver is reviewed separately before binding readiness. Its actual socket connection under the site user is the acceptance check: a temporary probe `/var/www/<id>/dbprobe-<token>.php`, root's and readable by the site's group with mode 0640, which the site's pool runs and which is removed before success. A database binding is observed from the site's proven Linux identity, effective socket authentication and catalog ownership/grants. Existing databases or roles with partial or broader privileges are not silently adopted. A root SSH identity can inspect them without escalation; a lesser identity sees inaccessible evidence unless it explicitly starts an authorized privileged read-only preparation.

## TLS convention

Install only the distribution Certbot and its webroot requirements, through reviewed package admission. The webroot authenticator writes challenges beneath the per-site root in the table. The Nginx challenge location has a fixed filesystem mapping, never PHP execution, directory listing or an arbitrary alias. HTTP serving remains available until issuance and HTTPS activation succeed.

Use separate Certbot staging configuration/work/log locations for rehearsals, with no staging lineage referenced by live Nginx: `/etc/letsencrypt-staging/<id>` for the isolated configuration (accounts, renewal configurations and one lineage named `s<id>`), `/var/lib/letsencrypt-staging/<id>` for the work directory and `/var/log/letsencrypt-staging/<id>` for the logs, each root-owned with mode 0700. The challenge webroot stays the convention's `/var/lib/letsencrypt/<id>`; the staging directories are never under it. No private keys or account data are uploaded to the controller. Bound and review staging artifacts and their native cleanup; no production certificate is deleted by cleanup.

A production TLS plan fixes the CA endpoint, account/contact, exact names, certificate key policy supported on both qualified Certbot versions, renewal authenticator, paths and activation effects. Use ECDSA P-256 unless the installed qualified Certbot cannot support that policy, in which case refuse. Nginx references the native lineage's full chain and private key. Review two exact Nginx candidate states in the activation plan. The first enables HTTPS with unchanged HTTP; after real HTTPS verification, the second redirects HTTP to the literal canonical HTTPS name while retaining the HTTP-01 location. A second-stage failure remains partial completion. HTTPS accepts only the site's declared names. The first TLS activation creates a shared root-owned 0644 `/etc/nginx/conf.d/tls-default-reject.conf` with default IPv4/IPv6 443 listeners and `ssl_reject_handshake on`; later activations verify its exact supported state. Refuse custom competing defaults. Site TLS blocks enforce their explicit Host names, including a Host different from valid SNI; prove unknown/no SNI and unmatched Host do not serve a site. This guard does not change the distribution HTTP default. HSTS is excluded.

Use the packaged `certbot.timer` and a reviewed override for `certbot.service`, with a fixed bounded native command that safely opens the shared lock before invoking Certbot. Preserve the timer's native randomized schedule. On first setup, require no existing lineage/account and review a temporary native service inhibition before package installation; install and validate the guarded override before removing inhibition or enabling renewal. An interrupted setup must remain safely inhibited or have no renewable lineage. Refuse unknown existing automation instead of stopping it. No custom polling daemon is installed. The root-owned deploy hook checks Nginx syntax before reload and runs under its parent's already-held lock. Native service and journal evidence must expose a failed deployment separately from Certbot's certificate issuance result.

After taking the shared lock, renewal checks every apply control group; apply and unknown-outcome closure also check renewal's whole control group. These symmetric checks require compatible v0.3 controllers. Upgrade or stop v0.2 mutation clients before TLS setup; mixed-version mutation is unsupported and cannot be fenced by a local database. Do not run another scheduled renewal path or an unguarded interactive Certbot command through the dashboard. The same root-controlled empty lock inode and safety checks used for apply must be usable after reboot, when `/run` is empty. Lock ordering is shared mutation lock, then Certbot's locks. Test this contract with bootstrap, site writes, interactive issuance, timer renewal and unknown-outcome closure before enabling TLS.

Ordinary Certbot files, native systemd service overrides and finite deploy hooks are service configuration, not Barectl inventory or audit files. Backups and staged candidate files are never consulted as authoritative current state. The implementation must document its exact qualified override/hook configuration and refuse unknown native automation rather than rewriting it.
