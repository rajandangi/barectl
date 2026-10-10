# Site creation

The ordinary hosting workflow is a site form with automatic prerequisite preparation. [Issue #320](https://github.com/rajandangi/barectl/issues/320) owns this change. Native qualification and delivery evidence are recorded in [site creation qualification](site-creation-qualification.md). The [competitor comparison](site-creation-competitor-analysis.md) records the official sources behind the product choices.

## Operator journey

1. Add the server using an existing SSH alias and check its connection.
2. Open Sites and choose **Create site** or **Create WordPress site**. Enter the domain. WordPress also needs a site title, administrator username and administrator email. The email supplies the certificate contact. Accept the named certificate authority's agreement when enabling HTTPS.
3. Press **Create** once. The form describes the software and site resources this authorizes. Barectl installs missing requirements, creates the isolated site and optional database, and enables requested HTTPS. WordPress installation runs only for an explicit WordPress request.
4. Follow progress. A completed WordPress site offers its login page and a one-time administrator password reveal in the requesting browser. Its site settings offer explicit password recovery if first access is unavailable.

Optional **Site settings** hold a PHP override, additional domains, and the generic PHP site's database and Node selection. New sites otherwise use the observed server PHP default. Setup contains server PHP and Node defaults. Each existing site's overview contains its own runtime controls. Sources, package refreshes, drivers and individual preparation/apply tools remain in Advanced for diagnosis.

The operator-input target is two minutes from a usable connection through submitting Create. Downloads, source availability, certificate validation and installation have no promised duration. Failed DNS and corrective server administration are outside the ordinary input target.

## One authorization, native admission at every step

The local creation request records its requester, server connection, domains, application choice and version selections. Repeated identical submissions reuse the original request. They never authorize a second WordPress installation. The certificate authority is the configured production authority; WordPress uses MariaDB and HTTPS.

The controller coordinator reuses existing discovery, package, site, database, TLS and WordPress services. It prepares immutable plans, applies them through the existing worker, verifies results, and advances when each operation finishes. Its stages establish distribution software tools, authenticated PHP supply and current package indexes, web/PHP software, the isolated site and selected capabilities, the database binding, HTTPS, and the explicitly requested application. No intermediate Prepare or Apply click is required.

Every native mutation retains fresh evidence, current permissions, server identity checks, exact package admission, the shared native lock, bounded transient systemd execution and postcondition checks. There is no second SSH execution path or persistent remote agent. Plans and history stay in the controller database. Standard native configuration is the server's authority.

## PHP defaults and site versions

Fresh servers use the approved Surý supply under [ADR 0016](adr/0016-limit-third-party-php-supply.md). Required tools and non-PHP packages use authenticated Ubuntu sources. Normal forms offer no source picker or fallback supplier. Existing supported Ubuntu installations retain their native supply; legacy or conflicting sources need explicit corrective administration. Creation never silently converts existing packages.

The server default is reconstructed from `/usr/bin/php`, its native alternatives group, installed version and authenticated package provenance. On a fresh server without PHP, the initial branch is the distribution release's default. Missing or unsupported evidence produces a visible refusal, never a cached preference.

Changing the default affects subsequent sites and the ordinary PHP command. Existing sites retain versioned CLI paths and their operative Nginx/FPM pool configuration. Installation of an additional branch preserves the reviewed previous default, including a known package failure that changed package state. Restoration failure remains a reported partial failure.

A site's PHP change installs missing capabilities through existing exact profiles, then switches only that site's pool and routing. It admits the native package, service, configuration and database preimages and verifies a temporary FPM probe's branch, Linux identity and database access. Other sites and the server default are preserved. An uncertain result is reconciled before another operation; known verification failures restore the admitted previous configuration. WordPress combinations must pass the owning qualification gate before they can be offered.

## Node defaults and site versions

[Node runtime design](node-runtimes-native-design.md) owns the fixed LTS catalog and authenticated installation through mise. Setup selects a server default. A site's Node selection pins its exact version in the standard `.node-version` file. Changing the server default preserves existing pins. Inventory is reconstructed from validated native installation, global configuration and recognized site roots.

Site settings show the selected version's executable for an application's commands. The ordinary `node`, `npm` and `npx` commands continue to use the server default; changing a directory does not change their selection. The site pin records the application's runtime choice and does not rewrite its service or build commands.

Runtime management does not authorize application deployment, arbitrary build commands or a persistent Node application service. Those require an application contract. A missing or customized installation produces a useful refusal without adopting foreign commands or configuration.

## WordPress first access

[ADR 0026](adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md) owns browser first access. The requesting browser retains a nonexportable private key and submits only its public key. The native installer generates the administrator password, passes it to WP-CLI over stdin, and encrypts it for that browser. The controller retains ciphertext only, bound to the original requester and verified native run.

The requester can retrieve the ciphertext once while authorized and within its expiry. Decryption and password display happen in the browser. The password clears from the display after one minute. Loss or expiry of browser keys requires an explicit administrator password reset with fresh native admission and a new browser key. Neither server setup nor another site action resets credentials automatically.

## Progress and recovery

Completed native work survives controller or SSH loss. Later stages need the controller worker; the progress view says this. Another authorized controller reconstructs supported native resources, not the previous device's private history or browser key.

Creation stops on denied permissions, changed identity or selection, source/index failure, DNS or certificate failure, conflicting work, failed verification, or an uncertain outcome. It retains completed work and names the failed stage. It never retries an uncertain certificate order or installation, deletes partial tables or content, or claims automatic rollback of the whole recipe. Existing exact missing-resource and Finish workflows remain available in Advanced after fresh inspection.

A failed site PHP switch records its fixed apply or recovery phase in the existing native systemd journal, with the exception class and bounded numeric metadata from the original process and serving checks. It excludes command arguments, configuration, credentials and response bodies. Diagnostics do not run another probe, replay work or establish the outcome; native unit state and fresh verification remain authoritative. The [reuse decision](https://github.com/rajandangi/barectl/issues/320#issuecomment-6094022953) records the existing Python and systemd facilities and the caught-phase evidence gap.

## Delivery gates

The qualification record must cover fresh creation, every offered PHP combination, defaults and per-site preservation, browser first access and explicit recovery, current/revoked permissions, drift, partial failure and reconstruction. Local native evidence and hosted amd64 evidence remain distinct. Required repository checks, browser checks and full exact-head native statuses precede delivery. Unsupported combinations remain disabled.
