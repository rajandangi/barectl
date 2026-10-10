# Barectl

Barectl lets an operator inspect and manage native Linux web servers from a local or self-hosted application.

## Language

**Operator**:
The person using a Barectl installation to manage its registered servers.
_Avoid_: Customer, tenant

**Barectl account**:
An operator's login to a Barectl installation, local to that installation by default. It is separate from Linux users and does not grant SSH access or server permissions.
_Avoid_: Server user, SSH identity

**Managed server**:
A remote Linux machine registered with Barectl for inspection and, in later releases, management.
_Avoid_: Barectl host, control panel

**Controller host**:
The machine running Barectl and holding the SSH credentials used to access managed servers. It may be the operator's local computer or a private management host.
_Avoid_: Managed server

**Local database**:
A Barectl installation's default store for its accounts, settings, connection records, queued requests, operation history, and cached server observations. Another authorized device does not need a copy to discover and manage the same server.
_Avoid_: Server source of truth, shared control plane

**Shared database** (planned):
An optional remote application database that operators configure to share Barectl records across local installations. It is not authoritative server state and is not required for independent SSH management.
_Avoid_: Hosted Barectl service, server source of truth

**SSH alias**:
A concrete `Host` name in the controller host's SSH configuration. A managed server is registered by its alias; connection settings, credentials and host trust stay on the controller host.
_Avoid_: Connection details, hostname

**Saved server connection** (planned):
A managed server's non-secret address, SSH username, port and approved host-managed authentication reference saved in the local Barectl database. It is an alternative to SSH alias registration, not a stored private key, server trust record or grant of SSH access. See [the specification](docs/saved-server-connections.md).
_Avoid_: Stored credentials, verified connection

**Discovery**:
A read-only inspection of a managed server's current configuration and resources.
_Avoid_: Provisioning, bootstrap

**Reconstruction**:
Rebuilding supported server views from native configuration, service state, and available logs in a fresh Barectl installation without the previous installation's database. It cannot recover another device's private application records or native history the server no longer retains.
_Avoid_: Database restore, provisioning

**Discovery attempt**:
One queued run of connection verification and discovery for a managed server, with the outcome queued, running, succeeded or failed. It is a remote operation of the discovery kind, so it shares the server's one active slot with other kinds.
_Avoid_: Job, scan

**Verified connection**:
A connection whose host key matched the controller host's known_hosts and whose authentication succeeded, recorded by a succeeded discovery attempt. A registration alone is not verified.
_Avoid_: Connected, online

**Connection status**:
The dashboard's one-phrase summary of a managed server's connection: not verified, connection check queued, checking connection, connection failed, verified, or SSH alias unavailable. An active discovery attempt is reported even when the alias has since become unusable; otherwise an unusable alias outranks the latest attempt's outcome.
_Avoid_: Health, online status

**Server removal**:
Deleting a managed server's registration and its local history from Barectl: discovery attempts with their snapshots, and plan preparations with their plans. Finished apply runs are kept as audit without the server. It never connects to the server or changes the controller host, and it waits for any active remote operation.
_Avoid_: Deprovisioning, uninstall

**Remote operation**:
One queued run that connects to a managed server: a discovery attempt, a plan preparation or an apply run. Its lifecycle states are queued, running, reconciling, succeeded and failed. Within one Barectl database, a server has at most one queued, running, or reconciling remote operation, whatever its kind; independent devices also require coordination for conflicting changes.
_Avoid_: Job, task

**Bootstrap**:
Preparing a supported managed server with the distribution's standard web-stack packages and service configuration after operator review.
_Avoid_: Site creation, server adoption

**Bootstrap profile**:
The supported package and service baseline an operator chooses to establish on a managed server: Nginx, the FPM and CLI of the release's default PHP version, or the release's MariaDB server with its initialized data directory, or the release's default PostgreSQL major with its `main` cluster, from the packages of the server's own supported release with their default configuration. Each profile is established by applying its reviewed plan, independently of the others and of any site. A database profile establishes the engine and, for PostgreSQL, its one default cluster only, never a site's database, database user or PHP driver.
_Avoid_: Arbitrary package list, site template

**Supported release**:
An Ubuntu LTS release whose own policy bootstrap follows. Ubuntu 26.04 (resolute) is the one supported release; a server on any other release is reported as an unsupported release. The policy names the archives a reviewed transaction may use, the APT and systemd series qualified on the release, apt 3.2 and systemd 259, its tested APT hook baseline, its default PHP version, PHP 8.5, its MariaDB series, archive components and data directory, MariaDB 11.8 from `main` in `/var/lib/mariadb`, and its default PostgreSQL major, 18. A server is reviewed only against its own release and never receives another release's packages.
_Avoid_: Supported OS, distribution version

**Third-party source**:
An APT source other than a supported release's own Ubuntu archive, which is its three suites and its backports, as the downloaded Release files identify them. A hosting provider's repository, a PPA and a PHP packager's repository are third-party sources even when authenticated. Authentication identifies the publisher; it does not make the source part of the Ubuntu archive.
_Avoid_: Foreign repository, external source

**PHP supply choice**:
On released servers, the single package supplier selected for a managed server's PHP runtimes and their shared support packages: its Ubuntu archive or the one approved third-party PHP source. It is separate from the PHP branch a site selects. New servers take runtimes from the runtime catalog instead.
_Avoid_: PHP version, repository ownership

**PHP branch**:
A PHP major/minor release family, such as 8.4. A site's selected branch identifies the runtime serving its PHP requests; patch versions are exact package versions reviewed during installation.
_Avoid_: PHP supplier, default CLI

**Host standing** (planned):
Barectl's judgment of a managed server, made afresh from server evidence on every discovery and review: fresh host, incomplete foundation, target stack or not manageable. Nothing on the server records it.
_Avoid_: Server status, health

**Fresh host** (planned):
A host standing: a supported Ubuntu release and architecture with nothing of the target stack and no other web stack, PHP installation, hosting panel or Nix installation that is not Barectl's. Only a fresh host can be set up.
_Avoid_: New server, clean install

**Incomplete foundation** (planned):
A host standing: part of the target stack's server-wide foundation is present in its supported form and nothing foreign is present, as after an interrupted setup. Setup can continue from where it stopped.
_Avoid_: Broken server, failed bootstrap

**Target stack** (planned):
The one stack Barectl sets up on fresh hosts, and the host standing of a server whose server-wide foundation is complete in its supported form. Sites and runtimes are added on top of it.
_Avoid_: New stack, profile

**Not manageable** (planned):
A host standing in which Barectl reads the server and shows why, but reviews no change: an unsupported release or architecture, missing privilege, another web stack, PHP installation, panel or Nix installation, or a layout made by an earlier Barectl. Distinct from the observation outcome unsupported.
_Avoid_: Unsupported server, legacy server

**Outside supported settings** (planned):
The state of a target-stack resource that contains a setting Barectl does not interpret. It is reported once, and only the changes that depend on it are blocked; changes within the supported settings are adopted, whoever made them.
_Avoid_: Foreign, not following the convention, unsupported

**Runtime catalog** (planned):
The pinned set of language runtimes and tools a managed server can offer its sites, shared by every site that selects the same entry.
_Avoid_: Package list, per-site toolchain

**Catalog lock**:
The generated list in Barectl's source of every runtime catalog build: for each catalog entry and architecture, the exact Nix store path, version and sizes from one pinned nixpkgs commit, with the builds of earlier commits kept as retired.
_Avoid_: Manifest, package list

**Catalog entry**:
One named runtime or tool in the catalog lock, such as `php84` or `caddy`, with one build per architecture. A retired build is still recognized on a server but never offered.
_Avoid_: Package, attribute

**Runtime** (planned):
A named language branch with a fixed extension set, taken from the runtime catalog, such as PHP 8.4 with its default extensions. Its exact build changes over time through reviewed catalog updates, and the previous build stays available for rollback. Sites that select the same runtime share it. One branch can have several runtimes with different extension sets.
_Avoid_: PHP version, exact build

**PHP-FPM master** (planned):
The one PHP-FPM service serving every site pool of one PHP runtime. Its shared settings and restarts affect all of those sites.
_Avoid_: PHP service, pool

**Plan preparation**:
A remote operation that inspects a server read-only to build a configuration plan for a supported bootstrap profile, maintenance action or site. It may read with root or verified noninteractive sudo, unlike discovery, and cannot authorize or perform the proposed changes.
_Avoid_: Apply run, metadata refresh

**Configuration plan**:
An immutable local record of one plan preparation's decision: the proposed changes and their effects, or the reasons they are refused, tied to fingerprints of the server evidence, the boot and an admission deadline. Changed or unavailable evidence requires a new plan and review. Every kind of plan can be applied, except a privileged catalog inspection.
_Avoid_: Dry-run guarantee, transaction, saved commands

**Admission deadline**:
The time on a managed server's monotonic clock, 15 minutes after a plan's evidence was collected in the same boot, after which the plan can no longer be admitted for applying. It limits admission, not the lifetime of accepted work.
_Avoid_: Expiry date, timeout

**Refusal**:
One reason a configuration plan cannot be applied, with what ordinary administration resolves it. A refused plan is still a review record; Barectl changes nothing.
_Avoid_: Error, failure

**Reconciliation**:
Establishing an apply run's execution outcome from native evidence of its own transient unit after an interruption or uncertain response, through Check outcome. A reconciling run keeps the server's active slot and is never submitted again. Each check records only while no newer check has started.
_Avoid_: Retry, replay, rollback

**Outcome unknown**:
An apply run whose native evidence is gone, so Barectl cannot establish whether its requested changes completed. It stays reconciling until an operator allowed to apply its action acknowledges it and Barectl proves, under the mutation lock, that the run can no longer start or still be running; it then closes as failed with outcome unknown. Current configuration may still be observable without proving the run's history.
_Avoid_: Failed without changes, succeeded, safe to retry

**Apply run**:
A remote operation that submits one reviewed configuration plan revision to a managed server as a transient systemd unit and closes from native evidence of it. Its private approval and audit records belong to the Barectl installation and outlive the server's registration. Implemented for metadata refresh plans, for clearing finished bootstrap runs, for the Nginx and PHP profiles and for site plans.
_Avoid_: Deployment, provisioning run

**Package guard**:
The fixed shell command Barectl adds to one `apt-get install` as its last pre-install command. Under APT's dpkg lock and before dpkg changes any package, it compares APT's actual package actions with the reviewed plan's and stops the installation on any difference. Nothing of it is stored on the server.
_Avoid_: Hook script, helper, validator

**Execution outcome**:
What native evidence established about an apply run's unit: completed, refused before changes, partly applied, failed, timed out or terminated. Separate from verification and from the run's lifecycle state.
_Avoid_: Result, status

**Partly applied**:
The execution outcome of a site run that stopped after its first change, with the boundary it reached. What exists stays, and a new reviewed Finish plan creates only missing resources, with existing resources and account IDs revalidated as exact ([ADR 0015](docs/adr/0015-recognize-only-the-convention.md)). A site observation is also partly applied when every existing convention resource matches and some are absent.
_Avoid_: Rolled back, failed without changes

**Verification outcome**:
Whether a plan's postconditions held when checked with fresh reads after a successful execution, or why they could not be checked.
_Avoid_: Health check

**Mutation lock**:
The one empty, root-owned lock file, `/run/lock/barectl/mutation.lock`, that every apply payload takes without waiting before it checks its boot, deadline and evidence. It excludes mutations from every controller and alias of a server, which a local database cannot. It holds no data and is never replaced during its boot. On released servers, Certbot's renewal wrapper also takes it.
_Avoid_: Lease, lock record

**Finished bootstrap run**:
A transient bootstrap unit that systemd retains after its run ended, successful or failed, with no processes left. It is native evidence, not a conflict. New submissions are refused while 100 are retained; a reviewed cleanup clears them.
_Avoid_: Stale lock, zombie job

**Cleanup of finished runs**:
A reviewed maintenance action, applied like any apply run, that makes systemd forget listed finished bootstrap units after rechecking each one under the mutation lock. It never stops a unit with processes, keeps journal entries and Barectl's audit, and can leave another installation's run as outcome unknown.
_Avoid_: Garbage collection, reset

**Discovery worker**:
The separate process from the same application that runs queued remote operations: discovery attempts, plan preparations and apply runs. Accepted apply runs continue on the server without it.
_Avoid_: Agent

**Activity**:
The recorded discovery attempts across all managed servers, and for accounts that may review plans the plan preparations and apply runs too, newest recorded first, shown as one dashboard section. A managed server's Activity section shows the same record types scoped to that server registration, and a site's Activity the preparations and apply runs recorded for its identifier on that registration; neither establishes a current resource's identity or state. Activity distinguishes each attempt's outcome from the snapshot a success published and that snapshot's warnings; a failed or interrupted attempt stays listed beside the earlier snapshot it did not replace.
_Avoid_: Logs, event feed

**Discovery history**:
The attempts recorded in this Barectl installation for one managed server, newest recorded first, shown on that server's page. This history is not reconstructed from the server's logs or another device's private database.
_Avoid_: attempt log

**Native server history** (planned):
Past activity evidenced by logs and records that the server's operating system and services retain. It may be incomplete or unavailable and does not include private Barectl operation records.
_Avoid_: Discovery history, complete audit trail

**Jobs view** (planned):
A managed server's dashboard section for supported running work, schedules, background services and retained native server history. It is distinct from Activity's private Barectl records and does not list individual application queue items.
_Avoid_: Activity, complete audit trail, application job history

**Discovery snapshot**:
The timestamped observations from a discovery run, including warnings about anything that could not be inspected. A snapshot describes what was observed at collection time, not the server's live state.
_Avoid_: Live monitoring, real-time status

**Stale observation**:
The last successful discovery snapshot while a later discovery attempt is queued or running, or after it failed. Pages keep showing it with its collection time and a notice, but it cannot authorize a change until a new attempt succeeds.
_Avoid_: Cached state, current observation

**Observation**:
One fact about a managed server recorded in a discovery snapshot, together with its observation outcome, the commands or files it was read from, and any warning.
_Avoid_: Result, check

**Observation outcome**:
Whether an observation produced a finding: observed, absent, inaccessible or unsupported. Absent is a positive finding that something does not exist; unsupported is no finding at all.
_Avoid_: Status (in prose), error

**Observed**:
The observation outcome when Barectl read the fact and interpreted it.

**Absent**:
The observation outcome when Barectl's supported way of inspecting worked and showed that the thing does not exist on the managed server. A missing inspection tool never makes something absent.
_Avoid_: Missing, not found

**Inaccessible**:
The observation outcome when the SSH user's permissions refused ordinary discovery. Ordinary discovery never escalates privileges to overcome it.
_Avoid_: Forbidden, denied

**Unsupported**:
The observation outcome when Barectl reached no conclusion, because what it read is not in a form it interprets or its way of inspecting is unavailable on the server. It says nothing about whether the thing exists.
_Avoid_: Unknown, failed

**Web-stack component**:
One of the server software products Barectl recognises in a managed server's web stack: Nginx, PHP-FPM, MariaDB or PostgreSQL.
_Avoid_: Service, software, stack, app

**Service unit**:
A systemd unit that runs part of a web-stack component, such as `nginx.service`.
_Avoid_: Service, daemon

**Service state**:
The running state systemd reports for a service unit, such as active (running) or inactive (dead).
_Avoid_: Service status, health

**Component observation**:
The observation of one web-stack component in a discovery snapshot: its package observation, its service observation, each with its own observation outcome, and whether the installed packages follow the server release's bootstrap profile.
_Avoid_: Service observation, service

**Package observation**:
The half of a component observation that records which of the component's packages are installed and their versions, and names any versioned or variant package outside the server release's bootstrap profile.
_Avoid_: Version check

**Not following the profile**:
The state of a component whose installed packages, PostgreSQL major or cluster lie outside the server release's bootstrap profile. The observation names each one and what to remove or change, and Barectl reads only the release default PostgreSQL major's `main` cluster.
_Avoid_: Foreign package, custom stack

**Service observation**:
The half of a component observation that records the service states of the component's service units.
_Avoid_: Service status, health check

**Nginx site file**:
One entry under `/etc/nginx/sites-enabled`. Discovery reads only the declared server names of an enabled file that is neither the distribution's default nor a Barectl convention candidate; it does not treat one as a site, and it no longer lists site files generally.
_Avoid_: Site, vhost, virtual host

**PHP-FPM pool**:
A named PHP-FPM worker pool within one PHP version, identified by that version and its pool name.
_Avoid_: Pool, FPM config, worker

**Site**:
A PHP application whose native configuration links its document root and domain names to a PHP-FPM pool and a dedicated Linux site user. A database binding and TLS are optional. Discovery recognizes a site, whoever made it, by its exact match with the convention from native evidence, and applying a site plan creates one.
_Avoid_: Nginx site file, website, domain

**Site observation**:
The observation of one site candidate in a discovery snapshot, carrying exactly one state: managed, partly applied, changed outside Barectl, or not following the convention. Discovery recognizes a site by rendering the convention for its identifier and comparing native evidence byte for byte. Only accounts allowed to view site observations see them.
_Avoid_: Site health, managed site

**Not following the convention**:
The state of an enabled Nginx site file that is neither the distribution's default nor a Barectl convention candidate, or of a pool file outside the convention. The item names the file and, for a site file, its declared server names only; Barectl does not interpret it or change anything that depends on it.
_Avoid_: Foreign site, custom site, unsupported site

**Changed outside Barectl**:
The state of a convention candidate whose existing evidence no longer matches the convention. The observation names the first differing file and offers the content Barectl expects there, with no per-difference list, and locks the site until it matches again.
_Avoid_: Drifted site, edited site

**Supported site convention**:
The one native layout Barectl reconstructs, and will create, for a site: fixed Nginx and PHP-FPM files, paths, owners, modes and account attributes. A site that matches it was read that way; this is neither a serving check nor permission to change it.
_Avoid_: Template, healthy site

**Site plan**:
A configuration plan that reviews creating or finishing one site by the supported site convention: the exact generated files, directories, account, reloads and serving probe, or why the server cannot take the site. Its own permissions govern viewing, preparing and applying it, separately from bootstrap plans.
_Avoid_: Site template, site request

**Site convention template**:
One of the exact files the supported site convention generates for a site: its Nginx file, pool, placeholder page or serving probe. Site admission recognizes an existing file as the convention's only when its bytes equal a template's.
_Avoid_: Snippet, sample configuration

**Site user**:
The dedicated Linux identity under which one site's PHP application runs. It is separate from the operator's Barectl account and SSH identity.
_Avoid_: Operator, database principal

**Database principal**:
The native database account or role through which a site accesses its database, named like its site user. In v0.3 it authenticates through the local Linux site identity. A database plan creates it.
_Avoid_: Site user, Barectl account

**Database binding**:
The observed relationship between a site, a database and its database principal, established by native authentication, ownership and grants. Discovery reads it as root only, never escalating; it is satisfied, partial or not following the convention as the database convention describes.
_Avoid_: Saved connection, database name match

**Driver plan**:
A configuration plan that installs the selected site's branch-specific PHP driver for MariaDB or PostgreSQL through the exact package transaction and reloads that branch's PHP-FPM, judging its pool directory by the site grammar. Historical plans retain the release-default branch. Its own permissions are database plans'.
_Avoid_: Extension install, PHP module management

**Binding plan**:
A configuration plan that creates one site's database, principal and privileges by the database convention, statement by statement, and proves them through the site's own pool. Its own permissions are database plans'.
_Avoid_: Database provisioning, migration

**Catalog inspection**:
A read-only preparation that reads every site's database binding with privilege, as root or through noninteractive sudo, when ordinary discovery cannot. It is kept only with its plan and never updates discovery.
_Avoid_: Privileged discovery, escalation

**Satisfied binding**:
A database binding whose catalog rows are exactly the ones the database convention's statements create, and nothing else.
_Avoid_: Healthy database, working database

**Partial binding**:
A database binding where the database convention's statements took effect only up to one of them, in their order, and nothing else exists. A reviewed Finish plan runs only the remaining statements while the existing prefix stays exact; other states require ordinary administration.
_Avoid_: Broken binding, half-created database

**Guarded renewal**:
Certbot's packaged timer running Barectl's wrapper through a reviewed drop-in: it takes the mutation lock, skips while a Barectl run has processes, renews with one fixed deploy hook, and fails when a renewed certificate is not the one Nginx serves.
_Avoid_: Barectl renewal agent, renewal cron

**Renewal inhibition**:
Runtime masks on `certbot.timer` and `certbot.service` for the duration of a setup run, so the package's maintainer scripts cannot enable or start renewal before the guard exists.
_Avoid_: Disabling Certbot, stopping the timer

**Certificate installation**:
The operator's Create and Install request for a site's explicit domain names, obtaining its certificate, activating HTTPS and enabling native automatic renewal.
_Avoid_: DNS setup, certificate upload

**Certificate lineage** (planned):
Certbot's native certificate, key references and renewal configuration for one site's explicit names, including successive renewed certificates.
_Avoid_: Private approval record, site inventory

**Challenge route**:
A site's HTTP-01 route: one Nginx location that serves `/.well-known/acme-challenge/` as files from the site's own webroot under `/var/lib/letsencrypt`, never as PHP or a listing. Adding it replaces the site file and keeps the preimage.
_Avoid_: ACME proxy, challenge alias

**Recovery preimage**:
A root-only copy of a file a run replaced, named after the run's unit, kept for ordinary-administration recovery and never read as current state.
_Avoid_: Rollback file, backup record

**TLS readiness**:
The server's own fresh evidence that an order could stand on: each site name's DNS answers, the server's global addresses, its NTP-synchronized clock and the authority directory's answer over every family the names publish. A proxy in front of the site, an AAAA record without a working IPv6 path, CAA that names another authority, or an unreachable directory refuses.
_Avoid_: Uptime check, DNS management

**Staging order**:
An order against a staging authority into isolated configuration, work and log directories, ordered through an explicit `apply_tlsplan`; its evidence is diagnostic and Nginx never references the result.
_Avoid_: Production certificate, self-signed certificate

**Production order**:
One reviewed `certonly` order into Certbot's ordinary lineage `/etc/letsencrypt/live/<identifier>`, applied with `tls.issue_certificate` under the shared mutation lock; a matching lineage is a plan without changes, and a lost answer is reconciled without ordering twice.
_Avoid_: Auto-renewal, certificate install

**HTTPS activation**:
The separately reviewed publication of a site's HTTPS server block and then its HTTP redirect, keeping the HTTP-01 challenge route; a failed redirect stage leaves the verified HTTPS state. No HSTS.
_Avoid_: TLS install, certificate deployment

**Default TLS rejection server**:
The shared root-owned `/etc/nginx/conf.d/tls-default-reject.conf` with the IPv4 and IPv6 443 `default_server` listeners and `ssl_reject_handshake on`, so an unknown or absent SNI receives no certificate; later activations verify it and refuse competing defaults.
_Avoid_: SSL default vhost, catch-all certificate

**Barectl dashboard**:
The operator-facing interface for working with managed servers and discovery results.
_Avoid_: Django admin

**WordPress installation**:
A single WordPress application attached to one convention site and its local MariaDB binding. It is separate from the site's Nginx, PHP and certificate resources.
_Avoid_: WordPress server, site creation

**WordPress installation review**:
The immutable proposal to install WordPress at the root of one HTTPS name of a prepared convention site, bound to the pinned tool, archive and limits, the exact routing forms and the evidence it was read from. Preparing it changes nothing and runs no application code; it holds no password or salt. Applying it is a separate step.
_Avoid_: installation plan, WordPress setup

**WordPress Finish**:
The reviewed completion of a WordPress installation that stopped behind its provisioning gate. It reconstructs eligibility from the server alone and proposes only the missing resources it can verify as exactly what the installation creates, with the existing release files compared with a fresh copy of the pinned archive, then the reviewed change from the gate to the ready routing. Core installation runs once and only in a wholly empty database. It never replaces a file, rotates a salt, resets an administrator or deletes data; ambiguous or edited state needs ordinary administration.
_Avoid_: repair, recovery, resume

**WordPress PHP runtime**:
The fixed set of Ubuntu PHP extension packages (MySQL, cURL, XML, mbstring, ZIP, GD and intl) and the PHP build's own capabilities that one convention site's selected PHP branch needs before WordPress, reviewed as an exact package transaction and verified in the selected CLI and the site's own pool. It installs no WordPress, tool or database.
_Avoid_: WordPress server, extension management

**WordPress administrator**:
A WordPress application account allowed to administer that installation. It is separate from a Barectl account, Linux site user and database principal.
_Avoid_: Operator, superuser

**WordPress inspection**:
An explicitly authorized examination through WordPress tooling that may execute the application's code. Its result is separate from passive discovery evidence.
_Avoid_: Read-only discovery, health check

**WordPress supported combination**:
One supported Ubuntu release with its own PHP branch from Ubuntu packages and its default MariaDB, on one architecture, whose native suites passed for the pinned WordPress and WP-CLI on a recorded revision. The reviews refuse every other combination, and an architecture without recorded native statuses stays disabled.
_Avoid_: compatible environment, supported version

**WordPress maintenance action**:
One reviewed, named WP-CLI operation against a supported WordPress installation, with a fixed target and stated effects.
_Avoid_: Shell command, deployment

**Laravel application** (planned):
One Laravel application attached to a convention site, its private configuration, writable storage and local database binding.
_Avoid_: Laravel server, site creation

**Candidate release** (planned):
An inactive application code revision prepared for review. Its presence does not prove readiness, serving or successful schema changes.
_Avoid_: Deployment success, backup

**Current release** (planned):
The application code revision selected for serving by the site's operative configuration. Selection alone does not establish serving verification or background-process convergence.
_Avoid_: Healthy deployment, latest release

**Release staging** (planned):
Preparing an exact reviewed source revision and its locked production dependencies without selecting it for public serving.
_Avoid_: Activation, Git pull

**Release activation** (planned):
Selecting an eligible reviewed release and verifying its serving and managed-process outcomes. It does not imply a database transaction or uninterrupted service.
_Avoid_: Installation, atomic deployment

**Code reactivation** (planned):
Selecting a retained eligible code release after fresh review of current application state and compatibility. It does not reverse database, configuration, storage or job effects.
_Avoid_: Database rollback, restore

**Laravel migration action** (planned):
A separately reviewed execution of an application's conventional database migrations against its bound database, with explicit irreversible-effect and recovery limits.
_Avoid_: Code activation, schema rollback

**Maintenance gate** (planned):
Operative web routing that refuses new application traffic while preserving certificate challenges. It does not establish application-wide quiescence.
_Avoid_: Transaction isolation, provisioning gate

**Laravel scheduler** (planned):
Native minute execution of an application's supported scheduled work, independent of a connected Barectl controller.
_Avoid_: Controller job, hosted scheduler

**Laravel queue worker** (planned):
A native managed process executing an application's supported database queue jobs as its site identity.
_Avoid_: Barectl agent, discovery worker

**Backup artifact** (earlier rclone design only):
One complete recovery copy of a site's bound database, optionally with the matching application's runtime data. Observed availability, integrity and demonstrated restoration are separate findings. The target stack keeps recovery points in restic repositories instead ([ADR 0031](docs/adr/0031-back-up-with-restic.md)).
_Avoid_: Release, recovery preimage, server image

**Backup scope** (planned):
The recovery data selected for a capture: database only, or full application with its database. Full application includes the data required for its supported runtime recovery.
_Avoid_: Files-only backup, full server backup

**Onsite copy** (earlier rclone design only):
An encrypted backup artifact retained on its managed server. Its availability does not establish recovery after loss of that server.
_Avoid_: Disaster recovery guarantee

**Offsite copy** (earlier rclone design only):
The matching encrypted artifact retained outside the managed server under the supported storage convention. Its verified transfer does not establish that restoration has succeeded.
_Avoid_: Mirror, snapshot

**Backup schedule** (planned):
A site's recurring capture policy executed by native server scheduling without a connected Barectl device. Retained native evidence may not contain every historical invocation.
_Avoid_: Controller task, hosted scheduler

**Restore** (planned):
A separately reviewed destructive recovery of the selected site's database or full application from an exact compatible backup artifact. Partial recovery is not an atomic rollback and stays gated until verified.
_Avoid_: Code reactivation, migration rollback

**Safety backup** (planned):
A verified current capture made before restoring a nonempty target. It preserves a recovery option without promising automatic compensation.
_Avoid_: Automatic rollback

**Security review** (planned):
A server's plain-language findings about its firewall, SSH sign-in, automatic security updates, pending updates and restart requirement, reconstructed from native evidence with its collection time. It reports what Barectl could read; it is not a score or a statement that the server is secure.
_Avoid_: Security score, audit, compliance check

**Security finding** (planned):
One observed fact in a security review with its impact and the reviewed action or ordinary administration that addresses it. Unreadable evidence is an unknown finding, never a passing one.
_Avoid_: Vulnerability, alert

**Firewall standard** (planned):
UFW active with IPv6, default deny incoming, allow outgoing and deny routed, allowing each effective SSH port, HTTP and HTTPS, plus operator port rules from anywhere or one network. Any other rule or packet-filter manager does not follow the standard.
_Avoid_: Security group, cloud firewall

**SSH sign-in policy** (planned):
The fixed sshd drop-in that requires key sign-in and limits root to keys, or refuses root when Barectl does not connect as root. The effective `sshd -T` result decides whether it holds.
_Avoid_: SSH hardening, key management

**Confirm-or-revert window** (planned):
The fixed period after a firewall or SSH change during which a transient systemd timer restores the recovery preimage unless a new verified connection from the controller confirms access. Other Barectl mutations refuse while it is open.
_Avoid_: Rollback, grace period

**Automatic security updates** (planned):
Ubuntu's standard unattended-upgrades configuration: daily list refresh and unattended installation from the distribution's allowed origins, without automatic reboot. Barectl enables it but never runs it.
_Avoid_: Auto-patching, Barectl updates

**Pending update** (planned):
An installed package with a newer candidate in the server's current package lists, marked as security, other, phased, held or blocked. The list is only as current as its last refresh.
_Avoid_: Available upgrade, outdated package

**Restart required** (planned):
Ubuntu's `/run/reboot-required` evidence that installed packages take effect only after a reboot, with the packages that requested it.
_Avoid_: Reboot pending, unhealthy server

**Retention policy** (earlier rclone design only):
A site's reviewed number of days to keep backups, recorded only as its native cleanup unit. Cleanup deletes older artifacts one exact path at a time and always keeps the newest verified artifact of each scope in each location.
_Avoid_: Lifecycle rule, pruning schedule
