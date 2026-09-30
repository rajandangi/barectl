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
An Ubuntu LTS release whose own policy bootstrap follows: Ubuntu 24.04 (noble) or Ubuntu 26.04 (resolute). It names the archives a reviewed transaction may use, the APT and systemd series qualified on it, its tested APT hook baseline, its default PHP version, PHP 8.3 or PHP 8.5, and its MariaDB series, archive components and data directory, MariaDB 10.11 from `main` and `universe` in `/var/lib/mysql` or MariaDB 11.8 from `main` in `/var/lib/mariadb`, and its default PostgreSQL major, 16 or 18. A server is reviewed only against its own release and never receives another release's packages.
_Avoid_: Supported OS, distribution version

**Third-party source**:
An APT source other than a supported release's own Ubuntu archive, which is its three suites and its backports, as the downloaded Release files identify them, such as a hosting provider's repository. An authenticated one may stay configured; an installation is refused while it offers any package of the transaction.
_Avoid_: Foreign repository, external source

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
The execution outcome of a site run that stopped after its first change, with the boundary it reached. What exists stays; Barectl neither completes, removes nor resumes it, and a new review refuses the incomplete site until ordinary administration resolves it.
_Avoid_: Rolled back, failed without changes

**Verification outcome**:
Whether a plan's postconditions held when checked with fresh reads after a successful execution, or why they could not be checked.
_Avoid_: Health check

**Mutation lock**:
The one empty, root-owned lock file, `/run/lock/barectl/mutation.lock`, that every apply payload takes without waiting before it checks its boot, deadline and evidence. It excludes mutations from every controller and alias of a server, which a local database cannot. It holds no data and is never replaced during its boot. Certbot's scheduled renewal is expected to take the same lock, and because its children do not keep it, every apply and closure also refuses while `certbot.service`'s control group has processes.
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
The recorded discovery attempts across all managed servers, and for accounts that may review plans the plan preparations and apply runs too, newest recorded first, shown as one dashboard section. Activity distinguishes each attempt's outcome from the snapshot a success published and that snapshot's warnings; a failed or interrupted attempt stays listed beside the earlier snapshot it did not replace.
_Avoid_: Logs, event feed

**Discovery history**:
The attempts recorded in this Barectl installation for one managed server, newest recorded first, shown on that server's page. This history is not reconstructed from the server's logs or another device's private database.
_Avoid_: Activity (that is the cross-server view), attempt log

**Native server history** (planned):
Past activity evidenced by logs and records that the server's operating system and services retain. It may be incomplete or unavailable and does not include private Barectl operation records.
_Avoid_: Discovery history, complete audit trail

**Discovery snapshot**:
The timestamped observations from a discovery run, including warnings about anything that could not be inspected. A snapshot describes what was observed at collection time, not the server's live state.
_Avoid_: Live monitoring, real-time status

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
The observation of one web-stack component in a discovery snapshot, made of its package observation and its service observation, each with its own observation outcome.
_Avoid_: Service observation, service

**Package observation**:
The half of a component observation that records which of the component's packages are installed and their versions.
_Avoid_: Version check

**Service observation**:
The half of a component observation that records the service states of the component's service units.
_Avoid_: Service status, health check

**Nginx site file**:
One enabled Nginx configuration entry on a managed server, whose server blocks declare server names and listen addresses. Discovery observes Nginx site files; it does not treat one as a site.
_Avoid_: Site, vhost, virtual host

**PHP-FPM pool**:
A named PHP-FPM worker pool within one PHP version, identified by that version and its pool name.
_Avoid_: Pool, FPM config, worker

**Site**:
A PHP application whose native configuration links its document root and domain names to a PHP-FPM pool and a dedicated Linux site user. A database binding and TLS are optional. Discovery reconstructs sites from native evidence, and applying a site plan creates one; Barectl never adopts an existing site.
_Avoid_: Nginx site file, website, domain

**Site observation**:
The observation of one site candidate in a discovery snapshot: each of its native resources with its own observation outcome, and whether all of them follow the native site convention. Only accounts allowed to view site observations see them.
_Avoid_: Site health, managed site

**Supported site convention**:
The one native layout Barectl reconstructs, and will create, for a site: fixed Nginx and PHP-FPM files, paths, owners, modes and account attributes. A site that matches it was read that way; this is neither a serving check nor permission to change it.
_Avoid_: Template, healthy site

**Site plan**:
A configuration plan that reviews creating one site by the supported site convention: the exact generated files, directories, account, reloads and serving probe, or why the server cannot take the site. Its own permissions govern viewing, preparing and applying it, separately from bootstrap plans.
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
The observed relationship between a site, a database and its database principal, established by native authentication, ownership and grants. Discovery reads it as root only, never escalating; it is satisfied, partial or custom as the database convention describes.
_Avoid_: Saved connection, database name match

**Driver plan**:
A configuration plan that installs the release's PHP driver for MariaDB or PostgreSQL through the exact package transaction and reloads PHP-FPM, judging its pool directory by the site grammar. Its own permissions are database plans'.
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
A database binding where the database convention's statements took effect only up to one of them, in their order, and nothing else exists. Only ordinary administration completes or removes it.
_Avoid_: Broken binding, half-created database

**TLS enrollment** (planned):
A reviewed action that obtains a certificate for a site's explicit names and activates HTTPS with native automatic renewal.
_Avoid_: DNS setup, certificate upload

**Certificate lineage** (planned):
Certbot's native certificate, key references and renewal configuration for one site's explicit names, including successive renewed certificates.
_Avoid_: Private approval record, site inventory

**Barectl dashboard**:
The operator-facing interface for working with managed servers and discovery results.
_Avoid_: Django admin
