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
Deleting a managed server's registration and its local history from Barectl: discovery attempts with their snapshots, and plan preparations with their plans. It never connects to the server or changes the controller host, and it waits for any active remote operation.
_Avoid_: Deprovisioning, uninstall

**Remote operation**:
One queued run that connects to a managed server: a discovery attempt, a plan preparation or, in later releases, an apply run. Its lifecycle states are queued, running, reconciling, succeeded and failed. Within one Barectl database, a server has at most one queued, running, or reconciling remote operation, whatever its kind; independent devices also require coordination for conflicting changes.
_Avoid_: Job, task

**Bootstrap** (planned):
Preparing a supported managed server with the distribution's standard web-stack packages and service configuration after operator review.
_Avoid_: Site creation, server adoption

**Bootstrap profile**:
The supported package and service baseline an operator chooses to establish on a managed server: Nginx, or PHP 8.3 FPM and CLI, from Ubuntu 24.04 packages with their default configuration. Plans can be prepared for a profile; establishing it is planned.
_Avoid_: Arbitrary package list, site template

**Plan preparation**:
A remote operation that inspects a server read-only to build a configuration plan for a supported bootstrap profile or maintenance action. It may read with root or verified noninteractive sudo, unlike discovery, and cannot authorize or perform the proposed changes.
_Avoid_: Apply run, metadata refresh

**Configuration plan**:
An immutable local record of one plan preparation's decision: the proposed changes and their effects, or the reasons they are refused, tied to fingerprints of the server evidence, the boot and an admission deadline. Changed or unavailable evidence requires a new plan and review. Applying a plan is planned.
_Avoid_: Dry-run guarantee, transaction, saved commands

**Admission deadline**:
The time on a managed server's monotonic clock, 15 minutes after a plan's evidence was collected in the same boot, after which the plan can no longer be admitted for applying. It limits admission, not the lifetime of accepted work.
_Avoid_: Expiry date, timeout

**Refusal**:
One reason a configuration plan cannot be applied, with what ordinary administration resolves it. A refused plan is still a review record; Barectl changes nothing.
_Avoid_: Error, failure

**Reconciliation** (planned):
Establishing an apply run's execution outcome and the server's current condition from available native evidence after an interruption or uncertain response.
_Avoid_: Retry, replay, rollback

**Outcome unknown** (planned):
An apply run whose retained native evidence cannot establish whether its requested changes completed. Current configuration may still be observable without proving the run's history.
_Avoid_: Failed without changes, succeeded, safe to retry

**Apply run** (planned):
A remote operation that submits a reviewed configuration plan to a managed server and reconciles its execution and verified effects. Its private approval and audit records belong to the Barectl installation; apply runs are not implemented yet.
_Avoid_: Deployment, provisioning run

**Discovery worker**:
The separate process from the same application that runs queued discovery attempts.
_Avoid_: Agent

**Activity**:
The recorded discovery attempts across all managed servers, and for accounts that may review plans the plan preparations too, newest recorded first, shown as one dashboard section. Activity distinguishes each attempt's outcome from the snapshot a success published and that snapshot's warnings; a failed or interrupted attempt stays listed beside the earlier snapshot it did not replace.
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

**Site** (planned):
An operator-managed PHP application with its own Linux user, PHP-FPM pool, Nginx site file, databases and TLS. Barectl does not create or adopt sites yet.
_Avoid_: Nginx site file, website, domain

**Barectl dashboard**:
The operator-facing interface for working with managed servers and discovery results.
_Avoid_: Django admin
