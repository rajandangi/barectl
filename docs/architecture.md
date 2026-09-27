# Architecture

## Product boundaries

Barectl is one Django application. It may run locally or on a management host. Managed Linux servers remain agentless and expose SSH only for management. Provisioning will install ordinary web-stack packages; agentless does not mean a server can host applications without those packages.

The repository has `config`, `dashboard` (interface integration: Vite assets, sign-in form and HTMX request handling), `servers` (registration, removal and server pages), `discovery` (attempts, snapshots, the worker task and the SSH transport), shared templates, and the Vite frontend sources in `frontend/`. Add domain apps when a workflow needs them. The interface uses USWDS and HTMX 4. `servers/ssh_config.py` reads controller SSH aliases with paramiko, mirroring the planned pyinfra connector's configuration handling (`docs/ssh-aliases.md`). `discovery/ssh.py` is the only remote execution boundary (`docs/ssh-connections.md`). pyinfra and credential storage are planned.

## Request and execution flow

Views validate input and authorize access, then call application services. Services create durable jobs. A separate worker process from the same codebase executes infrastructure adapters. Long SSH operations must not run inside HTTP requests.

Discovery follows this flow. `discovery.services.queue_discovery` records a queued attempt and enqueues the `run_discovery` task in one transaction, using Django's tasks framework with the `django-tasks-db` database backend. `manage.py db_worker` runs the task, which resolves the alias, connects through `discovery.ssh.connect`, collects observations and publishes the snapshot with the attempt's outcome.

Read-only discovery uses paramiko through `discovery/ssh.py`, whose supported configuration, agent and host-trust behavior is recorded in `docs/ssh-connections.md`. pyinfra is planned for changes to servers. Its SSH backend must be tested against the same configuration, agent and hardware-key behavior before promising support. Do not assume every OpenSSH feature works through every transport.

The pyinfra adapter must meet the same host-trust rules as discovery:

- Pass the alias's known_hosts files as `ssh_known_hosts_file` and set `ssh_strict_host_key_checking` to `yes`. pyinfra's default, `accept-new`, adds unknown host keys to known_hosts.
- Refuse the aliases `servers/ssh_config.py` refuses, and resolve them with pyinfra's own `get_ssh_config` so both transports read the same settings.
- Use a pyinfra release that accepts the pinned paramiko version. The dependency audit must still pass. The verification is recorded in [#4](https://github.com/rajandangi/barectl/issues/4#issuecomment-5845273176).

## State and discovery

Store the registration's SSH alias and timestamped observations separately. Connection settings stay in the controller's SSH configuration. The remote server is authoritative for observed configuration. A failed discovery must retain the previous successful snapshot while showing it as stale. Discovery never automatically adopts or rewrites an unmanaged site.

## Trust and credentials

Require authentication, Django permissions, CSRF protection, and verified SSH host identity. The current inventory is shared among permitted operators. It is not a tenant-isolated application.

Credentials start with the controller account's SSH agent or the key files its SSH configuration names. Hosted deployments cannot use a browser user's laptop agent automatically. Any future stored credentials need encryption with the encryption secret outside the database, restricted access, rotation, and log redaction. Never accept arbitrary shell commands from the web interface.

## Changes and jobs

Read-only discovery is the first remote workflow. Later mutations need a reviewed plan, revalidation against current state, per-server serialization, bounded timeouts, audit events, and explicit failure recovery. A plan preview is not a transaction or an automatic rollback guarantee. Validate Nginx/PHP configuration before reload and retain previous configuration for recovery.

Durable jobs use Django's tasks framework with the `django-tasks-db` backend and its `db_worker` command. Per-server serialization is a database constraint on discovery attempts, and discovery attempts protect their server from deletion, so removal cannot race an attempt (`docs/ssh-connections.md#server-removal`). SQLite transactions begin immediately, so concurrent requests and the worker wait for each other's writes rather than failing with "database is locked". Attempts interrupted by a forced worker stop, or active for longer than ten minutes, are recovered as interrupted failures, keeping any previous snapshot; finishing filters on still-running attempts so a stale worker cannot overwrite newer results. Queued attempts with a ready task wait for the worker; there is no automatic retry.

## References

- [Django 6 release notes](https://docs.djangoproject.com/en/6.0/releases/6.0/)
- [pyinfra documentation](https://docs.pyinfra.com/en/3.x/)
