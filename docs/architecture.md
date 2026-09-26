# Architecture

## Product boundaries

Barectl is one Django application. It may run locally or on a management host. Managed Linux servers remain agentless and expose SSH only for management. Provisioning will install ordinary web-stack packages; agentless does not mean a server can host applications without those packages.

The repository has `config`, `dashboard` (interface integration: Vite assets, sign-in form and HTMX request handling), `servers`, shared templates, and the Vite frontend sources in `frontend/`. Add domain apps when a workflow needs them. The interface uses USWDS and HTMX 4. `servers/ssh_config.py` reads controller SSH aliases with paramiko, mirroring the planned pyinfra connector's configuration handling (`docs/ssh-aliases.md`). pyinfra, a job runner, and credential storage are planned and not installed yet.

## Request and execution flow

Views validate input and authorize access, then call application services. Services create durable jobs. A separate worker process from the same codebase executes infrastructure adapters. Long SSH operations must not run inside HTTP requests.

pyinfra will provide facts and operations. Its actual SSH backend and compatibility with SSH configuration, agents, and hardware keys must be tested before promising support. Do not assume every OpenSSH feature works through every transport.

## State and discovery

Store the registration's SSH alias and timestamped observations separately. Connection settings stay in the controller's SSH configuration. The remote server is authoritative for observed configuration. A failed discovery must retain the previous successful snapshot while showing it as stale. Discovery never automatically adopts or rewrites an unmanaged site.

## Trust and credentials

Require authentication, Django permissions, CSRF protection, and verified SSH host identity. The current inventory is shared among permitted operators. It is not a tenant-isolated application.

Credentials start with the controller account's SSH agent or the key files its SSH configuration names. Hosted deployments cannot use a browser user's laptop agent automatically. Any future stored credentials need encryption with the encryption secret outside the database, restricted access, rotation, and log redaction. Never accept arbitrary shell commands from the web interface.

## Changes and jobs

Read-only discovery is the first remote workflow. Later mutations need a reviewed plan, revalidation against current state, per-server serialization, bounded timeouts, audit events, and explicit failure recovery. A plan preview is not a transaction or an automatic rollback guarantee. Validate Nginx/PHP configuration before reload and retain previous configuration for recovery.

Choose a durable worker implementation when the discovery workflow is built. Django 6's Tasks API does not itself supply a production worker. Avoid a custom queue unless its recovery and concurrency behavior can be demonstrated.

## References

- [Django 6 release notes](https://docs.djangoproject.com/en/6.0/releases/6.0/)
- [pyinfra documentation](https://docs.pyinfra.com/en/3.x/)
