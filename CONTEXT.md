# Barectl

Barectl lets an operator inspect and manage native Linux web servers from a local or self-hosted application.

## Language

**Operator**:
The person using a Barectl installation to manage its registered servers.
_Avoid_: Customer, tenant

**Managed server**:
A remote Linux machine registered with Barectl for inspection and, in later releases, management.
_Avoid_: Barectl host, control panel

**Controller host**:
The machine running Barectl and holding the SSH credentials used to access managed servers. It may be the operator's local computer or a private management host.
_Avoid_: Managed server

**SSH alias**:
A concrete `Host` name in the controller host's SSH configuration. A managed server is registered by its alias; connection settings, credentials and host trust stay on the controller host.
_Avoid_: Connection details, hostname

**Reconciliation**:
Choosing an SSH alias for a record migrated from explicit connection details. Such a record cannot connect until reconciled.
_Avoid_: Automatic matching

**Discovery**:
A read-only inspection of a managed server's current configuration and resources.
_Avoid_: Provisioning, bootstrap

**Discovery attempt**:
One queued run of connection verification and discovery for a managed server, with the outcome queued, running, succeeded or failed. A server has at most one queued or running attempt.
_Avoid_: Job, scan

**Verified connection**:
A connection whose host key matched the controller host's known_hosts and whose authentication succeeded, recorded by a succeeded discovery attempt. A registration alone is not verified.
_Avoid_: Connected, online

**Discovery worker**:
The separate process from the same application that runs queued discovery attempts.
_Avoid_: Agent

**Discovery snapshot**:
The timestamped observations from a discovery run, including warnings about anything that could not be inspected. A snapshot describes what was observed at collection time, not the server's live state.
_Avoid_: Live monitoring, real-time status

**Barectl dashboard**:
The operator-facing interface for working with managed servers and discovery results.
_Avoid_: Django admin
