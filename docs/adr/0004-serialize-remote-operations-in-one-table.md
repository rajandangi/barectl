# Serialize remote operations on a server in one table

This decision governs planned local lifecycle expansion for v0.2. One Barectl database permits at most one queued, running, or reconciling remote operation for a managed server. Discovery is the only implemented kind; plan preparation and apply runs add real workflows using the same lifecycle owner, rather than independent tables whose constraints cannot exclude one another. Native cross-device exclusion is separately defined in [ADR 0006](0006-use-native-bootstrap-execution.md).

When plan preparation is introduced, migrate discovery's lifecycle columns to a shared RemoteOperation table, with typed one-to-one details for discovery, preparation, and apply. Preserve existing discovery identity, snapshots, history, permissions, queue behavior, and conditional transitions during migration. One partial unique index enforces the active set. Do not add a busy flag to the registration or hold a database transaction open across SSH work.

Apply execution outcome and postcondition verification are separate from local lifecycle. The shared states are queued, running, reconciling, succeeded, and failed; recovery is kind-specific. Discovery retains its current interruption rules. A dispatched or possibly dispatched apply enters reconciliation when its controller disappears and must not automatically fail or release exclusion after discovery's timeout. Check outcome runs within that operation so recovery does not conflict with its own active slot. See [the v0.2 lifecycle](../v0.2.md#local-lifecycle-and-uncertainty) for native evidence and safe closure requirements.

## Consequences

- Discovery, preparation, and apply cannot queue over one another for the same registration within one database. Different aliases and independent databases still require native mutation exclusion.
- Active operations block registration editing and removal. Terminal apply audit survives removal with copied non-secret server identity and plan details, independent of deleted discovery history.
- The shared service owns queueing, claiming, conditional transitions, and persistence. Each kind owns its evidence, recovery policy, and work; a new kind does not get a competing lifecycle implementation.
- Local audit is not copied to the managed server and cannot be reconstructed by a fresh controller. Unknown remote outcomes remain explicit even if current configuration can be inspected.
