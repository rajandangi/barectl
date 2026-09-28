# Serialize remote operations on a server in one table

One Barectl database permits at most one queued, running, or reconciling remote operation for a managed server. Discovery and plan preparation are implemented kinds; apply runs are declared and will use the same lifecycle owner, rather than independent tables whose constraints cannot exclude one another. Native cross-device exclusion is separately defined in [ADR 0006](0006-use-native-bootstrap-execution.md).

The `operations` app's RemoteOperation table holds every kind's lifecycle columns, and `operations/lifecycle.py` owns queueing, claiming, conditional transitions, recovery and the one worker task. Each kind's details are a Django multi-table-inheritance model (`DiscoveryAttempt`, `PlanPreparation`), whose implicit one-to-one parent link makes the detail share the operation's identifier and keeps discovery's permission codenames. Transitions update the shared table directly, so each remains one conditional UPDATE. One partial unique index enforces the active set. There is no busy flag on the registration, and no database transaction is held open across SSH work.

Apply execution outcome and postcondition verification are separate from local lifecycle. The shared states are queued, running, reconciling, succeeded, and failed; recovery is kind-specific. Each kind registers its step and whether an abandoned operation may be failed after a stale limit: discovery and plan preparation only read, so they keep discovery's ten-minute interruption rule, and a reconciling operation is never failed by it. A dispatched or possibly dispatched apply enters reconciliation when its controller disappears and must not automatically fail or release exclusion after discovery's timeout. Check outcome runs within that operation so recovery does not conflict with its own active slot. See [the v0.2 lifecycle](../v0.2.md#local-lifecycle-and-uncertainty) for native evidence and safe closure requirements.

## Consequences

- Discovery, preparation, and apply cannot queue over one another for the same registration within one database. Different aliases and independent databases still require native mutation exclusion.
- Active operations block registration editing and removal. Terminal apply audit survives removal with copied non-secret server identity and plan details, independent of deleted discovery history.
- The shared service owns queueing, claiming, conditional transitions, and persistence. Each kind owns its evidence, recovery policy, and work; a new kind does not get a competing lifecycle implementation.
- Local audit is not copied to the managed server and cannot be reconstructed by a fresh controller. Unknown remote outcomes remain explicit even if current configuration can be inspected.
