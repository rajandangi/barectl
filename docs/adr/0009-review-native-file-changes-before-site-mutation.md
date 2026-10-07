# Review native file changes before site mutation

Accepted for v0.3. Implemented for site creation ([ADR 0012](0012-publish-site-files-without-replacing-them.md)) and [TLS activation](../tls.md#activation). Site creation and TLS activation extend immutable configuration plans with exact non-secret file preimages and replacements, native account effects and service reloads. Revalidate the complete relevant configuration and collision evidence under the existing server-wide exclusion before mutation, publish each file safely, and verify native syntax and serving behavior.

Multiple files, accounts and services cannot form one atomic transaction. Report partial completion after the first write, retain ordinary configuration preimages for recovery, and never compensate by deleting application data or adopting an external resource. A declarative remote manifest or reconciliation daemon would weaken reconstruction from native state; both are excluded. The full admission and recovery contract is in [v0.3](../v0.3.md#exact-configuration-review-and-admission), with paths in the [site convention](../site-conventions.md).

[ADR 0015](0015-recognize-only-the-convention.md) supersedes refusal of every partly applied site. Exact existing resources can be finished by a new reviewed plan that creates only what is missing; it never replaces or removes them.
