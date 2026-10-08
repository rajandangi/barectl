# Deploy Laravel through reviewed native releases

Accepted for [v0.5](../v0.5.md), with implementation and qualification pending. Resolve a repository reference to an exact Git commit, stage it through a separately reviewed finite operation, and activate only a freshly reviewed candidate. Git and Composer remain native upstream tools. Root controls release publication; application tooling runs as the site identity. Private environment configuration and storage survive code replacement.

## Trade-off

An in-place Git pull changes serving code before readiness is established and mixes writable source with runtime state. Release directories concentrate code preparation and let a current link select code without claiming the whole deployment is atomic. This adds an explicit Laravel convention alongside the generic PHP convention. The only supported symlinks are operative current, environment and storage links with exact confined targets. [ADR 0015](0015-recognize-only-the-convention.md) remains in force, and this extends its recognized grammar rather than adopting arbitrary layouts. Its generic prohibition on application symlinks still applies outside this form.

Default Deployer recipes use `.dep` release history and `REVISION`/bad-release markers; dploy accepts arbitrary commands and manages retention. Their documented defaults do not satisfy Barectl's private-audit, exact review and no-deletion contract. The [reuse analysis](../laravel-native-design.md#upstream-reuse-and-the-specific-gap) records the checked alternatives. Use supported upstream operations where they fit; custom code must only enforce Barectl admission, protected publication and outcome reporting through [ADR 0006](0006-use-native-bootstrap-execution.md).

## Database and exposure consequences

Migration, code selection and process convergence are distinct outcomes. A current-link switch can select code; it cannot reverse schema, shared storage, environment changes or application effects. Migrations require separate review, compatibility/recovery acknowledgement and a public gate. No automatic rollback or replay follows uncertain schema work. A fresh code-reactivation plan is not database recovery.

Activation promises a bounded maintenance window and verified outcomes, rather than zero downtime. The gate preserves ACME and rejects new application traffic, but does not stop prior requests or external commands. Record limits and refuse unreliable managed-process coordination. v0.6 owns verified restore.

Stage extends the existing transient-unit submission with fixed native tmpfs/memory resource properties. A private bounded filesystem limits build bytes/inodes, and the run safely publishes an inactive protected candidate before ending. Unpublished staging vanishes with the unit and is not recoverable history. This explicitly extends ADR 0006's action-specific submission configuration while retaining its one SSH integration, finite payload, shared lock, fencing and no-replay outcome contract. No persistent helper or parallel deployment engine is introduced.

## Sources

[Laravel deployment](https://laravel.com/docs/13.x/deployment), [Composer root execution guidance](https://getcomposer.org/doc/faqs/how-to-install-untrusted-packages-safely.md), [Git fetch](https://git-scm.com/docs/git-fetch), [Deployer release recipe](https://deployer.org/docs/8.x/recipe/deploy/release), [Deployer rollback recipe](https://deployer.org/docs/8.x/recipe/deploy/rollback), [dploy workflow](https://www.cloudpanel.io/docs/v2/dploy/installation/). These establish tool behavior; the review and publication rules are Barectl policy.
