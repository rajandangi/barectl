# Use one native rclone backup convention

> Superseded by [ADR 0031](0031-back-up-with-restic.md): backups use restic.

Accepted for planned v0.6. Use native database clients and GNU tar for one complete recovery artifact, rclone crypt for onsite encryption and an exact AWS S3 offsite template, and fixed systemd service/timer configuration for controller-independent scheduling. Extend [ADR 0006](0006-use-native-bootstrap-execution.md) explicitly for those scheduled units and bounded file transfer through the existing pyinfra SSH connection, preserving its shared lock, cgroup exclusion, finite execution and no-replay rules.

A provider framework, a persistent backup helper or a server-side inventory/catalog would widen scope and weaken reconstruction. Native operative configuration and authenticated backup contents supply observations; private approval/audit stays local. Artifact-contained recovery metadata is recovery data, not live-server inventory or proof that a run succeeded. The [native contract and reuse record](../backups-native-design.md) own concrete choices, limitations and official sources. No existing runtime is changed or qualified by this decision.
