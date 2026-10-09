# v0.8: Automatic backup retention

Accepted design for implementation, tracked in [#294](https://github.com/rajandangi/barectl/issues/294) and blocked by the v0.6 backup foundation [#271](https://github.com/rajandangi/barectl/issues/271). Runtime behavior and qualification remain pending. This milestone adds one age-based retention policy per site that deletes older backups automatically through native scheduling. It explicitly extends the [v0.6 capture and restore contract](v0.6.md), which excludes deletion, and the [backup native contract](backups-native-design.md). [ADR 0025](adr/0025-delete-expired-backups-by-exact-native-cleanup.md) owns the deletion boundary.

## Problem Statement

A site with a daily backup schedule keeps every copy forever. Onsite copies fill the server's disk until captures fail for lack of space, and offsite copies accumulate storage cost. The operator must delete old copies by hand with rclone or the AWS console, where a mistake can remove the only usable recovery copy. A new authorized device must understand the retention policy and its effects from the server alone.

## Solution

A site's Backups section shows a **Keep backups for** choice beside its schedule: 1 week, 2 weeks, 3 weeks, 1 month or 6 months, with 1 week preselected for a new policy. Enabling or changing the policy is a reviewed plan that lists every existing backup it would delete now, onsite and offsite, and states that deletion is permanent. Once accepted, a native daily cleanup deletes eligible backups with every Barectl controller closed.

Cleanup never deletes the newest verified backup of each scope in each location, never deletes when its evidence is uncertain, and never touches objects that do not follow the backup convention. Each cleanup's result appears in the Backups section and, once delivered, in Jobs.

## User Stories

1. As an operator, I want to choose how long to keep a site's backups, so that disk and storage use stay bounded.
2. As an operator, I want five fixed choices with a one-week default, so that the policy is predictable.
3. As an operator, I want each choice defined as an exact number of days, so that "1 month" does not depend on calendar months.
4. As an operator, I want the policy shown beside the backup schedule, so that I see how often copies are made and how long they stay.
5. As an operator, I want the review to list every backup that would be deleted now, so that I see the immediate effect before accepting.
6. As an operator, I want the review to say deletion is permanent, so that I do not expect to recover deleted copies.
7. As an operator, I want shortening a policy reviewed with the newly eligible backups, so that a change cannot silently delete more than I expected.
8. As an operator, I want no policy enabled automatically when I upgrade Barectl, so that existing backups are never deleted without review.
9. As an operator, I want cleanup to run on the server daily with Barectl closed, so that retention does not depend on my computer.
10. As an operator, I want the newest verified backup of each scope kept in each location regardless of age, so that a stopped schedule never leaves me with nothing.
11. As an operator, I want an onsite copy whose offsite copy is missing kept by the same rule, so that a failed upload does not cost me the only copy.
12. As an operator, I want cleanup to skip when the server clock is not synchronized, so that a wrong clock cannot make every backup look old.
13. As an operator, I want backups with unreadable, future or inconsistent timestamps kept and reported, so that uncertain age never authorizes deletion.
14. As an operator, I want objects that do not follow the backup convention ignored and reported, so that cleanup never deletes files it does not understand.
15. As an operator, I want cleanup coordinated with capture, upload, download and restore, so that it never deletes a backup another operation is using.
16. As an operator, I want offsite cleanup to use a separate deletion credential, so that the credential used for every capture still cannot delete backups.
17. As an operator, I want onsite cleanup to work without that credential, so that offsite deletion authority is optional.
18. As an operator, I want missing or revoked offsite deletion authority reported while onsite cleanup continues, so that one failure does not stop the other.
19. As an operator, I want each cleanup's deleted, kept, skipped and failed counts shown, so that I know what happened.
20. As an operator, I want a partly finished cleanup reported with exactly which deletions are established, so that I do not assume all or none happened.
21. As an operator, I want a cleanup that was interrupted to resume only through the next normal run, so that nothing is replayed blindly.
22. As an operator, I want versioned AWS buckets reported as keeping noncurrent copies, so that I know deleted objects may still cost storage.
23. As an operator, I want to disable the policy through review, so that no further automatic deletion happens.
24. As an operator, I want the policy reconstructed from the server's native configuration, so that another device sees and manages it without my database.
25. As an operator, I want a policy written in another form reported as not following the standard and left alone, so that Barectl never converts it.
26. As an operator, I want retention results in Jobs once Jobs is delivered, so that overnight cleanup is visible with other server work.
27. As a restricted Barectl account, I want a separate permission to change retention, so that backup access alone does not grant permanent deletion.
28. As an operator, I want exact tested versions and limits published, so that an accepted design is not confused with released capability.

## Implementation Decisions

- **D1. One owner.** Retention is part of the v0.6 backups module's interface: a typed retention observation and two named requests, set policy and disable policy. Eligibility, the native cleanup unit and deletion stay inside the module. No generic lifecycle or pruning framework.
- **D2. Periods.** 1 week = 7 days, 2 weeks = 14 days, 3 weeks = 21 days, 1 month = 30 days, 6 months = 182 days, each as exact multiples of 24 hours in UTC. The form preselects 1 week only when the site has no policy.
- **D3. Scope.** One policy per site applies to both scopes (database only and full) and both locations (onsite and offsite). Separate periods per scope or location are outside this milestone.
- **D4. Artifact age.** Age comes from the capture time in the artifact's logical path (`<UTC-basic-timestamp>`). The listed object's modification time must not precede it, and the capture time must not be in the future. Any mismatch, unparseable name or missing metadata keeps the object and reports it.
- **D5. Eligibility.** An artifact is eligible when it is older than the period at the cleanup's start time, and a newer artifact of the same site and scope in the same location passes the cleanup's own verification in the same run: full rclone crypt decryption and the artifact's `checksums.sha256`, within the v0.6 size and time budgets. Controller findings are never used. When the newer artifact cannot be verified, every artifact of that scope and location is kept. The newest verified artifact per site, scope and location is never eligible. Eligibility is computed per location; an onsite copy is never deleted because an offsite copy exists, or the reverse.
- **D6. Clock.** Cleanup requires `timedatectl` to report a synchronized clock at start; otherwise it skips with a reported reason.
- **D7. Native policy.** The policy is one fixed `s<identifier>-backup-retention.service` and `.timer` pair beside the v0.6 schedule units, with the period in days and a daily UTC time as the only template values, no catch-up and a finite `TimeoutStartSec` recorded in the native contract. The review proposes the first free slot after the site's schedule window, or the first free slot after 03:00 UTC without a schedule. Cleanup windows join the v0.6 fixed-window overlap check, so a cleanup can never make another site's capture skip. Native unit files and enablement are the policy's only record.
- **D8. Exact cleanup.** The cleanup lists the site's objects through the onsite crypt remote and, for offsite, the deletion crypt remote of D9, computes eligibility, then deletes each eligible object individually with `rclone deletefile` on its exact path. It never uses `rclone delete` with age filters, `purge` or provider lifecycle rules, which cannot keep the newest verified copy.
- **D9. Offsite authority.** The v0.6 capture principal keeps no delete permission. Offsite cleanup uses an optional second backend `barectl-s3-retention` and crypt remote `barectl-offsite-retention` over the same path and crypt settings, terminal-configured in the same encrypted configuration, whose AWS principal may only list, read and delete objects under the backup prefix. The [backup native contract](backups-native-design.md) admits exactly these two extra remotes; anything else still does not follow the standard. Without it, cleanup deletes onsite only and reports offsite as not configured.
- **D10. Coordination.** Cleanup is a scheduled native unit under ADR 0006 as extended by ADR 0021: it takes the shared mutation lock without waiting, refuses while a capture, replicate, restore, download staging or another cleanup has processes, and has a finite runtime. A refused or interrupted cleanup is retried only by the next daily tick.
- **D11. Results.** Each run writes one bounded journal line per deletion attempt with the logical path and result, then one summary: start time, period, deleted, kept, skipped and failed counts per location, and the reason for any skip. The Backups section reads them as native evidence with ordinary journal retention. A run that ends without its summary is partial; its per-deletion lines and the next listing establish what remains.
- **D12. Review.** Set policy previews eligibility from fresh authorized listings and lists each artifact that would be deleted now. Applying installs or replaces the units and does not delete anything itself; the first cleanup runs at the next tick. A stale preview cannot authorize the plan.
- **D13. Versioning.** When the bucket has versioning enabled, the review and results state that deletion leaves noncurrent versions that AWS still stores. Barectl does not manage lifecycle rules.
- **D14. Permissions.** `backups.change_retention` applies set and disable plans, in addition to the backup view and preparation permissions.
- **D15. Reconstruction.** A fresh controller recognises the policy from the native units, and recent results from the journal. Foreign units, edited templates or an extra backend are reported as not following the standard and block retention changes for that site only.
- **D16. Jobs.** Retention runs are added to Jobs as automatic work with their results once Jobs (v0.7) and this milestone are both delivered.

## Testing Decisions

- Test through the authorized Backups workflow: preview, review, apply, native cleanup evidence and rendered result. Reuse v0.6 schedule, native coordination and offsite fakes and real rclone tests.
- Qualify eligibility on disposable servers with backdated artifacts: each period, the newest-verified rule per scope and location, failed offsite copies, future and mismatched timestamps, malformed and foreign objects, and an unsynchronized clock.
- Qualify concurrency with two controllers and with capture, replicate, restore and download in progress; interrupted cleanup and the next tick; and missing, revoked and over-permissioned deletion credentials.
- Qualify offsite deletion against AWS S3 with the documented least-privilege principal, including a versioned bucket.
- Prove reconstruction from an independent controller database and refusal for edited units.
- Each slice runs repository gates and affected native tests locally, independent Standards and Spec reviews, and exact-head CI before merge.

## Out of Scope

Count-based or grandfather-father-son retention, separate periods per scope or location, manual deletion of a single backup, S3 lifecycle or Object Lock management, other providers, recovery of deleted backups, fleet-wide policies and notifications.

## Further Notes

The approved periods and default were settled before this specification. This document resolves the open design questions recorded in #294.
