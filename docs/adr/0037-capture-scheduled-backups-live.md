# Capture scheduled backups live

Accepted on 2026-10-10 for [#323](https://github.com/rajandangi/barectl/issues/323), delivered in Phase D; not implemented. Amends [ADR 0022](0022-review-destructive-restore-and-coordinated-capture.md). A scheduled recovery point is captured live: the database dump first, then the files, so every upload the dump references exists apart from deletions during the window. The recovery point is labelled live, and the restore screen says files and database can differ by the capture window. Manual captures and the safety capture before a restore still pause the site, now through a Caddy gate and an idle pool of that site only, without reloading the shared PHP-FPM master.

ADR 0022 required writer quiescence, including draining PHP-FPM, for every full capture. With one master per runtime ([ADR 0029](0029-share-one-php-fpm-master-per-runtime.md)), draining it for a nightly backup would interrupt every site on that runtime every night. Reopening the rule is justified because ADR 0022 assumed a master per site; the trade-off is a recovery point whose files and database may differ slightly, which is disclosed, in exchange for no scheduled downtime.

Restore keeps ADR 0022's review, safety capture and gating. Ownership of restored files is reset to the target site user, and a files-only restore is offered only from a full recovery point, with a warning.
