# Picomatch advisory applicability review

Checked on 2026-11-18 for [#569](https://github.com/rajandangi/barectl/issues/569)
against release-preparation revision `236758f2`. The owner approved a scoped audit
exception for [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
for the v1.2.0 release preparation.

The advisory is valid and the affected installed library behavior was reproduced in a
bounded local check. All five locked picomatch copies are in the advisory's affected
range: four at 4.0.7 and one at 2.3.2. The advisory listed no patched release at the
time of review. This decision does not dispute the upstream finding.

Barectl's reviewed npm commands and tool configurations use repository-controlled
patterns. Production Python does not run this npm toolchain with operator or HTTP
input. The browser entry imports and built dependency-license output contain no
identified picomatch import. Managed-site Node runtimes are separate installations.
The review found no application path that supplies an attacker-controlled pattern to
these dependencies. It did not instrument every Vite Plus, watcher or Vitest call in
every development mode. A contributor who can change executable tool configuration
crosses the developer and CI trust boundary.

`npm run audit:dependencies` now allowlists this exact advisory ID alongside the
existing [braces exception](braces-advisory-review.md#required-audit-policy). It
continues to print the full raw audit report, include development dependencies and
fail on other findings at low severity or higher and on registry errors. Python's
strict dependency audit is unchanged. This is an applicability decision for the
reviewed checkout, not a patched dependency or proof of passing hosted CI.

Reassess the exception if tool globs, configuration, the dependency tree,
development-server input handling or shipped imports change. Remove this ID when an
upstream fix is available. The [release qualification](v1.2.0-qualification.md)
records the separate verification and publication gates.
