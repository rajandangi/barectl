# Braces advisory applicability review

Checked on 2026-10-07 for [#221](https://github.com/rajandangi/barectl/issues/221), against the current locked checkout at `9993cbd`. This review separates a reproducible library failure, Barectl's exposure and the project's delivery policy.

## Verdict

The dependency finding remains valid, and the library's stack overflow is reproducible. The current Barectl lint command does not reach brace expansion, and no production input path to this dependency was identified. Treat it as a development-tool advisory with demonstrated non-applicability to the reviewed command, rather than a demonstrated remote denial of service in Barectl. This does not establish that the upstream advisory is intrinsically false.

The owner [closed #221 as non-applicable](https://github.com/rajandangi/barectl/issues/221#issuecomment-6034560394), superseding the earlier wait-for-release decision. The required audit now applies that assessment through the scoped policy below. The raw npm finding remains visible; this does not exempt development dependencies as a class.

## Current upstream evidence

- The [maintainer's response](https://github.com/micromatch/braces/issues/70#issuecomment-5995348316) disputes the security classification and argues that callers should restrict untrusted patterns and use the existing `maxLength` option. The response is not an advisory withdrawal.
- [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), CVE-2026-93687, remains GitHub-reviewed and high severity, with `withdrawn_at: null`, affected versions through 3.0.3 and no patched version. The [GitHub advisory API](https://api.github.com/advisories/GHSA-vfj7-8cjw-p6xm) records its latest update as 2026-10-02.
- The [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-93687) still has state `PUBLISHED`, rather than `REJECTED`.
- `npm view braces version` still returns 3.0.3. [PR #77](https://github.com/micromatch/braces/pull/77), proposing an opt-in nesting limit, was closed by its author on 2026-10-06 without merging. Its earlier open status in #221 is outdated.
- The relevant package is `braces`, not the separate `brace-expansion` package and its separately patched advisories.

## Local reproduction

On Node 24.21.0 with installed `braces@3.0.3`, a pattern containing 4,998 opening braces, `a,b` and 4,998 closing braces is 9,999 characters long. The default compile API throws `RangeError: Maximum call stack size exceeded`, and an uncaught invocation exits 1. The input is below the actual 10,000-character default in the [installed release's parser](https://github.com/micromatch/braces/blob/3.0.3/lib/parse.js) and [constants](https://github.com/micromatch/braces/blob/3.0.3/lib/constants.js). A separate expand call with 4,999 nested literal braces also overflows below that limit.

Each probe ran in a separate local process with a ten-second timeout and a 128 MiB heap bound. It did not submit input to a server or change dependencies. The heap bound does not change the native stack size. Thresholds depend on the engine and call context; this is a reproduction on the project's Node major, not a universal minimum depth.

```javascript
const braces = require('braces');
const depth = 4998;
const pattern = '{'.repeat(depth) + 'a,b' + '}'.repeat(depth);
braces(pattern);
```

Setting `maxLength: 1000` rejects the long probe with a length-related `SyntaxError` before recursive compilation. A smaller caller-supplied length cap mitigates this input. The default 10,000-character cap did not prevent the observed overflow. Whether that behavior deserves a network-severity rating depends on an application's actual input boundary.

## Barectl reachability

The installed dependency chain is `stylelint@17.15.0` to `micromatch@4.0.8` to `braces@3.0.3`, with additional development paths through `fast-glob@3.3.3` and `globby@16.2.4`. Barectl's [lint script](../package.json) passes the fixed pattern `frontend/**/*.scss`.

A read-only instrumented Stylelint run used the actual repository configuration and linted all five current SCSS files. The only patterns observed at micromatch's brace-handling boundary were `frontend/**/*.scss` and `**/node_modules/**`. Neither contains braces; micromatch's no-braces fast path returned before entering `braces.create` or expansion. There were zero expansion calls. See [micromatch 4.0.8](https://github.com/micromatch/micromatch/blob/4.0.8/index.js) and [fast-glob's pattern adapter](https://github.com/mrmlnc/fast-glob/blob/3.3.3/src/utils/pattern.ts).

A temporary fixture containing twenty `{a,b}` groups in a stylesheet filename was linted as one literal file, with the same fixed patterns and zero expansion calls. Filenames are match candidates here, not patterns to expand. The reviewed configuration and presets add no dynamic reference-file, override or glob-option patterns. `.stylelintignore` uses the separate `ignore` package; globby's gitignore options are not enabled by this command.

Production frontend entries import HTMX, USWDS and styles; the built JavaScript and dependency-license output contain no Stylelint or this globbing dependency chain. Django does not invoke Stylelint with operator or network input. A caller changing the CLI glob or checkout configuration could reach brace expansion, but that changes the developer/CI execution boundary. A malicious checkout can already change npm scripts and executable configuration. This review does not classify all CI or dependency risks as harmless.

## Audit result and follow-up

`npm audit --json` exits 1 with ten high affected package records from this one advisory, not ten independent vulnerabilities. The record for `braces` has `fixAvailable: false`. npm computes dependent-package findings from dependency versions; it does not prove application reachability. See [npm's advisory and meta-vulnerability behavior](https://docs.npmjs.com/cli/v11/commands/npm-audit/).

A diagnostic `npm audit --omit=dev --json` exits 0. That is not an alternative required gate: Barectl declares its browser assets and tooling as development dependencies, so omitting that whole tree alone cannot prove shipped asset safety. The import and lint-call checks above establish this advisory's narrower exposure assessment. The raw full audit remains failing.

### Required audit policy

`npm run audit:dependencies` uses exactly pinned `audit-ci@7.1.0` and [audit-ci.json](../audit-ci.json). It audits the complete npm tree, prints the full npm report and fails on low or higher findings outside six exact scanner-reported paths for this advisory. No package name, whole advisory or wildcard is allowlisted. The trailing separators in some records are part of audit-ci's current npm meta-vulnerability path output; retain exact matching rather than broadening them.

Every record expires at `2026-11-07T00:00:00Z`. Reassess before renewing; remove the records when an upstream fix resolves the finding. A new reported path, a different advisory or expiry restores failure. Registry errors remain failures, and Python's strict audit is unchanged. Passing this policy means no unaccepted findings, not zero raw scanner findings.

The [maintainer's version-matched guidance](https://github.com/IBM/audit-ci/blob/v7.1.0/README.md#allowlisting) supports path records with expiry and describes paths as its most granular choice. The published package supports Node 16 and newer, including Barectl's Node 24. Barectl keeps this tool in its exact-pinned lockfile so local and CI commands use the same reviewed version. Upstream recommends running it before dependency installation to reduce install-script exposure; the existing locked `npm ci` workflow still installs before the audit and does not claim to prevent malicious install scripts. This is an applicability policy, not an upstream dependency patch. No custom audit parser, package fork or remote execution mechanism is added.

Reassess applicability when the dependency chain, lint globs, configuration, public input boundary or shipped imports change, even if the scanner's reported path remains the same. Reviewers must check those boundaries against the evidence above. A successful local policy run does not establish a passing hosted CI run or qualify any PHP source combination.

On 2026-10-07, the live required npm command passed while printing the ten raw high package findings. Eight CLI fixture controls also passed: the reviewed report was accepted; expired records, an omitted accepted path, a new consumer path for the same advisory, a new low advisory, mixed advisories, non-JSON output and a registry `ENOAUDIT` error all exited 1 as expected. These controls exercised the pinned upstream CLI with captured npm output, without changing the installed application packages or replacing the real registry during the live check.
