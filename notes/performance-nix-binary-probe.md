# Nix binary probe performance

Issue: [#557](https://github.com/rajandangi/barectl/issues/557).
Baseline: `09e0c10623404394ffca23616bf08e1252ec9114`.

## Scope

This change combines only the presence check for
`/nix/var/nix/profiles/default/bin/nix` and its ancestor walk into one SSH read.
When `/nix` is absent, that instance previously made 14 reads. The shared path
helpers, other Nix paths, panel checks, executability checks and version/configuration
validation retain their existing behavior.

The fixed command uses the original `test -e` check and the same ancestor
`test -x`, then `test -e`, order. Its reply distinguishes present, missing and
unreadable. Failed, truncated or malformed replies remain unknown. It uses the
existing SSH boundary and limits, with the connection user's permissions.

## Before and after

The controlled comparison booted the existing L0 disposable image and used the real
SSH adapter. Three samples alternated baseline and candidate for each network
condition. Only `_nix_shape` was replaced by its baseline function in the baseline
arm; the other collector code was identical. Added delay used `tc netem` inside
the disposable server. The lane and temporary credentials were removed afterward.

| Workload | Before median | After median |
| --- | --- | --- |
| Missing binary, local forwarded SSH | 0.0511 s | 0.0187 s |
| Missing binary, 25 ms added server egress delay | 0.9690 s | 0.0840 s |
| Missing binary remote reads | 14 | 1 |
| Full software stage, local forwarded SSH | 0.3415 s | 0.3023 s |
| Full software stage, 25 ms added server egress delay | 7.5030 s | 6.6022 s |
| Software-stage remote reads | 108 | 95 |

The delayed binary probe improved by 91%; the delayed software stage improved by
12%. These are disposable-server measurements, not a new timing of the registered
remote server. An already visible binary still needs one read.

Every sample compared standing, reasons, warnings, foundation states and runtime
profiles. They matched. Volatile capacity evidence was not compared. The profile
does not include worker progress database updates.

## Regression and reuse

The regression exercises the actual Nix-shape caller. It failed with `22 != 9`
before the change: the binary probe accounted for 14 calls and the other probes for
eight. Those other probes still account for eight calls afterward.

The filesystem contract executes the fixed command against real temporary paths
and compares it with the fake and the previous helper. Cases cover an absent tree,
a present binary, a dead symlink, unreadable and unsearchable ancestors, and a file
blocking the path. Parser tests assert unknown for failed, truncated, unreadable,
empty, invalid and extra-token replies.

The reuse review is recorded in #557. pyinfra's
[files.File fact](https://docs.pyinfra.com/en/3.x/facts/files.html#files-file)
does not specify this missing-versus-hidden classification. The change keeps the
existing connector and shell tests rather than introducing another discovery API.

Independent preliminary Standards and Spec reviews had no findings. Focused tests
passed, including the new filesystem contract, with the existing GNU-only contract
skip on macOS. The native L0 and passwordless-sudo discovery scenarios both passed.

## Validation

- All 32 transcript states were re-recorded from real servers; the manifest check passed.
- Controller suite: 2,793 tests passed in 29.370 seconds with one existing skip.
- Browser suite: 110 tests passed in 117.224 seconds.
- Native lifecycle: all 93 scenarios passed in 247 seconds, below the 300-second target.
- Native validators: all six groups passed in 33 seconds.
- Python lint, formatting, strict typing, dead-code checks, templates, frontend checks
  and production build, dependency audits, Django checks and migration checks passed.
