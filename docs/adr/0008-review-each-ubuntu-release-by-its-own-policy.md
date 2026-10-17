# Review each Ubuntu release by its own policy

> Amended at the Phase A exit ([#341](https://github.com/rajandangi/barectl/issues/341)): Barectl supports a single release, Ubuntu 26.04 LTS, and the per-release package profiles and their release records were deleted with the old stack. PHP supply and the default PHP version moved to [ADR 0028](0028-supply-runtimes-and-tools-from-pinned-nix.md).

Barectl supports one Ubuntu LTS release at a time: Ubuntu 26.04 (resolute), on amd64 and arm64, with the release's own apt 3.2, dpkg 1.23 and systemd 259. Host standing reads `/etc/os-release` and the tool versions first; any other distribution, release or series makes the server Not manageable, naming what was found ([ADR 0026](0026-manage-fresh-hosts-on-one-target-stack.md)). A second release would double every convention, native scenario and qualification for no current need.

A later LTS is added by its own reviewed release policy: the release's identity, the tool series its native execution is qualified with, and the native scenarios and qualification on both architectures. Barectl never judges a server by another release's rules, and a server upgraded to another release after a review changes the evidence the change rechecks under the lock, so the change refuses.
