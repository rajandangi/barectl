#!/bin/sh
# docs/quality.md#runtime-catalog-lock: the Nix release the lock pins, with a digest taken
# from the base branch's lock or, for a new release, from the release's published file.
set -eu
architecture="$(uname -m)-linux"
set -- $(uv run --no-project python -m runtimes.lock_generation installer "$architecture")
url="$1"
sha256="$2"
work="$(mktemp -d)"
curl -fsSL --retry 3 "$url" -o "$work/nix.tar.xz"
echo "$sha256  $work/nix.tar.xz" | sha256sum -c -
tar -xJf "$work/nix.tar.xz" -C "$work"
"$work"/nix-*/install --no-daemon --yes --no-channel-add
echo "$HOME/.nix-profile/bin" >> "$GITHUB_PATH"
