#!/bin/sh
# docs/quality.md#runtime-catalog-lock: the Nix release and digest the catalog lock pins.
set -eu
lock=runtimes/catalog_lock.json
architecture="$(uname -m)-linux"
url="$(jq -er --arg a "$architecture" '.nix.installers[$a].url' "$lock")"
sha256="$(jq -er --arg a "$architecture" '.nix.installers[$a].sha256' "$lock")"
work="$(mktemp -d)"
curl -fsSL --retry 3 "$url" -o "$work/nix.tar.xz"
echo "$sha256  $work/nix.tar.xz" | sha256sum -c -
tar -xJf "$work/nix.tar.xz" -C "$work"
"$work"/nix-*/install --no-daemon --yes --no-channel-add
echo "$HOME/.nix-profile/bin" >> "$GITHUB_PATH"
