#!/bin/sh
# Build the signed third-party repository of the disposable Ubuntu 26.04 server, which
# stands for a hosting provider's own APT source (docs/ssh-connections.md). Runs in a build
# stage with a throwaway key that never reaches the server image. It writes to $1:
#
#   provider.gpg  the public key, for the server's Signed-By
#   clean/        a repository offering only provider-agent
#   offering/     the same repository also offering an nginx-common stand-in
#
# Like the provider's, its Release file names a Suite and a Codename but no Origin or Label.
set -eu
out=$1
suite=resolute
export GNUPGHOME="$(mktemp -d)"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Disposable provider repository' ed25519 sign never
mkdir -p "$out"
gpg --batch --export >"$out/provider.gpg"

build() {
    root=$(mktemp -d)
    mkdir -p "$root/DEBIAN"
    printf '%s\n' "Package: $1" "Version: $2" "Architecture: all" \
        "Maintainer: Disposable provider <provider@example.invalid>" \
        "Description: Stand-in for a hosting provider's package" >"$root/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$root" "$3/$1_$2_all.deb" >/dev/null
}

publish() {
    repository=$1
    shift
    mkdir -p "$repository/pool"
    for package in "$@"; do
        build "${package%=*}" "${package#*=}" "$repository/pool"
    done
    (
        cd "$repository"
        for architecture in amd64 arm64; do
            mkdir -p "dists/$suite/main/binary-$architecture"
            apt-ftparchive packages pool >"dists/$suite/main/binary-$architecture/Packages"
        done
        apt-ftparchive -o "APT::FTPArchive::Release::Suite=$suite" \
            -o "APT::FTPArchive::Release::Codename=$suite" \
            -o APT::FTPArchive::Release::Components=main \
            -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
            release "dists/$suite" >Release
        mv Release "dists/$suite/Release"
        gpg --batch --yes --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
    )
}

publish "$out/clean" provider-agent=1.0
publish "$out/offering" provider-agent=1.0 nginx-common=0.1-provider
