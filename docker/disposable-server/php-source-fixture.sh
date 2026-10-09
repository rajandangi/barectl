#!/bin/sh
# Build the disposable server's approved PHP source fixture
# (docs/ssh-connections.md#php-source-fixture). It writes to $1:
#
#   www/php/          the repository, served as https://packages.sury.org/php/
#   www/php/apt.gpg   the fixture's public key
#   trust             the fixture key's fingerprint and the SHA-256 of apt.gpg
#   ca.crt            a CA limited to packages.sury.org, for the server's trust store
#   server.crt, server.key  the fixture's TLS certificate and key
#
# Build arguments name the approved key and the allowed packages (bootstrap/php_supply.py).
set -eu
out=$1
. /etc/os-release
codename=$VERSION_CODENAME
architecture=$(dpkg --print-architecture)
work=$(mktemp -d)
chmod 755 "$work"
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"

/usr/lib/apt/apt-helper download-file https://packages.sury.org/php/apt.gpg \
    "$work/publisher.gpg" "SHA256:$PHP_SOURCE_DIGEST"
chmod 644 "$work/publisher.gpg"
mkdir -p "$work/sources" "$work/pool"
printf '%s\n' 'Types: deb' 'URIs: https://packages.sury.org/php/' "Suites: $codename" \
    'Components: main' "Architectures: $architecture" \
    "Signed-By: $work/publisher.gpg $PHP_SOURCE_FINGERPRINT" >"$work/sources/php.sources"
rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial
set -- -o Dir::Etc::SourceList=/dev/null -o "Dir::Etc::SourceParts=$work/sources"
apt-get "$@" --error-on=any -qq update
names=""
for name in $PHP_SOURCE_PACKAGES; do
    if apt-cache "$@" show "$name" >/dev/null 2>&1; then
        names="$names $name"
    fi
done
chown _apt "$work/pool"
# shellcheck disable=SC2086 # one argument per package name
(cd "$work/pool" && apt-get "$@" -qq download $names)

repository="$out/www/php"
mkdir -p "$repository/pool/main" "$repository/dists/$codename/main/binary-$architecture"
# Debian pool names omit the epoch that apt-get download writes URL-encoded.
for deb in "$work/pool"/*.deb; do
    mv "$deb" "$repository/pool/main/$(basename "$deb" | sed 's/_[0-9]*%3a/_/')"
done
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Disposable PHP source fixture' ed25519 sign never
gpg --batch --export >"$repository/apt.gpg"
fingerprint=$(gpg --batch --with-colons --show-keys "$repository/apt.gpg" |
    awk -F: '$1 == "fpr" {print $10; exit}')
(
    cd "$repository"
    index="dists/$codename/main/binary-$architecture/Packages"
    apt-ftparchive packages pool >"$index"
    gzip -9 -k "$index"
    apt-ftparchive -o APT::FTPArchive::Release::Origin=deb.sury.org \
        -o "APT::FTPArchive::Release::Suite=$codename" \
        -o "APT::FTPArchive::Release::Codename=$codename" \
        -o APT::FTPArchive::Release::Components=main \
        -o "APT::FTPArchive::Release::Architectures=$architecture" \
        release "dists/$codename" >"$work/Release"
    mv "$work/Release" "dists/$codename/Release"
    gpg --batch --yes --clearsign -o "dists/$codename/InRelease" "dists/$codename/Release"
)
printf '%s %s\n' "$fingerprint" "$(sha256sum "$repository/apt.gpg" | cut -d' ' -f1)" \
    >"$out/trust"

cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj '/CN=Disposable PHP source fixture CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign' \
    -addext 'nameConstraints=critical,permitted;DNS:packages.sury.org' \
    -keyout ca.key -out "$out/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=packages.sury.org' \
    -keyout "$out/server.key" -out server.csr 2>/dev/null
printf '%s\n' 'basicConstraints=CA:FALSE' 'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:packages.sury.org' >server.ext
openssl x509 -req -in server.csr -CA "$out/ca.crt" -CAkey ca.key -CAcreateserial -days 3650 \
    -extfile server.ext -out "$out/server.crt" 2>/dev/null
cd /
rm -rf "$work"
