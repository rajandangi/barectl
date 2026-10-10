"""Fixed native reads and upstream installation (docs/node-runtimes-native-design.md)."""

import base64
import hashlib
import re
import shlex

from bootstrap import native as execution
from sites import native as files
from sites.names import valid_identifier

from . import alternatives, catalog, npm_tree

SAFE = (
    'safe() { [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ] && '
    '[ "$((0$(stat -c %a "$1") & 022))" = 0 ]; }; '
    "for p in / /usr /usr/local /usr/local/lib /usr/local/share /etc /var; "
    'do safe "$p" || exit 31; done; '
    f"for p in /usr/local/lib/mise {catalog.DATA} {catalog.DATA}/installs "
    f"{catalog.DATA}/installs/http-node /etc/mise {catalog.CONFIG} {catalog.MISE}; do "
    '[ ! -e "$p" ] && [ ! -L "$p" ] && continue; safe "$p" || exit 31; done'
)


def _installed(version: str) -> str:
    root = f"{catalog.DATA}/installs/http-node/{version}"
    binary = catalog.executable(version)
    hashes = "|".join(f"{a}:{catalog.BINARY_SHA256[version, a]}" for a in catalog.MISE_SHA256)
    return (
        f"if [ -e {root} ]; then safe {root} && safe {root}/bin && safe {binary} "
        "|| exit 31; "
        f'h=$(sha256sum {binary} | cut -d" " -f1); '
        f'case "$architecture:$h" in {hashes}) :;; *) exit 31;; esac; '
        f'[ -x {binary} ] || exit 31; echo "installed {version}"; fi;'
    )


def _mise_state() -> str:
    hashes = "|".join(f"{a}:{h}" for a, h in catalog.MISE_SHA256.items())
    return (
        f'if [ -e {catalog.MISE} ]; then h=$(sha256sum {catalog.MISE} | cut -d" " -f1); '
        f'case "$architecture:$h" in {hashes}) :;; *) exit 31;; esac; fi'
    )


def inventory_text() -> str:
    cases = " ".join(
        hashlib.sha256(catalog.configuration(v, a).encode()).hexdigest()
        + f') [ "$architecture" = {a} ] || exit 31; '
        + f'selected={catalog.executable(v)}; echo "default {v}";;'
        for v in catalog.VERSIONS
        for a in catalog.MISE_SHA256
    )
    return (
        SAFE + "; selected=; architecture=$(dpkg --print-architecture); " + _mise_state() + "; "
        f"if [ -e {catalog.CONFIG} ]; then [ -f {catalog.CONFIG} ] && "
        f"[ \"$(stat -c '%u:%g:%a:%h' {catalog.CONFIG})\" = 0:0:644:1 ] || exit 31; "
        f"c=$(sha256sum {catalog.CONFIG} | cut -d' ' -f1); "
        f'case "$c" in {cases} *) exit 31;; esac; fi; '
        + " ".join(_installed(v) for v in catalog.VERSIONS)
        + npm_tree.command(verify=True)
        + ";"
        + alternatives.inspect_command()
        + ";"
        + ' for p in /var/www/*/.node-version; do [ -e "$p" ] || [ -L "$p" ] || continue; '
        'safe "$p" && [ -f "$p" ] && [ "$(stat -c %h "$p")" = 1 ] || exit 31; '
        "r=${p%/.node-version}; i=${r##*/}; "
        'safe /var/www && safe "$r" && [ -d "$r" ] && '
        '[ "$(stat -c %u:%g:%a "$r")" = 0:0:755 ] && '
        '[ "$(stat -c %u:%g:%a "$p")" = 0:0:644 ] || exit 31; '
        'getent passwd "s$i" | awk -F: -v r="$r" '
        "'$6==r && $7==\"/usr/sbin/nologin\"{f=1} END{exit !f}' || exit 31; "
        'v=$(cat "$p"); printf "site %s %s\\n" "$i" "$v"; done'
    )


def inventory() -> list[str]:
    return files.script(inventory_text())


def digest_text(identifier: str = "") -> str:
    if identifier and not valid_identifier(identifier):
        raise ValueError("Invalid site identifier.")
    paths = [
        catalog.CONFIG,
        catalog.MISE,
        catalog.DATA,
        "/etc/passwd",
        "/etc/group",
        alternatives.LINK,
        alternatives.INDIRECT,
        alternatives.STATE,
        "/usr/local/bin/npm",
        "/usr/local/bin/npx",
        "/etc/alternatives/npm",
        "/etc/alternatives/npx",
        *(catalog.executable(v) for v in catalog.VERSIONS),
    ]
    if identifier:
        paths.extend((f"/var/www/{identifier}", f"/var/www/{identifier}/.node-version"))
    return (
        "{ "
        f"for p in {shlex.join(paths)} /var/www/*/.node-version; do "
        'if [ -e "$p" ] || [ -L "$p" ]; then '
        'stat -c "%n|%F|%u|%g|%a|%h" "$p"; '
        'if [ -L "$p" ]; then readlink "$p"; '
        'elif [ -f "$p" ]; then sha256sum "$p"; fi; '
        'else echo "absent $p"; fi; done; ' + npm_tree.command(verify=False) + "; } | sha256sum"
    )


def site_check(identifier: str) -> str:
    if not valid_identifier(identifier):
        raise ValueError("Invalid site identifier.")
    root = f"/var/www/{identifier}"
    return (
        f"safe /var/www && safe {root} && [ -d {root} ] || exit 31; "
        f"[ \"$(stat -c '%u:%g:%a' {root})\" = 0:0:755 ] || exit 31; "
        f'getent passwd s{identifier} | awk -F: \'$6=="{root}" && $7=="/usr/sbin/nologin" '
        "{found=1} END{exit !found}' || exit 31"
    )


def _curl(url: str, path: str) -> str:
    return (
        "curl --fail --location --silent --show-error --proto =https --proto-redir =https "
        f'--connect-timeout 10 --max-time 300 --max-filesize 268435456 -o "{path}" '
        + shlex.quote(url)
        + " || exit 32"
    )


def _checksum(path: str, digest: str, *, code: int = 33) -> str:
    return f'[ "$(sha256sum "{path}" | cut -d" " -f1)" = {digest} ] || exit {code}'


def _signature_status() -> str:
    return (
        '! grep -qE " (KEYREVOKED|KEYEXPIRED|SIGEXPIRED|EXPKEYSIG|EXPSIG|'
        'REVKEYSIG|BADSIG|ERRSIG)( |$)" "$k/status" || exit 33'
    )


def _signed_line(line: str, name: str) -> str:
    return f'[ "$(grep -Fxc {shlex.quote(line)} "$k/{name}.sums")" = 1 ] || exit 33'


def payload(
    unit: str,
    boot: str,
    deadline: int,
    *,
    version: str,
    architecture: str,
    identifier: str,
    digest: str,
) -> str:
    filename = catalog.archive(version, architecture)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid digest.")
    pin = f"/var/www/{identifier}/.node-version" if identifier else catalog.CONFIG
    content = f"{version}\n" if identifier else catalog.configuration(version, architecture)
    encoded = base64.b64encode(content.encode()).decode()
    arch = "x64" if architecture == "amd64" else "arm64"
    mise_asset = f"mise-v{catalog.MISE_VERSION}-linux-{arch}"
    mise_base = f"https://github.com/jdx/mise/releases/download/v{catalog.MISE_VERSION}"
    node_base = f"https://nodejs.org/dist/v{version}"
    request = (
        f"http:node[url={node_base}/{filename},"
        f"checksum=sha256:{catalog.SHA256[version, architecture]},"
        f"strip_components=1,bin_path=bin]@{version}"
    )
    steps = [
        "export LC_ALL=C PATH=/usr/sbin:/usr/bin; umask 022",
        SAFE,
        *execution.digest_preconditions(((digest_text(identifier), digest),)),
        "{ " + inventory_text() + "; } >/dev/null",
        *([site_check(identifier)] if identifier else []),
        "[ -x /usr/bin/curl ] && [ -x /usr/bin/gpg ] && [ -x /usr/bin/gpgv ] || exit 31",
        "k=$(mktemp -d /run/node-runtime.XXXXXXXX) || exit 31",
        'trap \'rm -rf -- "$k"\' EXIT; chmod 0700 "$k"; mkdir -m 0700 "$k/gpg"',
        _curl(catalog.KEYRING_URL, "$k/node.kbx"),
        _checksum("$k/node.kbx", catalog.KEYRING_SHA256),
        _curl(f"{node_base}/{catalog.SIGNATURE_NAME}", "$k/node.asc"),
        (
            'gpgv --homedir "$k/gpg" --keyring "$k/node.kbx" --status-fd 3 '
            '--output "$k/node.sums" "$k/node.asc" 3>"$k/status" || exit 33'
        ),
        _signature_status(),
        _signed_line(catalog.SHA256[version, architecture] + "  " + filename, "node"),
        f"if [ ! -e {catalog.MISE} ]; then",
        _curl(catalog.MISE_KEY_URL, "$k/mise.key"),
        _checksum("$k/mise.key", catalog.MISE_KEY_SHA256),
        (
            'gpg --no-options --batch --homedir "$k/gpg" --import "$k/mise.key" '
            ">/dev/null 2>&1 || exit 33"
        ),
        (
            '[ "$(gpg --no-options --batch --homedir "$k/gpg" --with-colons --list-keys '
            '| awk -F: \'$1=="fpr"{print $10; exit}\')" = '
            f"{catalog.MISE_FINGERPRINT} ] || exit 33"
        ),
        _curl(f"{mise_base}/SHASUMS256.asc", "$k/mise.asc"),
        (
            'gpg --no-options --batch --homedir "$k/gpg" --status-fd 3 '
            '--output "$k/mise.sums" --decrypt "$k/mise.asc" '
            '3>"$k/status" 2>/dev/null || exit 33'
        ),
        _signature_status(),
        _signed_line(catalog.MISE_SHA256[architecture] + "  ./" + mise_asset, "mise"),
        _curl(f"{mise_base}/{mise_asset}", "$k/mise"),
        _checksum("$k/mise", catalog.MISE_SHA256[architecture]),
        "install -d -o root -g root -m 0755 /usr/local/lib/mise || exit 34",
        f'install -o root -g root -m 0755 "$k/mise" {catalog.MISE} || exit 34',
        "fi",
        _checksum(catalog.MISE, catalog.MISE_SHA256[architecture]),
        f"install -d -o root -g root -m 0755 {catalog.DATA} || exit 34",
        'cd "$k" || exit 31',
        (
            f'env -i HOME="$k" PATH=/usr/sbin:/usr/bin LC_ALL=C MISE_DATA_DIR={catalog.DATA} '
            f'MISE_SYSTEM_DATA_DIR={catalog.DATA} MISE_CACHE_DIR="$k/cache" '
            f'MISE_STATE_DIR="$k/state" {catalog.MISE} --no-config --no-env --no-hooks '
            f"install --system {shlex.quote(request)} || exit 34"
        ),
        _checksum(
            catalog.executable(version), catalog.BINARY_SHA256[version, architecture], code=34
        ),
        (
            f"safe {catalog.executable(version)} && "
            f'[ "$({catalog.executable(version)} --version)" = v{version} ] || exit 24'
        ),
        npm_tree.command(verify=True),
        *(["install -d -o root -g root -m 0755 /etc/mise"] if not identifier else []),
        f'printf %s {shlex.quote(encoded)} | base64 -d >"$k/pin" || exit 34',
        f'install -o root -g root -m 0644 "$k/pin" {shlex.quote(pin)} || exit 34',
        *([alternatives.select(version)] if not identifier else []),
        f'echo "native-node: selected {version} for {identifier or "server default"}"',
    ]
    body = "; ".join(steps).replace("then;", "then ")
    return "; ".join((*execution.admission(unit, boot, deadline), *execution.staged(body)))
