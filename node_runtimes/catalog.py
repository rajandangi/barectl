"""Reviewed upstream release pins (docs/node-runtimes-native-design.md)."""

MISE_VERSION = "2026.10.6"
MISE = f"/usr/local/lib/mise/mise-{MISE_VERSION}"
MISE_KEY_URL = "https://mise.jdx.dev/gpg-key.pub"
MISE_KEY_SHA256 = "91c72340c5cc84ae2ba98c1070083feacf789b0a4a3d34b2416147769e475d96"
MISE_FINGERPRINT = "24853EC9F655CE80B48E6C3A8B81C9D17413A06D"
MISE_SHA256 = {
    "arm64": "5f3187febbe9ff98e4c78b3596c7bbfde0e3ef8e4b1820494d03efd499de7b6e",
    "amd64": "3f44343eebc7e0d6623bcea46e304864f02dff648edd75c82871b53cc697b366",
}
KEYRING_URL = (
    "https://raw.githubusercontent.com/nodejs/release-keys/"
    "481637f813e912c4aa3622d7964ab426c97b8e8d/gpg-only-active-keys/pubring.kbx"
)
KEYRING_SHA256 = "140f2ad5260fd62773b6243ce8e1d3009645d558f121b8262c55e383dc285932"
VERSIONS = ("24.21.0", "22.23.3")
DEFAULT = VERSIONS[0]
SHA256 = {
    ("24.21.0", "arm64"): "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2",
    ("24.21.0", "amd64"): "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6",
    ("22.23.3", "arm64"): "a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f",
    ("22.23.3", "amd64"): "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de",
}
DATA = "/usr/local/share/mise"
CONFIG = "/etc/mise/config.toml"


def executable(version: str) -> str:
    if version not in VERSIONS:
        raise ValueError("Select a reviewed Node LTS release.")
    return f"{DATA}/installs/http-node/{version}/bin/node"


def archive(version: str, architecture: str) -> str:
    if (version, architecture) not in SHA256:
        raise ValueError("Unsupported Node release or architecture.")
    arch = "x64" if architecture == "amd64" else "arm64"
    return f"node-v{version}-linux-{arch}.tar.xz"


def configuration(version: str, architecture: str) -> str:
    filename = archive(version, architecture)
    return (
        '[tools]\n"http:node" = { version = "' + version + '", '
        f'url = "https://nodejs.org/dist/v{version}/{filename}", '
        f'checksum = "sha256:{SHA256[version, architecture]}", '
        'strip_components = 1, bin_path = "bin" }\n'
    )


BINARY_SHA256 = {
    ("24.21.0", "arm64"): "0f8949d1028f6d61506b2d5bc57e7e6fe893d7b1997509b7847294fc9c616584",
    ("24.21.0", "amd64"): "7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c",
    ("22.23.3", "arm64"): "d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d",
    ("22.23.3", "amd64"): "fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48",
}
SIGNATURE_NAME = "SHASUMS256.txt.asc"
