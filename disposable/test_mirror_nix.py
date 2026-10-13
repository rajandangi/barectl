"""The harness's mirror self-check: a Nix client in L0 verifies the official signature.

docs/quality.md#native-layer. This proves the local mirror serves the Nix cache under its
real host name with the upstream signature intact: Nix installs from the mirrored tarball,
realises a catalog path with ``max-jobs = 0`` (nothing can be built) and reads the
signature back, which must name the cache's own key. The ``nix.conf`` settings are ADR
0028's; the host foundation ticket owns the product's copy.
"""

from django.test import tag

from . import mirror
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

# docs/adr/0028-supply-runtimes-and-tools-from-pinned-nix.md
NIX_CONF = """allowed-users = root
trusted-users = root
substituters = https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
max-jobs = 0
fallback = false
"""
# The key every path in the Nix cache is signed with; a Nix client checks it against this.
CACHE_KEY = "cache.nixos.org-1"
# Where the multi-user installer puts the profile; a non-login shell does not source it.
NIX = "/nix/var/nix/profiles/default/bin"


@tag(SCENARIO_TAG)
class MirrorNixSignature(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = "sn"

    def test_the_l0_nix_client_verifies_the_official_signature(self) -> None:
        architecture = mirror.lock_architecture(self.native("uname -m").strip())
        url, digest = mirror.catalog_installer(architecture)
        path = self._caddy(architecture)
        self.native(
            f"""
set -eu
python3 - <<'PY'
import urllib.request
open('/tmp/nix.tar.xz', 'wb').write(urllib.request.urlopen("{url}").read())
PY
echo {digest}  /tmp/nix.tar.xz | sha256sum -c -
tar -xJf /tmp/nix.tar.xz -C /tmp
sh /tmp/nix-*/install --daemon --yes --no-channel-add
cat >>/etc/nix/nix.conf <<'CONF'
{NIX_CONF}CONF
systemctl restart nix-daemon
""",
            timeout=600,
        )
        self.assertIn(CACHE_KEY, self.native("cat /etc/nix/nix.conf"))
        # max-jobs = 0 means nothing can be built, so a realised path came from the mirror.
        realise = self.native(f"{NIX}/nix-store --realise {path} 2>&1; echo exit=$?", timeout=300)
        self.assertIn("exit=0", realise, realise)
        signatures = self.native(
            f"{NIX}/nix --extra-experimental-features nix-command path-info "
            f"--store https://cache.nixos.org --json {path}",
            timeout=120,
        )
        self.assertIn(CACHE_KEY, signatures, signatures)

    def _caddy(self, architecture: str) -> str:
        caddy = next(
            (path for path in mirror.catalog_store_paths(architecture) if "-caddy-" in path),
            None,
        )
        if caddy is None:
            raise AssertionError(f"the catalog lock lists no Caddy for {architecture}")
        return caddy
