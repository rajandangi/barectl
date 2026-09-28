"""A simulated Ubuntu 24.04 server's native evidence for plan preparation tests.

``NobleServer`` answers every preparation command on a ``discovery.fakes.FakeServer``,
with output in the exact shapes recorded from the disposable acceptance server (Ubuntu
24.04, apt 2.8.3, systemd 255). Tests change its fields, such as which profiles are
installed or which hooks are configured, and ``answer`` writes the answers. The commands
themselves come from ``bootstrap.inspection``; ``PREPARATION_READ_ONLY`` states
independently which command shapes preparation may run.
"""

import re
from dataclasses import dataclass, field
from typing import override

from discovery.fakes import READ_ONLY, DiscoveryTestCase, FakeServer
from discovery.ssh import CommandResult
from servers.models import Server

from . import inspection
from .models import ConfigurationPlan, PlanPreparation, Privilege
from .profiles import DISTRIBUTION_HOOKS

BOOT_ID = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
# Hundredths of a second: 5,000.25 seconds after boot.
UPTIME = "5000.25 19822.11\n"
UPTIME_CENTISECONDS = 500025
OS_RELEASE = (
    'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
    'VERSION="24.04.5 LTS (Noble Numbat)"\nID=ubuntu\nID_LIKE=debian\n'
)
NGINX_VERSION = "1.24.0-2ubuntu7.18"
PHP_VERSION = "8.3.6-0ubuntu0.24.04.11"
UPDATES = "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security"
SITE = "http://archive.ubuntu.com/ubuntu"
# The addresses the default Nginx site listens on, as ss reports them.
WILDCARDS = ("0.0.0.0", "[::]")  # noqa: S104 - reported addresses, not a bind

# The hook entries of the tested distribution baseline, as apt-config dump prints them.
_HOOK_KEYS = {
    "dpkg::pre-install-pkgs": "DPkg::Pre-Install-Pkgs",
    "dpkg::post-invoke": "DPkg::Post-Invoke",
    "apt::update::post-invoke-success": "APT::Update::Post-Invoke-Success",
    "apt::update::pre-invoke": "APT::Update::Pre-Invoke",
    "binary::apt::aptcli::hooks::upgrade": "binary::apt::AptCli::Hooks::Upgrade",
}
BASELINE_HOOKS = tuple((f"{_HOOK_KEYS[name]}::", value) for (name, value) in DISTRIBUTION_HOOKS)
_SETTINGS = (
    ("APT", ""),
    ("APT::Architecture", "amd64"),
    ("APT::Install-Recommends", "1"),
    ("Acquire::AllowInsecureRepositories", "0"),
    ("Acquire::AllowDowngradeToInsecureRepositories", "0"),
    ("Dir::Bin::dpkg", "/usr/bin/dpkg"),
    # A secret-looking value that must never be stored or shown.
    ("Acquire::http::Proxy", "http://proxyuser:hunter2@proxy.internal:3128"),
)

NGINX_CONFFILES = {
    "/etc/nginx/fastcgi.conf": "74e91892a9e591cde6d65c3e8e7e5fb2",
    "/etc/nginx/mime.types": "96fd3f507b3a4fe666fcb0bb0042f428",
    "/etc/nginx/nginx.conf": "e5398edc0b51497dba606859fb13a86e",
    "/etc/nginx/sites-available/default": "f1f26aef86f90a484f3a2f46ccc46ff6",
    "/etc/nginx/snippets/fastcgi-php.conf": "828e5bd1f3de7b3ef0e6856598b2a8c0",
}
PHP_CONFFILES = {
    "/etc/php/8.3/fpm/php-fpm.conf": "696fcb228ad0e29f57cdd2082eb41fac",
    "/etc/php/8.3/fpm/pool.d/www.conf": "6204554fd51b0d45f12e2f2b5b62e377",
}
PHP_UCF = {
    "/etc/php/8.3/fpm/php.ini": "75451050d77c02f5b29da8360395a9dd",
    "/etc/php/8.3/cli/php.ini": "726c33e11795235b71f7367d79eb8744",
    "/etc/php/8.3/mods-available/opcache.ini": "5454a910708937435d02de816081a39c",
    "/etc/php/8.3/mods-available/pdo.ini": "2bcf2cd02149a7b3118f9a8ed7cfe1b3",
}
# The dependencies APT adds to nginx on a server without them, in the simulation's order.
NGINX_DEPENDENCIES = (
    ("libelf1t64", "0.190-1.1ubuntu0.1", "amd64", UPDATES),
    ("libbpf1", "1:1.3.0-2build2", "amd64", "Ubuntu:24.04/noble"),
    ("iproute2", "6.1.0-1ubuntu6.4", "amd64", "Ubuntu:24.04/noble-updates"),
)
PHP_PACKAGES = (
    ("php-common", "2:93ubuntu2", "all", "Ubuntu:24.04/noble"),
    ("php8.3-common", PHP_VERSION, "amd64", UPDATES),
    ("php8.3-opcache", PHP_VERSION, "amd64", UPDATES),
    ("php8.3-readline", PHP_VERSION, "amd64", UPDATES),
    ("php8.3-cli", PHP_VERSION, "amd64", UPDATES),
    ("php8.3-fpm", PHP_VERSION, "amd64", UPDATES),
)

# The command shapes preparation may run, stated independently of the inspection module:
# fixed reads of the platform, APT, dpkg, systemd and configuration files, APT's
# simulation, and sudo only to list authorization or for the listening-socket query.
PREPARATION_READ_ONLY = re.compile(
    r"\A(cat /proc/sys/kernel/random/boot_id|cat /proc/uptime|cat /etc/os-release"
    r"|test -d /run/systemd/system|dpkg --print-architecture|id -u|apt-mark showhold"
    r"|cat /var/lib/ucf/hashfile|LC_ALL=C apt-config dump|LC_ALL=C dpkg --audit)\Z"
    r"|\Adpkg-query -W -f='[^']*' [a-z0-9+. -]+\Z"
    r"|\Aapt-mark showauto [a-z0-9+. :-]+\Z"
    r"|\ALC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
    r"install [a-z0-9+. -]+\Z"
    r"|\ALC_ALL=C apt-get indextargets --format '[^']*' 'Created-By: Packages'\Z"
    r"|\Asudo -n -l /usr/bin/(systemd-run|ss -Hltnp sport = :80)\Z"
    r"|\A(sudo -n /usr/bin/ss -Hltnp|/usr/bin/ss -Hltnp|ss -Hltn) sport = :80\Z"
    r"|\Asystemctl show [a-z0-9.-]+\.service( -p [A-Za-z]+)+\Z"
    r"|\Atest -e /etc/(nginx|php/8\.3/(fpm|cli|mods-available))\Z"
    r"|\Afind /etc/(nginx|php/8\.3/(fpm|cli|mods-available)) -xdev "
    r"(-printf '%y\\t%p\\t%l\\n'|-type f -exec md5sum -- \{\} \+)\Z"
    r"|\Afind /etc/apt -xdev -type f ! -path '/etc/apt/auth\.conf\*' -exec sha256sum -- \{\} \+\Z"
    r"|\Afind /etc/apt -maxdepth 2 -xdev -type f .* -exec grep -qiE -- '[^']*' \{\} \\; -print\Z"
    r"|\Afind /var/lib/apt/lists -maxdepth 1 -type f -name '\*_InRelease' "
    r"-exec sha256sum -- \{\} \+\Z"
)


def _unit(name: str, *, installed: bool, active: str, enabled: str, drop_ins: str) -> str:
    if not installed:
        return (
            f"Id={name}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "FragmentPath=\nDropInPaths=\nUnitFileState=\n"
        )
    return (
        f"Id={name}\nLoadState=loaded\nActiveState={active}\n"
        f"SubState={'running' if active == 'active' else 'dead'}\n"
        f"FragmentPath=/usr/lib/systemd/system/{name}\nDropInPaths={drop_ins}\n"
        f"UnitFileState={enabled}\n"
    )


@dataclass
class NobleServer:
    """An Ubuntu 24.04 server as plan preparation reads it. Change fields, then ``answer``."""

    # "installed", "absent", or "leftover" (removed with configuration files left).
    nginx: str = "absent"
    php: str = "absent"
    # "root", "sudo" or "none".
    privilege: str = "sudo"
    nginx_active: str = "active"
    nginx_enabled: str = "enabled"
    php_active: str = "active"
    php_enabled: str = "enabled"
    unit_drop_ins: str = ""
    hooks: list[tuple[str, str]] = field(default_factory=lambda: list(BASELINE_HOOKS))
    suites: tuple[str, ...] = ("noble", "noble-updates", "noble-security", "noble-backports")
    trusted: bool = True
    holds: tuple[str, ...] = ()
    audit: str = ""
    source_overrides: tuple[str, ...] = ()
    # Other processes listening on port 80, by address.
    other_listeners: tuple[str, ...] = ()
    # Extra entries under /etc/nginx or /etc/php/8.3/fpm, as (path, md5).
    extra_files: dict[str, str] = field(default_factory=dict)
    changed_conffiles: tuple[str, ...] = ()
    # Installed dependency versions the nginx simulation would upgrade, if any.
    upgrades: tuple[tuple[str, str, str], ...] = ()
    # A different archive offering the nginx packages, such as a PPA.
    nginx_origins: str = UPDATES
    simulation_text: str | None = None
    # Installed packages marked automatically installed.
    automatic: tuple[str, ...] = ("nginx-common", "php8.3-common", "php-common")
    extra: dict[str, CommandResult] = field(default_factory=dict)

    def answer(self, remote: FakeServer) -> None:
        if self._package_query not in remote.answers:
            remote.answers.append(self._package_query)
        results = remote.results
        results.update(self._platform())
        results.update(self._apt())
        results.update(self._packages())
        results.update(self._web())
        results.update(self.extra)

    def _platform(self) -> dict[str, CommandResult]:
        uid = "0\n" if self.privilege == "root" else "1000\n"
        sudo = self.privilege == "sudo"
        return {
            inspection.BOOT_ID: CommandResult(0, f"{BOOT_ID}\n"),
            inspection.UPTIME: CommandResult(0, UPTIME),
            inspection.OS_RELEASE: CommandResult(0, OS_RELEASE),
            inspection.SYSTEMD: CommandResult(0, ""),
            inspection.ARCHITECTURE: CommandResult(0, "amd64\n"),
            inspection.TOOL_VERSIONS: CommandResult(
                0, "apt\t2.8.3\ndpkg\t1.22.6ubuntu6.6\nsystemd\t255.4-1ubuntu8.17\n"
            ),
            inspection.USER_ID: CommandResult(0, uid),
            inspection.SUDO_APPLY: CommandResult(0, "/usr/bin/systemd-run\n")
            if sudo
            else CommandResult(1, ""),
            inspection.sudo_listeners(80): CommandResult(0, "/usr/bin/ss -Hltnp sport = :80\n")
            if sudo
            else CommandResult(1, ""),
        }

    def _apt(self) -> dict[str, CommandResult]:
        lines = [f'{key} "{value}";' for key, value in _SETTINGS]
        lines.extend(f'{key} "{value}";' for key, value in self.hooks)
        targets = "".join(
            f"Ubuntu|{suite}|noble|{'yes' if self.trusted else 'no'}|{component}|amd64|{SITE}\n"
            for suite in self.suites
            for component in ("main", "universe")
        )
        releases = "".join(
            f"{index:064x}  /var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_{suite}_InRelease\n"
            for index, suite in enumerate(self.suites, start=1)
        )
        files = (
            f"{'a' * 64}  /etc/apt/sources.list.d/ubuntu.sources\n"
            f"{'b' * 64}  /etc/apt/apt.conf.d/70debconf\n"
        )
        return {
            inspection.APT_CONFIG: CommandResult(0, "\n".join(lines) + "\n"),
            inspection.APT_FILES: CommandResult(0, files),
            inspection.SOURCE_OVERRIDES: CommandResult(
                0, "".join(f"{path}\n" for path in self.source_overrides)
            ),
            inspection.INDEX_TARGETS: CommandResult(0, targets),
            inspection.RELEASES: CommandResult(0, releases),
        }

    def _states(self) -> dict[str, str]:
        """Every package's state line, by name."""
        states = {"needrestart": "needrestart\tall\t3.6-7ubuntu4.5\tii "}
        if self.nginx == "installed":
            states["nginx"] = f"nginx\tamd64\t{NGINX_VERSION}\tii "
            states["nginx-common"] = f"nginx-common\tall\t{NGINX_VERSION}\tii "
        elif self.nginx == "leftover":
            states["nginx-common"] = f"nginx-common\tall\t{NGINX_VERSION}\trc "
        if self.php == "installed":
            for name, version, arch, _ in PHP_PACKAGES:
                states[name] = f"{name}\t{arch}\t{version}\tii "
        for name, previous, _ in self.upgrades:
            states[name] = f"{name}\tamd64\t{previous}\tii "
        for hold in self.holds:
            states.setdefault(hold, f"{hold}\t\t\thn ")
        return states

    def _packages(self) -> dict[str, CommandResult]:
        return {
            inspection.DPKG_AUDIT: CommandResult(0, self.audit),
            inspection.HOLDS: CommandResult(0, "".join(f"{hold}\n" for hold in self.holds)),
            inspection.simulate(["nginx"]): CommandResult(
                0, self.simulation_text or self._nginx_simulation()
            ),
            inspection.simulate(["php8.3-fpm", "php8.3-cli"]): CommandResult(
                0, self._php_simulation()
            ),
        }

    def _package_query(self, command: str) -> CommandResult | None:
        """Answer dpkg-query and apt-mark queries for whichever packages they name."""
        states = self._states()
        for prefix in (inspection.package_states([]), inspection.automatic_marks([])):
            if not command.startswith(prefix):
                continue
            names = command.removeprefix(prefix).split()
            known = [name for name in names if name in states]
            if prefix == inspection.automatic_marks([]):
                automatic = [name for name in known if name in self.automatic]
                return CommandResult(0, "".join(f"{name}\n" for name in automatic))
            # dpkg-query lists known packages sorted by name, and exits 1 for unknown ones.
            text = "".join(f"{states[name]}\n" for name in sorted(known))
            return CommandResult(0 if len(known) == len(names) else 1, text)
        return None

    def _nginx_simulation(self) -> str:
        actions = [
            (name, version, arch, origins, "")
            for name, version, arch, origins in NGINX_DEPENDENCIES
        ]
        actions.extend(
            (name, new, "amd64", "Ubuntu:24.04/noble-updates", previous)
            for name, previous, new in self.upgrades
        )
        actions.append(("nginx-common", NGINX_VERSION, "all", self.nginx_origins, ""))
        actions.append(("nginx", NGINX_VERSION, "amd64", self.nginx_origins, ""))
        return _simulation(actions)

    def _php_simulation(self) -> str:
        return _simulation([(n, v, a, o, "") for n, v, a, o in PHP_PACKAGES])

    def _web(self) -> dict[str, CommandResult]:
        results = {
            inspection.unit_state("nginx.service"): CommandResult(
                0,
                _unit(
                    "nginx.service",
                    installed=self.nginx == "installed",
                    active=self.nginx_active,
                    enabled=self.nginx_enabled,
                    drop_ins=self.unit_drop_ins,
                ),
            ),
            inspection.unit_state("php8.3-fpm.service"): CommandResult(
                0,
                _unit(
                    "php8.3-fpm.service",
                    installed=self.php == "installed",
                    active=self.php_active,
                    enabled=self.php_enabled,
                    drop_ins=self.unit_drop_ins,
                ),
            ),
            inspection.UCF_HASHES: CommandResult(
                0, "".join(f"{md5}  {path}\n" for path, md5 in PHP_UCF.items())
            ),
        }
        results.update(self._nginx_tree())
        results.update(self._php_trees())
        results.update(self._listeners())
        return results

    def _tree_results(
        self, root: str, files: dict[str, str], links: dict[str, str], present: bool
    ) -> dict[str, CommandResult]:
        if not present:
            return {inspection.exists(root): CommandResult(1, "")}
        files = {
            **files,
            **{p: m for p, m in self.extra_files.items() if p.startswith(f"{root}/")},
        }
        files = {p: ("0" * 32 if p in self.changed_conffiles else m) for p, m in files.items()}
        directories = sorted({root} | {p.rsplit("/", 1)[0] for p in (*files, *links)})
        listing = [f"d\t{path}\t" for path in directories]
        listing += [f"f\t{path}\t" for path in sorted(files)]
        listing += [f"l\t{path}\t{target}" for path, target in sorted(links.items())]
        return {
            inspection.exists(root): CommandResult(0, ""),
            inspection.tree(root): CommandResult(0, "\n".join(listing) + "\n"),
            inspection.tree_digests(root): CommandResult(
                0, "".join(f"{md5}  {path}\n" for path, md5 in sorted(files.items()))
            ),
        }

    def _nginx_tree(self) -> dict[str, CommandResult]:
        results = self._tree_results(
            "/etc/nginx",
            NGINX_CONFFILES,
            {"/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default"},
            present=self.nginx in {"installed", "leftover"},
        )
        conffiles = "".join(f" {path} {md5}\n" for path, md5 in NGINX_CONFFILES.items())
        results[inspection.conffiles(["nginx-common"])] = CommandResult(
            0, f"nginx-common\n{conffiles}"
        )
        return results

    def _php_trees(self) -> dict[str, CommandResult]:
        present = self.php == "installed"
        results: dict[str, CommandResult] = {}
        for root in ("/etc/php/8.3/fpm", "/etc/php/8.3/cli", "/etc/php/8.3/mods-available"):
            files = {
                path: md5
                for path, md5 in {**PHP_CONFFILES, **PHP_UCF}.items()
                if path.startswith(f"{root}/")
            }
            links = {}
            if root != "/etc/php/8.3/mods-available":
                links = {f"{root}/conf.d/10-opcache.ini": "/etc/php/8.3/mods-available/opcache.ini"}
            results.update(self._tree_results(root, files, links, present=present))
        conffiles = "".join(f" {path} {md5}\n" for path, md5 in PHP_CONFFILES.items())
        results[inspection.conffiles(["php8.3-cli", "php8.3-common", "php8.3-fpm"])] = (
            CommandResult(0, f"php8.3-cli\n\nphp8.3-common\n\nphp8.3-fpm\n{conffiles}")
        )
        return results

    def _listeners(self) -> dict[str, CommandResult]:
        attributed = self.privilege in {"root", "sudo"}
        lines = []
        if self.nginx == "installed" and self.nginx_active == "active":
            lines += [_listen(address, "nginx", attributed) for address in WILDCARDS]
        lines += [_listen(address, "apache2", attributed) for address in self.other_listeners]
        privilege = Privilege.ROOT if self.privilege == "root" else Privilege.SUDO
        query = inspection.listeners(80, privilege, attributed=attributed)
        return {query: CommandResult(0, "".join(f"{line}\n" for line in lines))}


def _listen(address: str, process: str, attributed: bool) -> str:
    users = f' users:(("{process}",pid=812,fd=5),("{process}",pid=811,fd=5))' if attributed else ""
    return f"LISTEN 0      511    {address}:80 0.0.0.0:*{users}"


def _simulation(actions: list[tuple[str, str, str, str, str]]) -> str:
    """APT's simulation output for ``actions``: (name, version, arch, origins, previous)."""
    installs = [a for a in actions if not a[4]]
    upgrades = [a for a in actions if a[4]]
    lines = [
        "NOTE: This is only a simulation!",
        "      apt-get needs root privileges for real execution.",
        "Reading package lists...",
        "Building dependency tree...",
        "Reading state information...",
        "The following NEW packages will be installed:",
        "  " + " ".join(a[0] for a in installs),
        (
            f"{len(upgrades)} upgraded, {len(installs)} newly installed, 0 to remove and 3 "
            "not upgraded."
        ),
    ]
    for name, version, arch, origins, previous in actions:
        before = f"[{previous}] " if previous else ""
        lines.append(f"Inst {name} {before}({version} {origins} [{arch}])")
    for name, version, arch, origins, _ in actions:
        lines.append(f"Conf {name} ({version} {origins} [{arch}])")
    return "\n".join(lines) + "\n"


PLAN_PERMISSIONS = ("view_server", "view_configurationplan", "prepare_configurationplan")


class PreparationTestCase(DiscoveryTestCase):
    """Plan preparation through requests and the worker, against a simulated Noble server."""

    noble: NobleServer
    server: Server

    @override
    def setUp(self) -> None:
        super().setUp()
        self.noble = NobleServer()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    @override
    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command) or PREPARATION_READ_ONLY.fullmatch(command),
                f"Not a read-only command: {command}",
            )

    def fresh_server(self) -> None:
        """Start again with a new simulated server and no recorded preparations."""
        self.remote.results = FakeServer().results
        self.remote.answers.clear()
        self.noble = NobleServer()
        PlanPreparation.objects.all().delete()

    def prepare(
        self, action: str = "nginx", *, perms: tuple[str, ...] = PLAN_PERMISSIONS
    ) -> PlanPreparation:
        """Request a preparation as an operator with ``perms``, run the worker, return it."""
        self.sign_in_with(*perms)
        self.noble.answer(self.remote)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": action})
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def plan(self, action: str = "nginx") -> ConfigurationPlan:
        """Prepare ``action`` and return its plan, failing the test without one."""
        preparation = self.prepare(action)
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def reasons(self, plan: ConfigurationPlan) -> list[str]:
        return [refusal.reason for refusal in plan.refusals.all()]
