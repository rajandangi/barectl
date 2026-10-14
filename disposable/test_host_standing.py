"""Native host-standing scenarios recorded from real Ubuntu server evidence."""

from django.test import tag

from bootstrap.standing import HostJudgment, Standing
from discovery.observations import collect

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


class ForeignHostScenario(ScenarioTestCase):
    layer = "L0-standing"
    exclusive = True
    prefix = "standing"

    def inspect_host(self, state: str, keep: str) -> HostJudgment:
        self.native(
            "systemctl stop nginx.service apache2.service php8.5-fpm.service 2>/dev/null || true"
        )
        purge = {
            "nginx": ("apache2", "php"),
            "apache": ("nginx", "php"),
            "php": ("nginx", "apache2"),
            "nginx-php": ("apache2",),
        }[keep]
        for pattern in purge:
            self.native(
                f"dpkg-query -W -f='${{Package}}\\n' '{pattern}*' 2>/dev/null "
                "| xargs -r dpkg --purge"
            )
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint(state, shell)
        standing = snapshot.standing
        if standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(standing.standing, Standing.NOT_MANAGEABLE, standing.reasons)
        return standing


@tag(SCENARIO_TAG)
class NginxStanding(ForeignHostScenario):
    records: tuple[str, ...] = ("nginx-26.04",)

    def test_nginx_is_not_manageable(self) -> None:
        standing = self.inspect_host("nginx-26.04", "nginx")
        self.assertTrue(any("Nginx packages" in reason for reason in standing.reasons))


@tag(SCENARIO_TAG)
class ApacheStanding(ForeignHostScenario):
    records: tuple[str, ...] = ("apache-26.04",)

    def test_apache_is_not_manageable(self) -> None:
        standing = self.inspect_host("apache-26.04", "apache")
        self.assertTrue(any("Apache packages" in reason for reason in standing.reasons))


@tag(SCENARIO_TAG)
class AptPhpStanding(ForeignHostScenario):
    records: tuple[str, ...] = ("apt-php-26.04",)

    def test_apt_php_is_not_manageable(self) -> None:
        standing = self.inspect_host("apt-php-26.04", "php")
        self.assertTrue(any("APT PHP packages" in reason for reason in standing.reasons))


@tag(SCENARIO_TAG)
class EarlierBarectlStanding(ForeignHostScenario):
    records: tuple[str, ...] = ("earlier-barectl-26.04",)

    def test_earlier_barectl_layout_is_not_manageable(self) -> None:
        standing = self.inspect_host("earlier-barectl-26.04", "nginx-php")
        self.assertIn("Earlier Barectl layouts are not managed.", standing.reasons)


@tag(SCENARIO_TAG)
class UnsupportedUbuntuStanding(ScenarioTestCase):
    layer = "L0-24.04"
    exclusive = True
    prefix = "standing-unsupported"
    records: tuple[str, ...] = ("ubuntu-24.04",)

    def test_ubuntu_24_04_is_not_manageable(self) -> None:
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint("ubuntu-24.04", shell)
        standing = snapshot.standing
        if standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(standing.standing, Standing.NOT_MANAGEABLE)
        self.assertIn("Ubuntu 24.04 is outside supported settings.", standing.reasons)


@tag(SCENARIO_TAG)
class NixBuildUserCollision(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = "standing-build-user"
    records: tuple[str, ...] = ("nix-build-user-collision-26.04",)

    def test_nix_build_user_collision_is_not_manageable(self) -> None:
        self.native(
            "useradd --uid 30001 --no-create-home --shell /usr/sbin/nologin "
            "barectl-build-user-collision"
        )
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint("nix-build-user-collision-26.04", shell)
        standing = snapshot.standing
        if standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(standing.standing, Standing.NOT_MANAGEABLE)
        self.assertIn(
            "The Nix build-user ID range is occupied or could not be checked.", standing.reasons
        )


@tag(SCENARIO_TAG)
class PartialNixInstall(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = "standing-partial-nix"
    records: tuple[str, ...] = ("partial-nix-26.04",)

    def test_partial_nix_install_is_not_manageable(self) -> None:
        self.native("install -d /nix/store")
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint("partial-nix-26.04", shell)
        standing = snapshot.standing
        if standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(standing.standing, Standing.NOT_MANAGEABLE)
        self.assertIn(
            "Nix installation incomplete. Follow the official uninstall instructions before "
            "preparing again: https://nix.dev/manual/nix/2.35/installation/uninstall.html",
            standing.reasons,
        )


@tag(SCENARIO_TAG)
class AptDailyActive(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = "standing-apt-daily"
    records: tuple[str, ...] = ("apt-daily-active-26.04",)

    def test_active_apt_daily_is_not_manageable(self) -> None:
        self.native(
            "install -d /run/systemd/system/apt-daily.service.d && "
            "printf '[Service]\\nType=simple\\nExecStart=\\nExecStart=/bin/sleep 120\\n' "
            ">/run/systemd/system/apt-daily.service.d/override.conf && "
            "systemctl daemon-reload && "
            "(systemctl stop apt-daily.service 2>/dev/null || true) && "
            "systemctl start apt-daily.service && "
            "systemctl is-active --quiet apt-daily.service"
        )
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint("apt-daily-active-26.04", shell)
        standing = snapshot.standing
        if standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(standing.standing, Standing.NOT_MANAGEABLE)
        self.assertTrue(
            any("APT background package activity" in reason for reason in standing.reasons),
            standing.reasons,
        )
