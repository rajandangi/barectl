"""The bounded automation read includes root's crontab, not only site accounts' (#357).

A duplicate scheduler may be installed by root. The native read is one fixed program, so
this drives its crontab collector with a described filesystem instead of reading a host.
"""

import pathlib
from types import ModuleType
from unittest import mock

from django.test import SimpleTestCase

from automation.bodies import observe, observe_workers

SHOP = "shop"
ROOT_SCHEDULE = "* * * * * /var/www/shop/bin/php /var/www/shop/current/artisan schedule:run\n"
ROOT_WPCRON = "* * * * * /var/www/shop/bin/wp --path=/var/www/shop/current/public wp-cron\n"
ROOT_WORKER = "* * * * * /var/www/shop/bin/php /var/www/shop/current/artisan queue:work\n"


def crontabs(
    module: ModuleType, files: dict[str, list[str]], texts: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    directories = {
        str(directory): [pathlib.Path(name) for name in names] for directory, names in files.items()
    }

    def read(path: pathlib.Path, limit: int = 0) -> str:
        return texts.get(str(path), "")

    with (
        mock.patch.object(
            module, "_files", side_effect=lambda directory: directories.get(str(directory), [])
        ),
        mock.patch.object(module, "_read", side_effect=read),
    ):
        value: tuple[dict[str, str], list[str]] = module._crontabs()
        return value


class RootCrontabTests(SimpleTestCase):
    def test_a_root_line_running_the_schedule_is_a_duplicate(self) -> None:
        own, shared = crontabs(
            observe,
            {"/var/spool/cron/crontabs": ["root", "sshop"]},
            {
                str(observe.ROOT_CRONTAB): ROOT_SCHEDULE,
                "/var/spool/cron/crontabs/sshop": "",
            },
        )
        self.assertEqual(own, {"shop": ""})
        self.assertEqual(shared[0], ROOT_SCHEDULE)
        duplicate = observe._duplicate(SHOP, own, shared, [], {})
        self.assertEqual(
            duplicate["schedule"],
            "A hand-made crontab entry already runs the scheduler for this site.",
        )

    def test_a_root_line_running_wordpress_cron_is_a_duplicate(self) -> None:
        own, shared = crontabs(
            observe,
            {"/var/spool/cron/crontabs": ["root"]},
            {str(observe.ROOT_CRONTAB): ROOT_WPCRON},
        )
        duplicate = observe._duplicate(SHOP, own, shared, [], {})
        self.assertEqual(
            duplicate["wpcron"],
            "A hand-made crontab entry already runs WordPress cron for this site.",
        )

    def test_a_root_line_for_another_site_is_not_this_site_duplicate(self) -> None:
        own, shared = crontabs(
            observe,
            {"/var/spool/cron/crontabs": ["root"]},
            {
                str(observe.ROOT_CRONTAB): (
                    "* * * * * /var/www/other/bin/php /var/www/other/current/artisan schedule:run\n"
                )
            },
        )
        duplicate = observe._duplicate(SHOP, own, shared, [], {})
        self.assertEqual(duplicate["schedule"], "")

    def test_a_root_line_running_queue_work_is_a_worker_duplicate(self) -> None:
        own, shared = crontabs(
            observe_workers,
            {"/var/spool/cron/crontabs": ["root"]},
            {str(observe_workers.ROOT_CRONTAB): ROOT_WORKER},
        )
        self.assertEqual(
            observe_workers._duplicate(SHOP, own, shared, [], {}),
            "A hand-made crontab entry already runs queue:work for this site.",
        )

    def test_the_system_crontab_and_cron_d_are_still_read(self) -> None:
        own, shared = crontabs(
            observe,
            {
                "/var/spool/cron/crontabs": [],
                "/etc/cron.d": ["/etc/cron.d/barectl-other"],
            },
            {
                "/etc/crontab": "SHELL=/bin/sh\n",
                "/etc/cron.d/barectl-other": ROOT_SCHEDULE,
            },
        )
        self.assertEqual(own, {})
        self.assertEqual(shared, ["", "SHELL=/bin/sh\n", ROOT_SCHEDULE])
