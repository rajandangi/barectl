"""A graceful site PHP reload requires evidence of a new completed load."""

import os
import signal
import time
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from sites.bodies import common


def load(completed_at: int) -> dict[str, object]:
    return {"load": {"events": [{"__MONOTONIC_TIMESTAMP": str(completed_at)}]}}


class SiteReloadTests(SimpleTestCase):
    def test_the_prior_completed_load_cannot_finish_a_reload(self) -> None:
        settings = SimpleNamespace(identifier="shop", runtime="php84")
        with (
            mock.patch.object(common, "site_fpm_read", return_value=load(100)),
            mock.patch.object(
                common, "run", return_value="ActiveState=active\nMainPID=123\nInvocationID=abc\n"
            ),
            mock.patch.object(os, "kill"),
            mock.patch.object(time, "monotonic_ns", return_value=150_000),
            mock.patch.object(time, "monotonic", side_effect=[0, 0, 31]),
            mock.patch.object(time, "sleep"),
            self.assertRaisesRegex(ValueError, "did not complete"),
        ):
            common.reload_site_fpm(settings)

    def test_a_new_completed_load_with_the_same_master_finishes(self) -> None:
        settings = SimpleNamespace(identifier="shop", runtime="php84")
        with (
            mock.patch.object(common, "site_fpm_read", side_effect=[load(100), load(200)]),
            mock.patch.object(
                common, "run", return_value="ActiveState=active\nMainPID=123\nInvocationID=abc\n"
            ),
            mock.patch.object(os, "kill") as kill,
            mock.patch.object(time, "monotonic_ns", return_value=150_000),
            mock.patch.object(time, "monotonic", side_effect=[0, 0, 1]),
            mock.patch.object(time, "sleep"),
        ):
            common.reload_site_fpm(settings)
        kill.assert_called_once_with(123, signal.SIGUSR2)

    def test_a_replaced_master_does_not_count_as_graceful_reload(self) -> None:
        settings = SimpleNamespace(identifier="shop", runtime="php84")
        with (
            mock.patch.object(common, "site_fpm_read", return_value=load(200)),
            mock.patch.object(
                common,
                "run",
                side_effect=[
                    "ActiveState=active\nMainPID=123\nInvocationID=abc\n",
                    "ActiveState=active\nMainPID=124\nInvocationID=def\n",
                ],
            ),
            mock.patch.object(os, "kill"),
            mock.patch.object(time, "monotonic_ns", return_value=150_000),
            mock.patch.object(time, "monotonic", side_effect=[0, 0]),
            self.assertRaisesRegex(ValueError, "replaced"),
        ):
            common.reload_site_fpm(settings)

    def test_a_pool_change_can_be_unverified_until_the_new_load_completes(self) -> None:
        settings = SimpleNamespace(identifier="shop", runtime="php84")
        with (
            mock.patch.object(common, "site_fpm_read", side_effect=[None, load(200)]),
            mock.patch.object(
                common, "run", return_value="ActiveState=active\nMainPID=123\nInvocationID=abc\n"
            ),
            mock.patch.object(os, "kill"),
            mock.patch.object(time, "monotonic_ns", return_value=150_000),
            mock.patch.object(time, "monotonic", side_effect=[0, 0, 1]),
            mock.patch.object(time, "sleep"),
        ):
            common.reload_site_fpm(settings)
