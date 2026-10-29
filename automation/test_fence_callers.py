"""Every change that fences reaches the one fence/restore step in its own body (#395).

The body functions are driven with a fake reviewed document and a fence that raises; a
body that never reaches its fence fails instead of passing on a staged-source substring.
The staged program is still compiled, because a body that does not compile cannot run.
"""

import base64
import contextlib
import gzip
import hashlib
import importlib.resources
import json
import os
from collections.abc import Callable
from types import ModuleType, SimpleNamespace
from typing import ClassVar, cast
from unittest import mock

from django.test import SimpleTestCase

from automation import fence, presentation
from automation.status import STATUS_SENTENCE, ScheduleStatus
from backups import change as backups_change
from backups import restore as backups_restore
from backups.bodies import full as full_body
from backups.bodies import restore as restore_body
from cache import instance as cache_instance
from cache.bodies import instance as cache_body
from laravel import change as laravel_change
from laravel import configuration as laravel_configuration
from laravel import rollback as laravel_rollback
from laravel import settings as laravel_settings
from laravel.bodies import common as laravel_common
from laravel.bodies import settings as laravel_settings_body
from operations import engine
from operations.engine import NativeBody
from runtimes import update as catalog_update
from runtimes.bodies import update as catalog_update_body
from sites import node_change, php_change, pool_change, remove
from sites.bodies import common as site_common
from sites.bodies import php_runtime
from sites.bodies import remove as remove_body
from wordpress import settings as wordpress_settings
from wordpress.bodies import settings as wordpress_settings_body

# Each fenced kind's staged body source, by the slug the engine plans for.
SOURCES = {
    "set_site_php": php_change.BODY_SOURCE,
    "set_site_node": node_change.BODY_SOURCE,
    "set_site_pool": pool_change.BODY_SOURCE,
    "deploy_laravel_site": laravel_change.BODY_SOURCE,
    "rollback_laravel_site": laravel_rollback.BODY_SOURCE,
    "edit_laravel_environment": laravel_settings.BODY_SOURCE,
    "edit_wordpress_settings": wordpress_settings.BODY_SOURCE,
    "remove_site": remove.BODY_SOURCE,
    "update_catalog": catalog_update.BODY_SOURCE,
    "set_site_object_cache": cache_instance.BODY_SOURCE,
    "back_up_full_site": backups_change.FULL_SOURCE,
    "restore_database": backups_restore.RESTORE_SOURCE,
}


class FenceReached(Exception):
    """The body executed its reviewed fence call."""


class CallerTests(SimpleTestCase):
    def test_the_source_map_covers_every_fenced_kind(self) -> None:
        self.assertEqual(set(SOURCES), set(fence.FENCING))
        for slug in fence.FENCING:
            self.assertIsNotNone(engine.kind_of(slug), slug)
        self.assertEqual({slug for slug, *_ in CALLERS} | {"remove_site"}, set(SOURCES))

    def test_every_fenced_change_stages_a_program_that_compiles(self) -> None:
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                compile(source, slug, "exec")

    def test_the_helpers_are_defined_before_any_entry_block_runs(self) -> None:
        """A body runs as ``__main__``; its entry block must come after the fence helpers."""
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                entry = source.find('if __name__ == "__main__":')
                terminate = source.find("raise SystemExit(main(")
                for marker in (entry, terminate):
                    if marker < 0:
                        continue
                    self.assertLess(source.find("def fence("), marker)
                    self.assertLess(source.find("def restore("), marker)

    def test_each_kind_own_change_function_reaches_its_fence(self) -> None:
        for slug, module, function, args, patches in CALLERS:
            with self.subTest(slug=slug), contextlib.ExitStack() as stack:
                for name, value in patches().items():
                    stack.enter_context(mock.patch.object(module, name, value))
                stack.enter_context(
                    mock.patch.object(module, "fence", side_effect=FenceReached, create=True)
                )
                with self.assertRaises(FenceReached):
                    getattr(module, function)(*args())

    def test_every_fenced_change_restores_except_removal(self) -> None:
        for slug, source in SOURCES.items():
            if slug == "remove_site":
                continue
            with self.subTest(slug=slug):
                self.assertIn("if not restore(document, ", source)

    def test_removal_never_starts_the_sites_work_again(self) -> None:
        steps = importlib.resources.files("sites.bodies").joinpath("remove.py").read_text()
        self.assertIn("remove_automation(document, identifier)", steps)
        self.assertNotIn("automation_restore", steps)

    def test_removal_reaches_the_fence_before_it_mutates(self) -> None:
        current = {"digest": "digest", "site_file_digest": "file"}
        with (
            mock.patch.object(remove_body, "inventory", return_value=current),
            mock.patch.object(remove_body, "fence", side_effect=FenceReached, create=True),
            self.assertRaises(FenceReached),
        ):
            remove_body.remove(
                {
                    "identifier": "shop",
                    "site_digest": "digest",
                    "site_file_digest": "file",
                }
            )


def _switch_args() -> tuple[object, ...]:
    return ({"identifier": "shop", "selection": "php85", "precondition_digest": "d", "path": "p"},)


def _switch_patches() -> dict[str, object]:
    return {
        "php_state": lambda identifier: {"digest": "d", "profiles": {"php85": "p"}},
        "php_settings": lambda identifier, state, selected: SimpleNamespace(
            directory="/var/www/shop"
        ),
        "missing_php_modules": lambda state, selected: False,
        "common": SimpleNamespace(
            open_site_lock=lambda identifier: os.open(os.devnull, os.O_RDONLY),
            stage=lambda label: None,
            result=lambda *args: None,
        ),
    }


def _node_args() -> tuple[object, ...]:
    return (
        {
            "identifier": "shop",
            "selection": "nodejs_24",
            "precondition_digest": "d",
            "path": "p",
        },
        os.open(os.devnull, os.O_RDONLY),
    )


def _node_patches() -> dict[str, object]:
    return {
        "site_node_state": lambda identifier: {
            "digest": "d",
            "native": {"sites": [{"identifier": "shop", "state": "complete", "problem": ""}]},
        },
        "known_node_profile": lambda selection: "p",
        "safe": lambda path, directory=False: True,
        "same_site_lock": lambda descriptor, identifier: True,
    }


def _pool_args() -> tuple[object, ...]:
    return (
        {"identifier": "shop", "pool": {}, "precondition_digest": "d"},
        os.open(os.devnull, os.O_RDONLY),
    )


def _pool_patches() -> dict[str, object]:
    state = {
        "digest": "d",
        "sites": [
            {
                "identifier": "shop",
                "state": "complete",
                "pool": object(),
                "names": ["shop.example.com"],
                "runtime": "php84",
                "https": True,
                "readiness": "/",
            }
        ],
    }
    return {
        "SitePool": SimpleNamespace(from_document=lambda value: object()),
        "native_state": lambda *args, **kwargs: state,
        "setting": lambda *args, **kwargs: SimpleNamespace(
            identifier="shop", runtime="php84", account="sshop"
        ),
        "site_pool_path": lambda identifier, runtime: "/run/barectl/test/pool.conf",
        "current_bytes": lambda path: "preimage",
        "render_pool_settings": lambda text, pool: "candidate",
        "pwd": SimpleNamespace(getpwnam=lambda account: SimpleNamespace(pw_uid=1001)),
        "validate_pool_candidate": lambda settings, uid, candidate: None,
        "same_site_lock": lambda descriptor, identifier: True,
        "stage": lambda label: None,
    }


def _deploy_args() -> tuple[object, ...]:
    document = {"commit": "c", "token": "t", "repository": "r", "branch": "main", "gate": "g"}
    return (document, SimpleNamespace(), "shop", os.open(os.devnull, os.O_RDONLY))


def _deploy_patches() -> dict[str, object]:
    return {
        "_preflight": lambda *args: "",
        "release_path": lambda settings, name: f"releases/{name}",
        "stage": lambda label: None,
        "fetch": lambda *args: None,
        "build": lambda *args: None,
        "link_shared": lambda *args: None,
        "discover": lambda *args: None,
        "classify": lambda *args: None,
        "_attempt": lambda *args: "",
    }


def _rollback_args() -> tuple[object, ...]:
    document = {"release": "r", "gate": "g"}
    return (document, SimpleNamespace(), "shop", os.open(os.devnull, os.O_RDONLY))


def _rollback_patches() -> dict[str, object]:
    return {
        "_rollback_preflight": lambda *args: "",
        "stage": lambda label: None,
    }


def _environment_args() -> tuple[object, ...]:
    text = "APP_ENV=production\n"
    return (
        {
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
            "environment_digest": hashlib.sha256(text.encode()).hexdigest(),
            "changes": [],
            "secret_fields": [],
        },
    )


def _environment_patches() -> dict[str, object]:
    return {
        "setting": lambda *args, **kwargs: SimpleNamespace(identifier="shop"),
        "site_account": lambda identifier: object(),
        "environment_path": lambda identifier: "/run/barectl/test/laravel.env",
        "open_site_lock": lambda identifier: os.open(os.devnull, os.O_RDONLY),
        "_private_file_ok": lambda path, identifier: True,
        "read_environment": lambda identifier: "APP_ENV=production\n",
        "environment_entries_from_text": lambda text: [],
        "laravel_managed": lambda identifier, entries: {},
        "_changes": lambda document: [],
        "stage": lambda label: None,
    }


def _settings_args() -> tuple[object, ...]:
    text = "<?php\n"
    return (
        {
            "identifier": "shop",
            "configuration_digest": hashlib.sha256(text.encode()).hexdigest(),
            "changes": [],
            "secret_fields": [],
        },
    )


def _settings_patches() -> dict[str, object]:
    return {
        "private_configuration_path": lambda identifier: "/run/barectl/test/wp-config.php",
        "open_site_lock": lambda identifier: os.open(os.devnull, os.O_RDONLY),
        "site_account": lambda identifier: object(),
        "_private": lambda path, account: True,
        "read_configuration": lambda identifier: "<?php\n",
        "private_configuration_problem": lambda text, identifier: False,
        "extra_constants": lambda text, identifier: [],
        "_changes": lambda document: [],
        "stage": lambda label: None,
    }


def _update_args() -> tuple[object, ...]:
    return ("shop", "php85", {"identifier": "shop"})


def _update_patches() -> dict[str, object]:
    return {
        "open_site_lock": lambda identifier: os.open(os.devnull, os.O_RDONLY),
        "php_state": lambda identifier: {"profiles": {"php85": "p"}},
        "profile_path": lambda target: "p",
        "missing_php_modules": lambda state, target: False,
    }


def _cache_args() -> tuple[object, ...]:
    text = "CACHE_STORE=database\n"
    return (
        {
            "enabled": False,
            "maxmemory_mib": 64,
            "environment_digest": hashlib.sha256(text.encode()).hexdigest(),
        },
        {},
        "shop",
    )


def _cache_patches() -> dict[str, object]:
    return {
        "_laravel_environment": lambda identifier: "CACHE_STORE=database\n",
        "laravel_wiring": lambda identifier, entries: "",
        "_environment_entries": lambda text: [],
        "stage": lambda label: None,
    }


def _full_args() -> tuple[object, ...]:
    document = {
        "identifier": "shop",
        "repository": "/var/lib/barectl-backups/shop/onsite",
        "server_key": "/etc/barectl/backups/shop.key",
        "point": "0123456789abcdef",
        "at": "2026-10-29T04:00:00+00:00",
        "restic_time": "2026-10-29 04:00:00",
        "scope": "files",
        "application": "plain",
        "names": ["shop.example.com"],
        "runtime": "php84",
        "https": True,
        "readiness": "/",
        "caddy": "open",
        "gate": "gate",
        "files": [],
        "dump": [],
        "filename": "sshop.sql",
        "tags": {},
        "automation_fence": {"version": 1, "sites": []},
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return (encoded,)


def _restore_args() -> tuple[object, ...]:
    document = {
        "identifier": "shop",
        "repository": "/var/lib/barectl-backups/shop/onsite",
        "server_key": "/etc/barectl/backups/shop.key",
        "point": "0123456789abcdef",
        "snapshot": "a" * 64,
        "filename": "sshop.sql",
        "engine": "mariadb",
        "engine_major": "11.8",
        "application": "plain",
        "scope": "database",
        "at": "2026-10-30T04:00:00+00:00",
        "restic_time": "2026-10-30 04:00:00",
        "names": ["shop.example.com"],
        "runtime": "php84",
        "https": True,
        "readiness": "/",
        "caddy": "open",
        "gate": "gate",
        "target_empty": True,
        "safety_tags": [],
        "dump": ["dump"],
        "point_size": 0,
        "automation_fence": {"version": 1, "sites": []},
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return (encoded,)


def _restore_patches() -> dict[str, object]:
    return {
        "site_settings": lambda document: SimpleNamespace(identifier="shop"),
        "open_file": lambda settings, application: "open",
        "site_lock": lambda identifier, gid: os.open(os.devnull, os.O_RDONLY),
        "free_bytes": lambda: 4 * 1024 * 1024 * 1024,
        "os": SimpleNamespace(
            path=SimpleNamespace(isfile=lambda path: True, join=os.path.join),
            open=os.open,
            close=os.close,
            access=lambda path, mode: True,
            X_OK=os.X_OK,
        ),
        "safe_config": lambda path: True,
        "locked_file": lambda path, mode: True,
        "controlled": lambda path: True,
        "pwd": SimpleNamespace(getpwnam=lambda account: SimpleNamespace(pw_uid=1001, pw_gid=1001)),
        "reviewed_point": lambda document, repository, key: True,
        "header_bytes": lambda repository, key, snapshot, filename: b"-- Server version\t11.8.2\n",
        "count_tables": lambda engine, identifier: 0,
    }


def _full_patches() -> dict[str, object]:
    return {
        "site_settings": lambda document: SimpleNamespace(identifier="shop"),
        "reviewed_files": lambda settings, application: [],
        "open_file": lambda settings, application: "open",
        "maintenance_file": lambda settings: "gate",
        "site_lock": lambda identifier, gid: os.open(os.devnull, os.O_RDONLY),
        "free_bytes": lambda: 4 * 1024 * 1024 * 1024,
        "os": SimpleNamespace(
            path=SimpleNamespace(isfile=lambda path: True, join=os.path.join),
            open=os.open,
            close=os.close,
        ),
        "safe_config": lambda path: True,
        "locked_file": lambda path, mode: True,
        "controlled": lambda path: True,
        "pwd": SimpleNamespace(getpwnam=lambda account: SimpleNamespace(pw_uid=1001, pw_gid=1001)),
    }


CALLERS: tuple[
    tuple[
        str,
        ModuleType,
        str,
        Callable[[], tuple[object, ...]],
        Callable[[], dict[str, object]],
    ],
    ...,
] = (
    ("set_site_php", php_runtime, "switch_php", _switch_args, _switch_patches),
    ("set_site_node", site_common, "node_locked_change", _node_args, _node_patches),
    ("set_site_pool", site_common, "pool_locked_change", _pool_args, _pool_patches),
    ("deploy_laravel_site", laravel_common, "_deploy_release", _deploy_args, _deploy_patches),
    (
        "rollback_laravel_site",
        laravel_common,
        "_rollback_release",
        _rollback_args,
        _rollback_patches,
    ),
    (
        "edit_laravel_environment",
        laravel_settings_body,
        "edit_environment",
        _environment_args,
        _environment_patches,
    ),
    (
        "edit_wordpress_settings",
        wordpress_settings_body,
        "edit_constants",
        _settings_args,
        _settings_patches,
    ),
    ("update_catalog", catalog_update_body, "move_site", _update_args, _update_patches),
    ("set_site_object_cache", cache_body, "_apply_laravel", _cache_args, _cache_patches),
    ("back_up_full_site", full_body, "main", _full_args, _full_patches),
    ("restore_database", restore_body, "main", _restore_args, _restore_patches),
)


def passthrough(value: dict[str, object]) -> dict[str, object]:
    return dict(value)


class PayloadTests(SimpleTestCase):
    """The reviewed plan must survive each kind's closed payload (#398 regression).

    A body that rebuilds its payload from a fixed key list silently dropped the plan, so the
    fence read the document as "nothing to pause" and did nothing. The native
    ``RebootGateFence`` scenario found it; this pins the assembly for every affected kind.
    """

    PLAN: ClassVar[dict[str, object]] = {
        "version": 1,
        "sites": [
            {
                "identifier": "shop",
                "slice": "barectl-site-shop.slice",
                "timers": ["barectl-site-shop-wpcron.timer"],
                "services": ["barectl-site-shop-wpcron.service"],
                "resume": ["barectl-site-shop-wpcron.timer"],
                "budget_seconds": 30,
            }
        ],
    }

    def decode(self, body: NativeBody) -> dict[str, object]:
        return cast(
            dict[str, object], json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        )

    def laravel_document(self, bootstrap: str) -> dict[str, object]:
        return {
            "version": 1,
            "body_sha256": bootstrap,
            "identifier": "shop",
            "names": ["shop.example.com"],
            "runtime": "php84",
            "repository": "https://git.example.com/shop.git",
            "commit": "a" * 40,
            "token": "t" * 8,
            "current": "release-1",
            "releases": ["release-1"],
            "prune": [],
            "disk_required": 0,
            "migrations": True,
            "gate": "",
            "caddy": "",
            "https": True,
            "branch": "main",
            "acknowledgement": laravel_change.MIGRATION_ACKNOWLEDGEMENT,
            "automation_fence": self.PLAN,
        }

    def settings_document(self, digest: str) -> dict[str, object]:
        return {
            "version": 1,
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
            "https": True,
            "changes": [{"key": "FEATURE_FLAG", "action": "set", "digest": "b" * 64}],
            "secret_fields": [],
            "environment_digest": digest,
            "configuration_digest": digest,
            "automation_fence": self.PLAN,
        }

    def test_a_deploy_and_a_roll_back_payload_carry_the_plan(self) -> None:
        for module, acknowledgement in (
            (laravel_change, laravel_change.MIGRATION_ACKNOWLEDGEMENT),
            (laravel_rollback, laravel_configuration.ROLLBACK_ACKNOWLEDGEMENT),
        ):
            with self.subTest(module=module.__name__):
                document = self.laravel_document(module.BODY_SHA256)
                document["acknowledgement"] = acknowledgement
                body = module.body(document, mock.Mock())
                self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)

    def test_a_settings_payload_carries_the_plan(self) -> None:
        digest = "c" * 64
        for module in (laravel_settings, wordpress_settings):
            with self.subTest(module=module.__name__):
                document = self.settings_document(digest)
                with mock.patch.object(module, "_document", passthrough):
                    body = module.body(document, mock.Mock(secret_path=""))
                self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)

    def test_a_cache_payload_carries_the_plan(self) -> None:
        document = {
            "version": 1,
            "identifier": "shop",
            "application": "wordpress",
            "enabled": True,
            "maxmemory_mib": 64,
            "automation_fence": self.PLAN,
        }
        with mock.patch.object(cache_instance, "_document", passthrough):
            body = cache_instance.body(document, mock.Mock())
        self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)


class FenceSummaryTests(SimpleTestCase):
    def summary(self, document: dict[str, object]) -> presentation.FenceSummary:
        summary = presentation.fence_summary(document)
        if summary is None:
            self.fail("The change declared no fence summary.")
        return summary

    def document(self, **values: object) -> dict[str, object]:
        site = {
            "identifier": "shop",
            "slice": "barectl-site-shop.slice",
            "timers": ["barectl-site-shop-wpcron.timer"],
            "services": ["barectl-site-shop-wpcron.service"],
            "resume": ["barectl-site-shop-wpcron.timer"],
            "budget_seconds": 30,
            **values,
        }
        return {"automation_fence": {"version": 1, "sites": [site]}}

    def test_a_site_change_names_what_it_pauses_and_starts_again(self) -> None:
        summary = self.summary(self.document())
        self.assertEqual(summary.pauses, ("shop's scheduled tasks",))
        self.assertEqual(summary.resumes, ("shop's scheduled tasks",))

    def test_a_change_with_no_automation_pauses_and_starts_nothing(self) -> None:
        summary = self.summary({"automation_fence": {"version": 1, "sites": []}})
        self.assertTrue(summary.pauses_nothing)
        self.assertTrue(summary.starts_nothing)

    def test_a_change_that_never_fences_has_no_summary(self) -> None:
        self.assertIsNone(presentation.fence_summary({}))

    def test_a_worker_is_named_as_the_work_it_does(self) -> None:
        summary = self.summary(
            self.document(
                timers=[],
                services=["barectl-site-shop-queue1.service"],
                resume=["barectl-site-shop-queue1.service"],
            )
        )
        self.assertEqual(summary.pauses, ("shop's queue workers",))
        self.assertEqual(summary.resumes, ("shop's queue workers",))

    def test_a_plan_that_leaves_installed_work_off_names_the_site(self) -> None:
        summary = self.summary(self.document(resume=[]))
        self.assertTrue(summary.work_off)
        self.assertEqual(summary.stopped_sites, ("shop",))

    def test_a_plan_that_starts_work_again_asks_nothing(self) -> None:
        self.assertFalse(self.summary(self.document()).work_off)

    def test_the_plain_words_name_the_paused_and_maintenance_states(self) -> None:
        self.assertEqual(STATUS_SENTENCE[ScheduleStatus.PAUSED], "Paused by an unfinished change")
        self.assertEqual(
            STATUS_SENTENCE[ScheduleStatus.OFF_MAINTENANCE],
            "Background work is off while the site is in maintenance",
        )
