"""The site object cache change and its recognition (#392).

The review is pure, so most of this runs without a database or an SSH connection. A real
instance, a real plugin and another site's failed connection are proved natively by
``disposable/test_cache.py``.
"""

from dataclasses import replace
from typing import cast

from django.test import SimpleTestCase

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED
from discovery.models import ObservationOutcome, SiteState, WebStackComponent
from discovery.snapshot import (
    CollectedSnapshot,
    Observation,
    ObservedSite,
    Package,
    ServiceUnit,
    SiteAccount,
    WebStackComponentObservation,
)
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import Consent

from . import convention, instance
from .plugin import PLUGIN_ARCHIVE_SHA256, PLUGIN_ARCHIVE_SIZE, PLUGIN_VERSION

BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
DIGEST = "b" * 64
CONFIGURATION = "c" * 64


def valkey_component(version: str = "9.0.4-0ubuntu0.2") -> WebStackComponentObservation:
    return WebStackComponentObservation(
        WebStackComponent.VALKEY,
        Observation(
            ObservationOutcome.OBSERVED,
            ("dpkg-query",),
            "",
            (Package("valkey-server", version), Package("valkey-tools", version)),
        ),
        Observation(
            ObservationOutcome.OBSERVED,
            ("systemctl show valkey-server.service",),
            "",
            (ServiceUnit("valkey-server.service", "masked", "inactive", "dead", "masked"),),
        ),
    )


def collected(*, valkey: bool = True) -> CollectedSnapshot:
    return replace(
        COLLECTED,
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        components=(*COLLECTED.components, valkey_component()) if valkey else COLLECTED.components,
        sites=Observation(ObservationOutcome.OBSERVED, ("/etc/caddy/sites",), "", ()),
        cache=Observation(ObservationOutcome.OBSERVED, ("/etc/valkey",), "", ()),
    )


def site(
    *,
    application: str = "wordpress",
    state: SiteState = SiteState.MANAGED,
    client: str = "phpredis",
) -> ObservedSite:
    return ObservedSite(
        "shop",
        ("shop.example.com",),
        "php84",
        SiteAccount(1001, 1001, "/var/www/shop", "/usr/sbin/nologin"),
        state,
        ObservationOutcome.OBSERVED,
        file="/etc/caddy/sites/shop.caddy",
        application=application,
        application_version="7.1.3" if application == "wordpress" else "",
        client=client,
    )


def wordpress(
    *,
    wiring: str = "complete",
    dropin: bool = True,
    plugin: str = PLUGIN_VERSION,
    present: bool = True,
    digest: str = CONFIGURATION,
) -> dict[str, object]:
    return {
        "present": present,
        "wiring": wiring,
        "configuration_digest": digest,
        "dropin": dropin,
        "plugin": plugin,
    }


def row(
    *,
    config: bool = True,
    memory: int | None = 64,
    config_problem: str = "",
    outside: str = "",
    dropin: bool = True,
    dropin_supported: bool = True,
    active: str = "active",
    user: str = "sshop",
    exec_start: str = "/usr/bin/valkey-server /etc/valkey/shop.conf",
    socket: bool = True,
    socket_uid: int = 1001,
    socket_mode: int = 0o600,
    data: bool = True,
    wordpress_state: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "identifier": "shop",
        "config_present": config,
        "config_digest": DIGEST if config else "",
        "config": convention.render_config("shop", memory or 64) if config else "",
        "memory_mib": memory,
        "config_problem": config_problem,
        "outside": outside,
        "drop_in_present": dropin,
        "drop_in_supported": dropin_supported,
        "drop_in_digest": DIGEST if dropin else "",
        "unit": {
            "LoadState": "loaded",
            "ActiveState": active,
            "SubState": "running" if active == "active" else "dead",
            "UnitFileState": "enabled",
            "User": user,
            "Group": user,
            "ExecStart": f"{{ path={exec_start.split()[0]} ; argv[]={exec_start} ; }}",
        },
        "socket": {"present": socket, "uid": socket_uid, "mode": socket_mode},
        "data": data,
        "wordpress": wordpress_state if wordpress_state is not None else wordpress(),
    }


def value(*rows: dict[str, object]) -> dict[str, object]:
    return {
        "version": 1,
        "boot": BOOT,
        "uptime": 1234,
        "digest": DIGEST,
        "instances": list(rows),
        "sites": ["shop"],
    }


def evidence(
    cache: dict[str, object] | None = None,
    *,
    valkey: bool = True,
    application: str = "wordpress",
    state: SiteState = SiteState.MANAGED,
    client: str = "phpredis",
) -> instance.InstanceEvidence:
    return instance.InstanceEvidence(
        collected(valkey=valkey),
        cache,
        site(application=application, state=state, client=client),
        DIGEST,
    )


def inputs(*, enabled: bool = True, memory: int = 64) -> PreparationInputs:
    return PreparationInputs(
        identifier="shop", object_cache=enabled, cache_mib=memory if enabled else 0
    )


class ObjectCacheReviewTests(SimpleTestCase):
    def test_turning_it_on_names_the_instance_plugin_and_site_consent(self) -> None:
        draft = instance.review(evidence(value(row(config=False, memory=None))), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        self.assertEqual(draft.stages, instance.STAGES)
        document = draft.document
        self.assertEqual(document["enabled"], True)
        self.assertEqual(document["maxmemory_mib"], 64)
        self.assertEqual(document["socket"], "/run/valkey/shop/valkey.sock")
        self.assertEqual(document["prefix"], "sshop:")
        self.assertEqual(document["plugin_version"], PLUGIN_VERSION)
        self.assertEqual(document["plugin_size"], PLUGIN_ARCHIVE_SIZE)
        self.assertEqual(document["plugin_sha256"], PLUGIN_ARCHIVE_SHA256)
        details = cast(list[dict[str, object]], document["details"])
        labels = {row["label"]: row["value"] for row in details}
        self.assertEqual(labels["Memory limit"], "64 MiB")
        self.assertIn(PLUGIN_VERSION, str(labels["WordPress plugin"]))
        self.assertEqual(labels["PHP client"], "phpredis (loaded for this site)")

    def test_a_repeated_review_proposes_nothing(self) -> None:
        draft = instance.review(evidence(value(row())), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already on", str(draft.document["note"]))

    def test_a_supported_hand_edited_limit_is_recognized(self) -> None:
        draft = instance.review(evidence(value(row(memory=128))), inputs(memory=128))
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertIn("already on", str(draft.document["note"]))

    def test_turning_it_off_disconnects_before_stopping(self) -> None:
        draft = instance.review(evidence(value(row())), inputs(enabled=False))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.stages, instance.STAGES_OFF)
        self.assertLess(
            draft.stages.index("disconnect"),
            draft.stages.index("stop"),
        )
        self.assertEqual(draft.document["enabled"], False)
        self.assertEqual(draft.document["maxmemory_mib"], 0)

    def test_an_off_site_with_nothing_proposes_nothing(self) -> None:
        draft = instance.review(
            evidence(
                value(
                    row(
                        config=False,
                        memory=None,
                        dropin=False,
                        wordpress_state=wordpress(wiring="", dropin=False) | {"present": True},
                    )
                )
            ),
            inputs(enabled=False),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertIn("no object cache", str(draft.document["note"]))

    def test_valkey_must_be_installed_first(self) -> None:
        draft = instance.review(evidence(value(row()), valkey=False), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("Install Valkey in Server Settings first", " ".join(draft.refusals))
        self.assertEqual(draft.effects, ())

    def test_a_site_that_is_neither_wordpress_nor_laravel_is_refused(self) -> None:
        draft = instance.review(evidence(value(row()), application="plain"), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("not a verified WordPress or Laravel installation", " ".join(draft.refusals))

    def test_a_site_that_is_not_managed_is_refused(self) -> None:
        draft = instance.review(evidence(value(row()), state=SiteState.PARTLY_APPLIED), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("not fully managed", " ".join(draft.refusals))

    def test_a_site_without_the_php_client_is_refused(self) -> None:
        draft = instance.review(evidence(value(row()), client=""), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("does not load the object cache's PHP client", " ".join(draft.refusals))

    def test_an_unreadable_or_unknown_site_is_refused(self) -> None:
        draft = instance.review(instance.InstanceEvidence(collected(), None, None), inputs())
        self.assertFalse(draft.eligible)
        self.assertIn("could not be read", " ".join(draft.refusals))

    def test_an_unsupported_instance_blocks_turning_on_but_not_off(self) -> None:
        changed = row(config_problem="The cache configuration is outside the supported settings.")
        on = instance.review(evidence(value(changed)), inputs())
        self.assertFalse(on.eligible)
        self.assertIn("outside supported settings", " ".join(on.refusals))
        off = instance.review(evidence(value(changed)), inputs(enabled=False))
        self.assertTrue(off.eligible, off.refusals)
        self.assertFalse(off.no_changes)

    def test_a_private_configuration_outside_the_grammar_is_refused(self) -> None:
        draft = instance.review(
            evidence(value(row(wordpress_state=wordpress(present=False, wiring="", dropin=False)))),
            inputs(),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("private WordPress configuration", " ".join(draft.refusals))


class ObjectCacheObservationTests(SimpleTestCase):
    def test_a_running_instance_with_complete_wiring_is_on(self) -> None:
        state, problem = instance.state_of(
            row(),
            application="wordpress",
            client="phpredis",
            account=[1001, 1001],
        )
        self.assertEqual((state, problem), ("on", ""))

    def test_another_site_account_socket_or_wiring_is_partial(self) -> None:
        for changed in (
            row(socket_uid=1002),
            row(socket_mode=0o666),
            row(socket=False),
            row(active="inactive"),
            row(wordpress_state=wordpress(wiring="partial")),
            row(wordpress_state=wordpress(dropin=False)),
            row(wordpress_state=wordpress(plugin="2.0.1")),
        ):
            with self.subTest(changed=changed["wordpress"]):
                state, problem = instance.state_of(
                    changed,
                    application="wordpress",
                    client="phpredis",
                    account=[1001, 1001],
                )
                self.assertEqual(state, "partial", problem)

    def test_a_supported_memory_edit_is_on_and_an_unsupported_one_is_outside(self) -> None:
        state, _ = instance.state_of(
            row(memory=256),
            application="wordpress",
            client="phpredis",
            account=[1001, 1001],
        )
        self.assertEqual(state, "on")
        outside = row(outside="The cache's memory limit is outside the reviewed sizes.")
        state, problem = instance.state_of(
            outside,
            application="wordpress",
            client="phpredis",
            account=[1001, 1001],
        )
        self.assertEqual(state, "unsupported")
        self.assertIn("memory limit", problem)

    def test_a_changed_user_or_exec_start_is_outside(self) -> None:
        for changed in (
            row(user="valkey"),
            row(exec_start="/usr/bin/valkey-server /etc/valkey/other.conf"),
        ):
            with self.subTest(changed=changed["unit"]):
                state, problem = instance.state_of(
                    changed,
                    application="wordpress",
                    client="phpredis",
                    account=[1001, 1001],
                )
                self.assertEqual(state, "unsupported")
                self.assertIn("outside the site's own account", problem)

    def test_a_plain_site_with_no_artifacts_is_off(self) -> None:
        state, problem = instance.state_of(
            row(
                config=False,
                memory=None,
                dropin=False,
                wordpress_state=wordpress(wiring="", dropin=False),
            )
        )
        self.assertEqual((state, problem), ("off", ""))

    def test_observed_rows_cover_every_site_and_orphan_instances(self) -> None:
        cache = value(row())
        rows = instance.observed(cache, (site(),))
        self.assertEqual([(item.identifier, item.state) for item in rows], [("shop", "on")])
        orphan = row()
        orphan["identifier"] = "orphan"
        unit = cast(dict[str, object], orphan["unit"])
        unit.update(
            {
                "User": "sorphan",
                "Group": "sorphan",
                "ExecStart": "{ path=/usr/bin/valkey-server ; argv[]=/etc/valkey/orphan.conf ; }",
            }
        )
        rows = instance.observed(value(orphan), (site(),))
        found = next(item for item in rows if item.identifier == "orphan")
        self.assertEqual(found.state, "on")


class ObjectCacheDocumentTests(SimpleTestCase):
    def _document(self, **changes: object) -> dict[str, object]:
        draft = instance.review(evidence(value(row(config=False, memory=None))), inputs())
        document = dict(draft.document)
        document.update(changes)
        return document

    def test_the_body_is_the_checked_in_source_and_keeps_the_plugin_pin(self) -> None:
        body = instance.body(self._document(), BodyContext("unit", BOOT, 0))
        self.assertEqual(body.source, instance.BODY_BYTES)
        self.assertFalse(body.source.endswith(b"\n"))
        self.assertEqual(len(body.arguments), 1)
        broken = self._document(plugin_sha256="0" * 64)
        with self.assertRaises(ValueError):
            instance.body(broken, BodyContext("unit", BOOT, 0))

    def test_a_disabled_review_must_not_name_a_memory_size(self) -> None:
        document = self._document(enabled=False, maxmemory_mib=64)
        with self.assertRaises(ValueError):
            instance.body(document, BodyContext("unit", BOOT, 0))

    def test_an_unreviewed_memory_size_is_refused(self) -> None:
        document = self._document(maxmemory_mib=48)
        with self.assertRaises(ValueError):
            instance.body(document, BodyContext("unit", BOOT, 0))

    def test_the_review_inputs_round_trip(self) -> None:
        decoded = decode_inputs(
            {"version": 1, "identifier": "shop", "object_cache": True, "maxmemory_mib": 128},
            (),
            InputShape.SITE_OBJECT_CACHE,
        )
        self.assertEqual(decoded.object_cache, True)
        self.assertEqual(decoded.cache_mib, 128)
        self.assertEqual(
            decoded.document(),
            {"version": 1, "identifier": "shop", "object_cache": True, "maxmemory_mib": 128},
        )
        with self.assertRaises(ValueError):
            decode_inputs(
                {"version": 1, "identifier": "shop", "object_cache": True, "maxmemory_mib": 48},
                (),
                InputShape.SITE_OBJECT_CACHE,
            )


class ObjectCacheFenceTests(SimpleTestCase):
    def test_the_wordpress_sequence_fences_before_its_first_change_and_restores_after(self) -> None:
        source = instance.BODY_SOURCE
        sequence = source[source.index("def apply(") : source.index('if __name__ == "__main__":')]
        self.assertLess(
            sequence.index("if not fence(document, identifier):"),
            sequence.index('stage("instance")'),
        )
        verify = sequence.index('stage("verify")')
        restore = sequence.index("if not restore(document, identifier):")
        self.assertLess(verify, restore)
        self.assertLess(restore, sequence.index('result("succeeded")'))


class ObjectCacheConventionTests(SimpleTestCase):
    def test_the_wordpress_connection_is_the_instance_socket(self) -> None:
        from wordpress import convention as wordpress_convention

        self.assertEqual(
            wordpress_convention.cache_socket("shop"),
            convention.instance_paths("shop").socket,
        )
        self.assertEqual(wordpress_convention.cache_prefix("shop"), "sshop:")
