"""A Laravel site's own object cache (#393).

The review and body are pure apart from their native seams, so these tests run without a
database or SSH. The real instance, the fixture route through the private connection and the
previous-store restoration are proved natively by ``disposable.test_cache.LaravelObjectCache``.
"""

import ast
import hashlib
import sys
from dataclasses import replace

from django.test import SimpleTestCase

from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import Observation, ObservedCache, ObservedSite
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import Consent

from . import instance
from . import laravel as laravel_convention
from .bodies import instance as body
from .test_site_cache import BOOT, DIGEST, collected, row, site, value, wordpress

SHOP = "shop"
SOCKET = "/run/valkey/shop/valkey.sock"


def laravel_row(
    *,
    current: str = "abc1234-token",
    release_state: str = "complete",
    store: str = "database",
    store_present: bool = True,
    host: str = SOCKET,
    port: str = "0",
    managed: bool = False,
    environment_digest: str = DIGEST,
) -> dict[str, object]:
    values = {"CACHE_STORE": store, "REDIS_HOST": host, "REDIS_PORT": port}
    details: list[dict[str, object]] = []
    for key, item in values.items():
        detail: dict[str, object] = {
            "key": key,
            "digest": hashlib.sha256(item.encode()).hexdigest(),
        }
        if not managed and (key != "CACHE_STORE" or store_present):
            detail["value"] = item
        details.append(detail)
    details.append(
        {
            "key": "APP_NAME",
            "digest": DIGEST,
            "value": "Laravel",
        }
    )
    return {
        "identifier": SHOP,
        "application": "laravel",
        "current": current,
        "repository": "https://example.test/fixture.git",
        "branch": "main",
        "php_requirement": "^8.4",
        "repository_problem": "",
        "releases": [
            {
                "name": current,
                "commit": "abc1234",
                "created": 1,
                "state": release_state,
                "repository": "https://example.test/fixture.git",
                "branch": "main",
            }
        ],
        "shared": {"environment": True, "storage": True, "cache": True},
        "environment": list(values),
        "environment_details": details,
        "environment_digest": environment_digest,
        "deploy_key": "",
        "host_keys": False,
        "problem": "",
    }


def laravel_site(*, state: SiteState = SiteState.MANAGED, client: str = "phpredis") -> ObservedSite:
    # A Laravel site's passive site record is plain; the release inventory names it.
    return replace(site(application="plain", state=state, client=client))


def laravel_cache(*, enabled: bool = False) -> dict[str, object]:
    return row(
        config=enabled,
        memory=64 if enabled else None,
        dropin=enabled,
        active="active" if enabled else "inactive",
        wordpress_state=wordpress(present=False, wiring="", dropin=False, plugin=""),
    )


def evidence(
    *,
    laravel: dict[str, object] | None = None,
    cache: dict[str, object] | None = None,
    state: SiteState = SiteState.MANAGED,
    client: str = "phpredis",
    valkey: bool = True,
) -> instance.InstanceEvidence:
    row_value = laravel if laravel is not None else laravel_row()
    inventory = row_value if "sites" in row_value else {"version": 1, "sites": [row_value]}
    return instance.InstanceEvidence(
        collected(valkey=valkey),
        cache if cache is not None else value(laravel_cache()),
        laravel_site(state=state, client=client),
        DIGEST,
        inventory,
    )


def inputs(
    *, enabled: bool = True, memory: int = 64, previous: tuple[bool, bool, str] | None = None
) -> PreparationInputs:
    known, present, store = previous if previous is not None else (False, True, "")
    return PreparationInputs(
        identifier=SHOP,
        object_cache=enabled,
        cache_mib=memory if enabled else 0,
        cache_store=store,
        cache_store_known=known,
        cache_store_present=present,
    )


class LaravelObjectCacheReviewTests(SimpleTestCase):
    def test_turning_it_on_names_the_store_and_site_consent(self) -> None:
        draft = instance.review(evidence(), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        self.assertEqual(draft.stages, instance.STAGES_LARAVEL)
        document = draft.document
        self.assertEqual(document["application"], "laravel")
        self.assertEqual(document["enabled"], True)
        self.assertEqual(document["maxmemory_mib"], 64)
        self.assertEqual(document["socket"], SOCKET)
        self.assertEqual(document["environment_digest"], DIGEST)
        self.assertTrue(document["write_environment"])
        self.assertEqual(document["previous_store"], "database")
        self.assertTrue(document["previous_store_present"])

    def test_a_repeated_review_proposes_nothing(self) -> None:
        draft = instance.review(
            evidence(
                laravel=laravel_row(store="redis", managed=True),
                cache=value(laravel_cache(enabled=True)),
            ),
            inputs(),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())
        self.assertIn("already on", str(draft.document["note"]))

    def test_turning_it_off_disconnects_and_rebuilds_before_stopping(self) -> None:
        draft = instance.review(
            evidence(
                laravel=laravel_row(store="redis", managed=True),
                cache=value(laravel_cache(enabled=True)),
            ),
            inputs(enabled=False, previous=(True, True, "database")),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.stages, instance.STAGES_LARAVEL_OFF)
        self.assertLess(
            draft.stages.index("disconnect"),
            draft.stages.index("config"),
        )
        self.assertLess(
            draft.stages.index("workers"),
            draft.stages.index("stop"),
        )
        self.assertEqual(draft.document["previous_store"], "database")
        self.assertTrue(draft.document["restore_store"])

    def test_a_fresh_controller_without_the_previous_store_refuses_to_guess(self) -> None:
        draft = instance.review(
            evidence(
                laravel=laravel_row(store="redis", managed=True),
                cache=value(laravel_cache(enabled=True)),
            ),
            inputs(enabled=False),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("will not guess", " ".join(draft.refusals))
        self.assertEqual(draft.effects, ())

    def test_turning_off_is_available_on_a_gated_site_and_a_broken_deploy(self) -> None:
        for row_value, state in (
            (laravel_row(), SiteState.PARTLY_APPLIED),
            (laravel_row(release_state="partial"), SiteState.MANAGED),
        ):
            with self.subTest(state=state, release=row_value["releases"]):
                draft = instance.review(
                    evidence(
                        laravel=row_value,
                        cache=value(laravel_cache(enabled=True)),
                        state=state,
                    ),
                    inputs(enabled=False, previous=(True, True, "database")),
                )
                self.assertTrue(draft.eligible, draft.refusals)

    def test_turning_on_is_refused_while_gated_or_the_last_deploy_is_incomplete(self) -> None:
        gated = instance.review(evidence(state=SiteState.PARTLY_APPLIED), inputs())
        self.assertFalse(gated.eligible)
        self.assertIn("not fully managed", " ".join(gated.refusals))
        incomplete = instance.review(
            evidence(laravel=laravel_row(release_state="partial")), inputs()
        )
        self.assertFalse(incomplete.eligible)
        self.assertIn("last deploy is not complete", " ".join(incomplete.refusals))

    def test_turning_on_is_refused_without_the_php_client_or_valkey(self) -> None:
        client = instance.review(evidence(client=""), inputs())
        self.assertFalse(client.eligible)
        self.assertIn("does not load the object cache's PHP client", " ".join(client.refusals))
        missing = instance.review(evidence(valkey=False), inputs())
        self.assertFalse(missing.eligible)
        self.assertIn("Install Valkey in Server Settings first", " ".join(missing.refusals))

    def test_an_unsupported_instance_blocks_turning_on_but_not_off(self) -> None:
        changed = laravel_cache(enabled=True) | {
            "config_problem": "The cache configuration is outside the supported settings."
        }
        on = instance.review(
            evidence(laravel=laravel_row(store="redis", managed=True), cache=value(changed)),
            inputs(),
        )
        self.assertFalse(on.eligible)
        self.assertIn("outside supported settings", " ".join(on.refusals))
        off = instance.review(
            evidence(laravel=laravel_row(store="redis", managed=True), cache=value(changed)),
            inputs(enabled=False, previous=(True, True, "database")),
        )
        self.assertTrue(off.eligible, off.refusals)


class LaravelObjectCacheStateTests(SimpleTestCase):
    def test_complete_wiring_and_a_running_instance_are_on(self) -> None:
        state, problem = instance.state_of(
            laravel_cache(enabled=True),
            application="laravel",
            client="phpredis",
            account=[1001, 1001],
            wiring="complete",
        )
        self.assertEqual((state, problem), ("on", ""))

    def test_partial_wiring_or_no_client_or_stopped_instance_is_partial(self) -> None:
        for changed, wiring, client in (
            (laravel_cache(enabled=True), "partial", "phpredis"),
            (laravel_cache(enabled=True), "complete", ""),
            (laravel_cache(enabled=False), "complete", "phpredis"),
        ):
            with self.subTest(wiring=wiring, client=client):
                state, problem = instance.state_of(
                    changed,
                    application="laravel",
                    client=client,
                    account=[1001, 1001],
                    wiring=wiring,
                )
                self.assertEqual(state, "partial", problem)

    def test_managed_values_are_withheld_and_the_state_is_reconstructed(self) -> None:
        from laravel.observation import settings_from

        inventory = {"version": 1, "sites": [laravel_row(store="redis", managed=True)]}
        records = settings_from(inventory)
        store = next(record for record in records if record.key == "CACHE_STORE")
        self.assertEqual(store.value, "")
        self.assertEqual(
            laravel_convention.laravel_managed_digests(
                SHOP, {record.key: record.digest for record in records}
            ),
            frozenset(laravel_convention.LARAVEL_KEYS),
        )
        app_name = next(record for record in records if record.key == "APP_NAME")
        self.assertEqual(app_name.value, "Laravel")

    def test_a_repeated_review_from_a_recorded_projection_proposes_nothing(self) -> None:
        projection = Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/valkey",),
            "",
            (
                ObservedCache(
                    SHOP,
                    "on",
                    64,
                    "",
                    "",
                    "phpredis",
                    "active",
                ),
            ),
        )
        self.assertEqual(projection.value[0].state, "on")
        draft = instance.review(
            evidence(
                laravel=laravel_row(store="redis", managed=True),
                cache=value(laravel_cache(enabled=True)),
            ),
            inputs(),
        )
        self.assertTrue(draft.no_changes, draft.refusals)


class LaravelObjectCacheDocumentTests(SimpleTestCase):
    def test_the_staged_body_imports_only_the_standard_library(self) -> None:
        """Every helper is inlined; a project import would fail on the server, not here."""
        tree = ast.parse(instance.BODY_SOURCE)
        modules = set(sys.stdlib_module_names)

        def imported(node: ast.AST) -> set[str]:
            found: set[str] = set()
            for child in ast.iter_child_nodes(node):
                if (
                    isinstance(child, ast.If)
                    and isinstance(child.test, ast.Name)
                    and child.test.id == "TYPE_CHECKING"
                ):
                    continue
                if isinstance(child, ast.Import):
                    found.update(alias.name.split(".")[0] for alias in child.names)
                elif isinstance(child, ast.ImportFrom) and child.level == 0 and child.module:
                    found.add(child.module.split(".")[0])
                found |= imported(child)
            return found

        self.assertEqual(imported(tree) - modules, set())

    def test_the_body_is_the_checked_in_source_and_names_the_environment(self) -> None:
        draft = instance.review(evidence(), inputs())
        body = instance.body(draft.document, BodyContext("unit", BOOT, 0))
        self.assertEqual(body.source, instance.BODY_BYTES)
        self.assertFalse(body.source.endswith(b"\n"))
        self.assertEqual(len(body.arguments), 1)

    def test_a_missing_environment_digest_is_refused(self) -> None:
        draft = instance.review(evidence(), inputs())
        document = dict(draft.document)
        document["environment_digest"] = ""
        with self.assertRaises(ValueError):
            instance.body(document, BodyContext("unit", BOOT, 0))

    def test_the_laravel_inputs_round_trip_and_validate_the_preimage(self) -> None:
        decoded = decode_inputs(
            {
                "version": 1,
                "identifier": SHOP,
                "object_cache": False,
                "maxmemory_mib": 0,
                "cache_store_known": True,
                "cache_store_present": True,
                "cache_store": "database",
            },
            (),
            InputShape.SITE_OBJECT_CACHE,
        )
        self.assertEqual(decoded.cache_store, "database")
        self.assertTrue(decoded.cache_store_known)
        self.assertEqual(
            decoded.document(),
            {
                "version": 1,
                "identifier": SHOP,
                "object_cache": False,
                "maxmemory_mib": 0,
                "cache_store_known": True,
                "cache_store_present": True,
                "cache_store": "database",
            },
        )
        with self.assertRaises(ValueError):
            decode_inputs(
                {
                    "version": 1,
                    "identifier": SHOP,
                    "object_cache": False,
                    "maxmemory_mib": 0,
                    "cache_store_known": True,
                    "cache_store_present": False,
                    "cache_store": "database",
                },
                (),
                InputShape.SITE_OBJECT_CACHE,
            )

    def test_the_body_changes_only_the_managed_environment_keys(self) -> None:
        from cache.bodies.instance import _laravel_changes

        managed = "\n".join(
            f"{key}={value}" for key, value in laravel_convention.laravel_values(SHOP).items()
        )
        on = _laravel_changes(SHOP, managed, {"enabled": True})
        self.assertEqual(
            [(change["key"], change["action"]) for change in on],
            [
                ("CACHE_STORE", "set"),
                ("REDIS_HOST", "set"),
                ("REDIS_PORT", "set"),
            ],
        )
        off = _laravel_changes(
            SHOP,
            managed,
            {
                "enabled": False,
                "restore_store": True,
                "previous_store_present": True,
                "previous_store": "database",
            },
        )
        values = {(change["key"], change["action"], change.get("value")) for change in off}
        self.assertEqual(
            values,
            {
                ("CACHE_STORE", "set", "database"),
                ("REDIS_HOST", "remove", None),
                ("REDIS_PORT", "remove", None),
            },
        )
        foreign = managed.replace("CACHE_STORE=redis", "CACHE_STORE=file")
        off_foreign = _laravel_changes(
            SHOP,
            foreign,
            {"enabled": False, "restore_store": False},
        )
        self.assertEqual(
            [(change["key"], change["action"]) for change in off_foreign],
            [("REDIS_HOST", "remove"), ("REDIS_PORT", "remove")],
        )

    def test_the_laravel_sequence_fences_before_its_first_change_and_restores_after(self) -> None:
        source = instance.BODY_SOURCE
        sequence = source[source.index("def _apply_laravel") : source.index("def apply(")]
        self.assertLess(
            sequence.index("if not fence(document, identifier):"),
            sequence.index('stage("environment")'),
        )
        self.assertEqual(sequence.count("if not restore(document, identifier):"), 2)
        on_verify = sequence.index('stage("verify")')
        on_restore = sequence.index("if not restore(document, identifier):")
        off_verify = sequence.index('stage("verify")', on_verify + 1)
        off_restore = sequence.index("if not restore(document, identifier):", on_restore + 1)
        self.assertLess(on_verify, on_restore)
        self.assertLess(off_verify, off_restore)

    def test_the_laravel_body_orders_the_environment_before_workers_and_stop(self) -> None:
        source = instance.BODY_SOURCE
        sequence = source[source.index("def _apply_laravel") : source.index("def apply(")]
        environment = sequence.index('stage("environment")')
        workers = sequence.index("_restart_site_workers(document, identifier)")
        stop = sequence.index('stage("stop")')
        self.assertLess(environment, workers)
        self.assertLess(workers, stop)

    def test_a_fenced_cache_change_leaves_the_workers_to_restore(self) -> None:
        plan = {
            "automation_fence": {
                "version": 1,
                "sites": [
                    {
                        "identifier": "shop",
                        "services": ["barectl-site-shop-queue1.service"],
                    }
                ],
            }
        }
        self.assertTrue(body._fenced_units(plan, "shop"))
        self.assertFalse(body._fenced_units(plan, "other"))
        self.assertFalse(body._fenced_units({}, "shop"))
