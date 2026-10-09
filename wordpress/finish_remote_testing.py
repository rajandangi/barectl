"""Fixtures for the Finish's native suites (docs/wordpress.md#finishing-a-partial-installation).

A partly installed site is made the way the product makes one: Barectl installs through the
dashboard's request, the worker and a real unit, and one administrator command is inserted
between two named fragments of the production body, here an ``exit``, so the run stops at that
boundary exactly as an interrupted run does. Nothing is simulated about the files, tables or
Nginx a Finish then finds. Ground truth is read as root through ``docker exec``.
"""

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from types import ModuleType
from unittest import mock

from django.test import Client

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation
from discovery.fakes import run_worker
from discovery.services import request_discovery
from servers.models import Server

from . import finish_native, install_apply, install_native
from .install_native import Evidence, Step
from .models import InstallationReview, PlanWordpressFinish, PlanWordpressInstall
from .test_install_remote import FORM, IDENTIFIER

FINISH_FORM = {
    "finish-title": "Shop & Sons",
    "finish-admin_login": "owner",
    "finish-admin_email": "owner@example.com",
}
# The status an interruption exits with, which no fragment of the body uses.
INTERRUPTED = 77


@contextmanager
def _injected(
    native: ModuleType,
    model: type[PlanWordpressInstall] | type[PlanWordpressFinish],
    plan: ConfigurationPlan,
    after: str,
    step: str,
) -> Iterator[None]:
    """Insert ``step`` after the named fragment of ``native``'s body and bind the plan's
    review to the resulting text, as preparing it would."""
    real = native.body_steps

    def steps(row: InstallationReview, evidence: Evidence, release: str) -> list[Step]:
        built: list[Step] = real(row, evidence, release)
        names = [item.name for item in built]
        built.insert(names.index(after) + 1, Step("injected", step))
        return built

    with mock.patch.object(native, "body_steps", steps):
        row = model.objects.get(plan=plan)
        text = native.body(row, install_apply._evidence(plan), plan.release)
        model.objects.filter(plan=plan).update(body_sha256=install_native.digest(text))
        yield


def injected_install(
    plan: ConfigurationPlan, after: str, step: str
) -> AbstractContextManager[None]:
    return _injected(install_native, PlanWordpressInstall, plan, after, step)


def injected_finish(plan: ConfigurationPlan, after: str, step: str) -> AbstractContextManager[None]:
    return _injected(finish_native, PlanWordpressFinish, plan, after, step)


def review(client: Client, server: Server, address: str, form: dict[str, str]) -> ConfigurationPlan:
    """Discover the server, post ``form`` to a review's address and return its plan."""
    request_discovery(server)
    run_worker()
    response = client.post(f"/servers/{server.pk}/sites/{IDENTIFIER}/wordpress/{address}", form)
    if response.status_code != 302:
        raise AssertionError(response.content[:300])
    run_worker()
    preparation = PlanPreparation.objects.latest("queued_at", "pk")
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    if plan is None:
        raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
    return plan


def review_install(client: Client, server: Server) -> ConfigurationPlan:
    return review(client, server, "install/prepare/", FORM)


def review_finish(
    client: Client, server: Server, form: dict[str, str] | None = None
) -> ConfigurationPlan:
    return review(client, server, "finish/prepare/", FINISH_FORM if form is None else form)


def apply(client: Client, plan: ConfigurationPlan) -> ApplyRun:
    client.post(f"/plans/{plan.pk}/apply/")
    run = ApplyRun.objects.get(plan_number=plan.pk)
    run_worker()
    run.refresh_from_db()
    return run


def interrupt_installation(
    client: Client, server: Server, after: str, step: str | None = None
) -> ApplyRun:
    """Install through Barectl and stop the unit after the named fragment of its body."""
    plan = review_install(client, server)
    if not plan.eligible:
        raise AssertionError(list(plan.refusals.values_list("text", flat=True)))
    with injected_install(plan, after, step or f"exit {INTERRUPTED}"):
        return apply(client, plan)
