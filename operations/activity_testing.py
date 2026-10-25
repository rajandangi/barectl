"""Recorded checks and changes for the Activity tests (#369).

Tests never import another test module, so the rows the Activity pages read are recorded
here once. Nothing in this module is imported by the application.
"""

import uuid
from datetime import timedelta

from django.utils import timezone

from operations.consent import DeclaredEffect, Scope
from operations.engine import ReviewDraft, save_review
from operations.fakes import BOOT_ID
from operations.models import (
    ChangePreparation,
    ChangeRun,
    RemoteOperation,
    Result,
    Verification,
)
from servers.models import Server


def record_change(
    server: Server,
    *,
    kind_slug: str = "host_foundation",
    site: str = "",
    status: str = RemoteOperation.Status.SUCCEEDED,
    age: timedelta = timedelta(),
) -> ChangePreparation:
    """A recorded preparation of the server, queued ``age`` ago."""
    inputs: dict[str, object] = {"version": 1}
    if site:
        inputs.update(
            {
                "identifier": site,
                "names": [f"{site}.example.com"],
                "selection": "php84",
            }
        )
    preparation = ChangePreparation.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        kind_slug=kind_slug,
        inputs=inputs,
        status=status,
    )
    ChangePreparation.objects.filter(pk=preparation.pk).update(queued_at=timezone.now() - age)
    preparation.refresh_from_db()
    return preparation


def record_run(
    preparation: ChangePreparation,
    *,
    status: str = RemoteOperation.Status.SUCCEEDED,
    execution: str = Result.SUCCEEDED,
    age: timedelta = timedelta(),
) -> ChangeRun:
    """A run of the preparation's review, queued ``age`` ago."""
    server = preparation.server
    if server is None:
        raise ValueError("A change needs its server.")
    review = save_review(
        preparation,
        ReviewDraft(
            kind=preparation.kind_slug,
            intent="Change something on the server.",
            effects=(DeclaredEffect(Scope.SERVER, "Change something on the server."),),
            stages=("preflight", "verify"),
            boot_id=BOOT_ID,
            uptime_centiseconds=500000,
        ),
        host_key="ssh-ed25519 key",
        collected_at=timezone.now(),
        sites_digest="",
    )
    run = ChangeRun.objects.create(
        server=server,
        review=review,
        requested_by_name="operator",
        server_name=server.name,
        unit_name="barectl-apply-" + uuid.uuid4().hex + ".service",
        status=status,
        execution=execution,
        verification=Verification.PASSED,
    )
    RemoteOperation.objects.filter(pk=run.pk).update(queued_at=timezone.now() - age)
    run.refresh_from_db()
    return run
