"""Stored and in-memory automation evidence for reviews, pages and recordings."""

import json
from dataclasses import replace
from datetime import datetime

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import (
    Observation,
    ObservedSetting,
    ObservedSite,
    SiteAccount,
    save_snapshot,
)
from discovery.ssh import CommandResult, RemoteShell
from servers.models import Server
from sites.bodies.common import NativeState, SiteRecord

from . import convention, observation, workers
from .observation import ObservedSchedule
from .status import ScheduleStatus
from .worker_observation import ObservedWorker
from .worker_status import WorkerStatus
from .workers import WorkerDefinition

IDENTIFIER = "shop"
DIGEST = "a" * 64
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"


class AutomationReplay:
    """A replaying shell that also answers the reviewed fence's automation read.

    A transcript is recorded with discovery's release inventory off, so it holds no
    automation read and no automation units (docs/quality.md#recorded-transcripts). A test
    that prepares a fenced change through the worker opts in here; every other command is
    the transcript's own answer, and an unrecorded one still fails.
    """

    def __init__(self, inner: RemoteShell, value: dict[str, object] | None = None) -> None:
        self._inner = inner
        self._value = {"version": 2, "sites": []} if value is None else value

    @property
    def host_key(self) -> str:
        return self._inner.host_key

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        if command == observation.read_command():
            return CommandResult(0, json.dumps(self._value))
        return self._inner.run(command, stdin)


def show(
    *,
    sub_state: str = "dead",
    result: str = "success",
    enabled: str = "enabled",
    active: str = "inactive",
    load: str = "loaded",
    start: str = "0",
    exit_time: str = "0",
    last_trigger: str = "0",
    next_elapse: str = "0",
    group: str = "",
) -> dict[str, str]:
    """One unit's ``systemctl show`` answer in the read's own format."""
    return {
        "Id": "unit",
        "LoadState": load,
        "ActiveState": active,
        "SubState": sub_state,
        "UnitFileState": enabled,
        "Result": result,
        "ExecMainStatus": "0",
        "ExecMainStartTimestamp": start,
        "ExecMainExitTimestamp": exit_time,
        "LastTriggerUSec": last_trigger,
        "NextElapseUSecRealtime": next_elapse,
        "ControlGroup": group,
        "RefuseManualStart": "no",
    }


def site_record(
    identifier: str = IDENTIFIER,
    *,
    application: str = "wordpress",
    state: str = "complete",
    problem: str = "",
    application_problem: str = "",
    uid: int = 1001,
) -> SiteRecord:
    return {
        "identifier": identifier,
        "names": [f"{identifier}.example.com"],
        "runtime": "php84",
        "node_runtime": "",
        "https": True,
        "readiness": "/",
        "certificate": None,
        "pool": None,
        "account": [uid, uid, f"/var/www/{identifier}", "/usr/sbin/nologin"],
        "file": f"/etc/caddy/sites/{identifier}.caddy",
        "state": state,
        "problem": problem,
        "application": application,
        "application_version": "7.1.3" if application == "wordpress" else "",
        "application_problem": application_problem,
        "serving_form": "wordpress",
    }


def native_state(site: SiteRecord | None = None) -> NativeState:
    record = site if site is not None else site_record()
    return {
        "version": 1,
        "boot": BOOT,
        "uptime": 500000,
        "sites": [record],
        "current_sites": [record["identifier"]],
        "disk_digest": DIGEST,
        "digest": DIGEST,
        "evidence": {},
        "next_id": 1002,
        "next_proxy_id": 1002,
        "validation": "",
        "pool_validation": "",
        "master_present": True,
    }


def wordpress(
    identifier: str = IDENTIFIER, *, disable: str = "", digest: str = DIGEST
) -> dict[str, object]:
    return {
        "version": 1,
        "sites": [
            {
                "identifier": identifier,
                "digest": digest,
                "constants": [],
                "cron": {"disable": disable},
            }
        ],
    }


def installed_units(
    identifier: str = IDENTIFIER, role: str = convention.ROLE_WPCRON
) -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "kind": kind,
            "text": convention.render(identifier, role, kind),
        }
        for kind, name in (
            ("slice", convention.slice_name(identifier)),
            ("service", convention.service_name(identifier, role)),
            ("timer", convention.timer_name(identifier, role)),
        )
    ]


def unit_digests(
    identifier: str = IDENTIFIER, role: str = convention.ROLE_WPCRON
) -> dict[str, str]:
    return {
        kind: convention.digest(convention.render(identifier, role, kind))
        for kind in ("slice", "service", "timer")
    }


def automation(
    identifier: str = IDENTIFIER,
    *,
    units: list[dict[str, str]] | None = None,
    service: dict[str, str] | None = None,
    timer: dict[str, str] | None = None,
    slice_values: dict[str, str] | None = None,
    schedule_service: dict[str, str] | None = None,
    schedule_timer: dict[str, str] | None = None,
    duplicate: str = "",
    schedule_duplicate: str = "",
    unreadable: bool = False,
    slice_populated: bool = False,
) -> dict[str, object]:
    absent = show(load="not-found", enabled="", active="inactive")
    return {
        "version": 2,
        "sites": [
            {
                "identifier": identifier,
                "units": installed_units(identifier) if units is None else units,
                "roles": {
                    convention.ROLE_WPCRON: {
                        "service": absent if service is None else service,
                        "timer": absent if timer is None else timer,
                    },
                    convention.ROLE_SCHEDULE: {
                        "service": absent if schedule_service is None else schedule_service,
                        "timer": absent if schedule_timer is None else schedule_timer,
                    },
                    **{
                        role: {"service": absent, "timer": absent}
                        for role in convention.WORKER_ROLES
                    },
                },
                "slice": absent if slice_values is None else slice_values,
                "slice_populated": slice_populated,
                "unreadable": [convention.ROLE_WPCRON, convention.ROLE_SCHEDULE]
                if unreadable
                else [],
                "duplicates": {
                    convention.ROLE_WPCRON: duplicate,
                    convention.ROLE_SCHEDULE: schedule_duplicate,
                    **dict.fromkeys(convention.WORKER_ROLES, ""),
                },
            }
        ],
    }


def schedule(
    *,
    identifier: str = IDENTIFIER,
    role: str = convention.ROLE_WPCRON,
    status: ScheduleStatus = ScheduleStatus.OFF,
    installed: bool = False,
    disable: str = "",
    duplicate: str = "",
    timer_active: bool = False,
    timer_enabled: bool = False,
    result: str = "",
    last_start_us: int = 0,
    last_exit_us: int = 0,
) -> ObservedSchedule:
    return ObservedSchedule(
        identifier=identifier,
        role=role,
        status=status,
        duplicate=duplicate,
        disable_wp_cron=disable,
        installed=installed,
        timer_active=timer_active,
        timer_enabled=timer_enabled,
        service_active=status == ScheduleStatus.RUNNING,
        result=result,
        last_start_us=last_start_us,
        last_exit_us=last_exit_us,
    )


def record_schedule(
    server: Server,
    *,
    identifier: str = IDENTIFIER,
    rows: tuple[ObservedSchedule, ...] | None = None,
    disable: str = "",
    application: str = "wordpress",
    application_version: str = "7.1.3",
    checked_at: datetime | None = None,
) -> None:
    """A site whose stored snapshot carries the projected scheduled work."""
    site = ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        "php84",
        SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
        https=True,
        application=application,
        application_version=application_version,
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", (site,)),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        settings=Observation(
            ObservationOutcome.OBSERVED,
            ("/var/www",),
            "",
            (
                (ObservedSetting(identifier, "laravel", "APP_ENV", DIGEST),)
                if application == "laravel"
                else (
                    (ObservedSetting(identifier, "wordpress", "DISABLE_WP_CRON", DIGEST, disable),)
                    if disable
                    else ()
                )
            ),
        ),
        automation=Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/systemd/system",),
            "",
            rows if rows is not None else (schedule(),),
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    from sites.ui_testing import attach_current_connection

    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, checked_at or timezone.now())


def record_laravel_schedule(
    server: Server,
    *,
    identifier: str = IDENTIFIER,
    rows: tuple[ObservedSchedule, ...] | None = None,
    checked_at: datetime | None = None,
) -> None:
    """A Laravel site whose stored snapshot carries the projected scheduler."""
    record_schedule(
        server,
        identifier=identifier,
        rows=rows
        if rows is not None
        else (schedule(identifier=identifier, role=convention.ROLE_SCHEDULE),),
        application="laravel",
        application_version="",
        checked_at=checked_at,
    )


def worker_definition(
    queues: tuple[str, ...] = ("default",), processes: int = 1, timeout: int = 60
) -> WorkerDefinition:
    return WorkerDefinition(queues, processes, timeout)


def worker_units(
    identifier: str = IDENTIFIER, definition: WorkerDefinition | None = None
) -> list[dict[str, str]]:
    value = definition if definition is not None else worker_definition()
    return [
        {"name": name, "kind": kind, "text": text}
        for kind, name, text in workers.render_worker_units(identifier, value)
    ]


def worker_show(
    *,
    active: str = "active",
    enabled: str = "enabled",
    result: str = "success",
    load: str = "loaded",
    start: str = "@60000000",
    exit_time: str = "@65000000",
    restarts: str = "0",
    group: str = "",
) -> dict[str, str]:
    return {
        "Id": "unit",
        "LoadState": load,
        "ActiveState": active,
        "SubState": "running" if active == "active" else "dead",
        "UnitFileState": enabled,
        "Result": result,
        "ExecMainStatus": "0",
        "ExecMainStartTimestamp": start,
        "ExecMainExitTimestamp": exit_time,
        "NRestarts": restarts,
        "ControlGroup": group,
    }


def worker_payload(
    identifier: str = IDENTIFIER,
    *,
    definition: WorkerDefinition | None = None,
    units: list[dict[str, str]] | None = None,
    show: dict[str, dict[str, str] | None] | None = None,
    slice_values: dict[str, str] | None = None,
    duplicate: str = "",
    unreadable: bool = False,
    slice_populated: bool = False,
) -> dict[str, object]:
    value = definition if definition is not None else worker_definition()
    absent = worker_show(load="not-found", enabled="", active="inactive")
    rows: dict[str, dict[str, str] | None] = {
        role: (worker_show() if index < value.processes else absent)
        for index, role in enumerate(workers.WORKER_ROLES)
    }
    if show is not None:
        rows.update(show)
    return {
        "version": 1,
        "sites": [
            {
                "identifier": identifier,
                "units": worker_units(identifier, value) if units is None else units,
                "show": rows,
                "slice": slice_values
                if slice_values is not None
                else worker_show(active="inactive"),
                "slice_populated": slice_populated,
                "unreadable": unreadable,
                "duplicate": duplicate,
            }
        ],
    }


def laravel_site(identifier: str = IDENTIFIER) -> ObservedSite:
    return ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        "php84",
        SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
        https=True,
        application="laravel",
    )


def record_worker(
    server: Server,
    *,
    identifier: str = IDENTIFIER,
    row: ObservedWorker | None = None,
    checked_at: datetime | None = None,
) -> None:
    """A Laravel site whose stored snapshot carries the projected queue workers."""
    site = laravel_site(identifier)
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", (site,)),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        settings=Observation(
            ObservationOutcome.OBSERVED,
            ("/var/www",),
            "",
            (ObservedSetting(identifier, "laravel", "APP_ENV", DIGEST, "production"),),
        ),
        workers=Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/systemd/system",),
            "",
            (row if row is not None else observed_worker(identifier),),
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    from sites.ui_testing import attach_current_connection

    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, checked_at or timezone.now())


def observed_worker(
    identifier: str = IDENTIFIER,
    *,
    status: WorkerStatus = WorkerStatus.RUNNING,
    definition: WorkerDefinition | None = None,
    installed: bool = True,
    enabled: bool = True,
    active_processes: int = 1,
    result: str = "",
    last_start_us: int = 0,
    last_exit_us: int = 0,
    nrestarts: int = 0,
) -> ObservedWorker:
    value = definition if definition is not None else worker_definition()
    return ObservedWorker(
        identifier=identifier,
        status=status,
        definition=value,
        processes=value.processes,
        active_processes=active_processes,
        installed=installed,
        enabled=enabled,
        result=result,
        last_start_us=last_start_us,
        last_exit_us=last_exit_us,
        nrestarts=nrestarts,
    )
