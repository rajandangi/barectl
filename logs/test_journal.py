"""The background-work journals in the Logs section (Phase C #397).

The server-side reader resolves each source's unit through the automation and cache
conventions, reads bounded journal pages by cursor, and scrubs the same secret values as the
file sources. These tests exercise the reader against a temporary unit directory and a fake
journalctl boundary; the native layer proves the real journal.
"""

import json
import pathlib
import tempfile
from collections.abc import Sequence
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from logs.bodies import read
from logs.models import LogRead
from logs.read import LogLine, LogPage, state_wording
from logs.sources import catalogue
from logs.testing import record_background_site, record_log_site
from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import HTMX_FRAGMENT, ControllerConfigTestCase

CANARY = "canary-journal-7c3e91"
Entry = tuple[str, int, str]
Journal = list[tuple[tuple[str, ...], dict[str, object]]]


def _empty_journal(
    units: Sequence[str], *, mode: str, cursor: str, since: str, until: str
) -> tuple[list[Entry], bool]:
    return [], True


def entries(*messages: str, start: int = 0, step: int = 1_000_000) -> list[Entry]:
    """Journal entries newest first, each with its own cursor and microsecond timestamp."""
    return [
        (f"s=page;n={start + index}", 1_793_000_000_000_000 + (start + index) * step, message)
        for index, message in reversed(list(enumerate(messages)))
    ]


class JournalReaderTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.systemd = self.root / "systemd"
        self.systemd.mkdir()
        self.cache = self.root / "valkey"
        self.cache.mkdir()
        self.www = self.root / "www"
        self.calls: Journal = []
        self.entries: read.JournalReader = _empty_journal

    def unit(self, name: str) -> None:
        (self.systemd / name).write_text("[Service]\n")

    def journal(self, *messages: str) -> None:
        """A fake journalctl that records its query and returns the prepared entries."""

        def run(
            units: Sequence[str],
            *,
            mode: str,
            cursor: str,
            since: str,
            until: str,
        ) -> tuple[list[Entry], bool]:
            self.calls.append(
                (
                    tuple(units),
                    {"mode": mode, "cursor": cursor, "since": since, "until": until},
                )
            )
            return entries(*messages), True

        self.entries = run

    def page(
        self, source: str, *, cursor: str = "", term: str = "", since: str = "", until: str = ""
    ) -> dict[str, object]:
        return read.read_page(
            "alpha",
            source,
            root=str(self.www),
            systemd_root=str(self.systemd),
            cache_root=str(self.cache),
            cursor=cursor,
            journal_entries=self.entries,
            term=term,
            since=since,
            until=until,
        )

    def lines(self, page: dict[str, object]) -> list[dict[str, object]]:
        return cast(list[dict[str, object]], page["lines"])

    def raws(self, page: dict[str, object]) -> list[str]:
        return [str(line["raw"]) for line in self.lines(page)]

    def test_a_source_with_no_installed_unit_is_not_configured(self) -> None:
        self.journal("ignored")
        page = self.page("scheduled_tasks")
        self.assertEqual(page["state"], "not_configured")
        self.assertIn("not configured", str(page["note"]))
        self.assertEqual(self.lines(page), [])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.page("queue_workers")["state"], "not_configured")
        self.assertEqual(self.page("object_cache")["state"], "not_configured")

    def test_a_wordpress_site_reads_its_cron_unit_and_a_laravel_site_its_schedule(self) -> None:
        self.journal("cron tick")
        self.unit("barectl-site-alpha-wpcron.service")
        page = self.page("scheduled_tasks")
        self.assertEqual(page["state"], "observed")
        self.assertEqual(self.raws(page), ["cron tick"])
        self.assertEqual(self.calls[-1][0], ("barectl-site-alpha-wpcron.service",))
        (self.systemd / "barectl-site-alpha-wpcron.service").unlink()
        self.unit("barectl-site-alpha-schedule.service")
        self.assertEqual(self.page("scheduled_tasks")["state"], "observed")
        self.assertEqual(self.calls[-1][0], ("barectl-site-alpha-schedule.service",))

    def test_every_installed_queue_unit_is_read_in_process_order(self) -> None:
        self.journal("job done", "job started")
        for index in (3, 1, 2):
            self.unit(f"barectl-site-alpha-queue{index}.service")
        self.unit("barectl-site-alpha-schedule.service")
        page = self.page("queue_workers")
        self.assertEqual(page["state"], "observed")
        self.assertEqual(
            self.calls[-1][0],
            (
                "barectl-site-alpha-queue1.service",
                "barectl-site-alpha-queue2.service",
                "barectl-site-alpha-queue3.service",
            ),
        )
        self.assertEqual(self.raws(page), ["job done", "job started"])

    def test_the_sites_own_cache_instance_is_the_only_cache_unit_read(self) -> None:
        self.journal("cache started")
        (self.cache / "alpha.conf").write_text("port 0\n")
        page = self.page("object_cache")
        self.assertEqual(page["state"], "observed")
        self.assertEqual(self.calls[-1][0], ("valkey-server@alpha.service",))
        (self.cache / "alpha.conf").unlink()
        self.assertEqual(self.page("object_cache")["state"], "not_configured")

    def test_the_newest_page_keeps_five_hundred_lines_and_names_an_older_cursor(self) -> None:
        messages = [f"line {number:04d} {'x' * 80}" for number in range(700)]
        self.unit("barectl-site-alpha-wpcron.service")
        self.journal(*messages)
        newest = self.page("scheduled_tasks")
        self.assertEqual(len(self.lines(newest)), read.MAX_LINES)
        self.assertEqual(self.raws(newest)[0], messages[200])
        self.assertEqual(self.raws(newest)[-1], messages[699])
        self.assertFalse(newest["at_end"])
        self.assertTrue(newest["cursor"])
        self.assertTrue(newest["newest"])
        older = self.page("scheduled_tasks", cursor=str(newest["cursor"]))  # noqa: F841
        self.assertEqual(self.calls[-1][1]["mode"], "older")
        self.assertEqual(self.calls[-1][1]["cursor"], str(newest["cursor"]).removeprefix("older:"))

    def test_a_live_page_reads_after_the_newest_cursor(self) -> None:
        self.unit("barectl-site-alpha-wpcron.service")
        self.journal("new line")
        first = self.page("scheduled_tasks")
        live = self.page("scheduled_tasks", cursor=str(first["newest"]))
        self.assertEqual(self.calls[-1][1]["mode"], "live")
        self.assertEqual(self.calls[-1][1]["cursor"], str(first["newest"]).removeprefix("live:"))
        self.assertTrue(live["live"])
        self.assertEqual(live["cursor"], "")
        self.assertEqual(live["newest"], first["newest"])
        self.assertEqual(self.raws(live), ["new line"])

    def test_a_page_is_at_most_five_hundred_lines_and_its_line_cap(self) -> None:
        self.unit("barectl-site-alpha-wpcron.service")
        self.journal("first", "z" * 20_000)
        page = self.page("scheduled_tasks")
        self.assertEqual(len(self.lines(page)), 2)
        self.assertTrue(self.lines(page)[-1]["truncated"])
        self.assertEqual(len(str(self.lines(page)[-1]["raw"])), read.MAX_LINE_BYTES)
        self.assertLessEqual(int(str(page["bytes"])), read.MAX_PAGE_BYTES)

    def test_secret_values_from_the_private_configuration_are_replaced_before_output(self) -> None:
        private = self.www / "alpha" / "private"
        private.mkdir(parents=True)
        environment = private / "laravel.env"
        environment.write_text(f"APP_KEY=base64:{CANARY}\nAPP_ENV=production\n")
        environment.chmod(0o600)
        self.unit("barectl-site-alpha-schedule.service")
        self.journal(f"job printed base64:{CANARY}")
        page = self.page("scheduled_tasks")
        self.assertNotIn(CANARY, json.dumps(page))
        self.assertIn(read.REDACTED, json.dumps(page))

    def test_an_installed_unit_with_no_lines_is_empty_not_not_configured(self) -> None:
        self.unit("barectl-site-alpha-wpcron.service")
        self.journal()
        page = self.page("scheduled_tasks")
        self.assertEqual(page["state"], "empty")
        self.assertNotEqual(page["state"], "not_configured")


class JournalCatalogueTests(SimpleTestCase):
    def test_a_wordpress_site_lists_scheduled_tasks_but_no_queue_workers(self) -> None:
        labels = [entry.label for entry in catalogue(None, "wordpress")]
        self.assertIn("Scheduled tasks", labels)
        self.assertIn("Object cache", labels)
        self.assertNotIn("Queue workers", labels)

    def test_a_laravel_site_lists_scheduled_tasks_queue_workers_and_the_cache(self) -> None:
        labels = [entry.label for entry in catalogue(None, "laravel")]
        self.assertEqual(labels[-3:], ["Scheduled tasks", "Queue workers", "Object cache"])

    def test_a_plain_php_site_list_lists_no_background_work(self) -> None:
        labels = [entry.label for entry in catalogue(None, "plain")]
        self.assertNotIn("Scheduled tasks", labels)
        self.assertNotIn("Queue workers", labels)
        self.assertNotIn("Object cache", labels)

    def test_the_journal_sources_are_read_by_the_one_reader_on_the_server(self) -> None:
        from logs.read import READ_SOURCE

        namespace: dict[str, object] = {"__name__": "barectl_log_read"}
        exec(compile(READ_SOURCE, "read.py", "exec"), namespace)  # noqa: S102 - the assembled program
        for slug in ("scheduled_tasks", "queue_workers", "object_cache"):
            self.assertIn(slug, read.SOURCES)
        self.assertEqual(
            getattr(namespace.get("read_page"), "__name__", ""),
            "read_page",
        )
        self.assertIn("def _journal_units(", READ_SOURCE)

    def test_a_page_keeps_its_live_and_older_cursors_and_the_not_configured_word(self) -> None:
        page = LogPage(
            "observed",
            (LogLine(raw="line"),),
            cursor="older:s=one",
            newest="live:s=two",
            live=True,
        )
        restored = LogPage.from_document(page.document())
        if restored is None:
            raise AssertionError("the page did not survive its document")
        self.assertEqual(restored.cursor, "older:s=one")
        self.assertEqual(restored.newest, "live:s=two")
        self.assertTrue(restored.live)
        self.assertIn("not configured", state_wording("not_configured", ""))


class JournalPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "view_evidence",
        )
        self.client.force_login(self.user)

    def logs(self, query: str = "") -> str:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/{query}")
        self.assertEqual(response.status_code, 200)
        if response.status_code != 200:
            raise AssertionError(response.content.decode())
        return response.content.decode()

    def test_a_configured_source_is_distinct_from_a_missing_unit_without_a_read(self) -> None:
        record_background_site(
            self.server, application="laravel", scheduled=False, workers=0, cache="off"
        )
        page = self.logs()
        for label in ("Scheduled tasks", "Queue workers", "Object cache"):
            self.assertIn(label, page)
        self.assertIn("Not configured.", page)
        self.assertEqual(LogRead.objects.count(), 0)

    def test_a_laravel_site_lists_queue_workers_and_a_wordpress_site_does_not(self) -> None:
        record_background_site(self.server, application="laravel", workers=2, cache="on")
        page = self.logs()
        for label in ("Scheduled tasks", "Queue workers", "Object cache"):
            self.assertIn(label, page)
        record_background_site(self.server, application="wordpress", scheduled=True)
        wordpress = self.logs()
        self.assertIn("Scheduled tasks", wordpress)
        self.assertNotIn("Queue workers", wordpress)

    def test_reading_a_journal_is_an_explicit_post_and_no_get_queues(self) -> None:
        record_background_site(self.server, application="laravel", workers=1)
        self.logs("?log=queue_workers")
        self.assertEqual(LogRead.objects.count(), 0)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/read/",
            {"source": "queue_workers"},
        )
        self.assertRedirects(
            response, f"/servers/{self.server.pk}/sites/alpha/logs/?log=queue_workers"
        )
        read = LogRead.objects.get()
        self.assertEqual(read.source, "queue_workers")
        self.assertEqual(read.cursor, "")

    def test_a_source_the_site_does_not_have_is_not_readable(self) -> None:
        record_log_site(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/read/",
            {"source": "object_cache"},
        )
        self.assertEqual(response.status_code, 404)

    def test_a_live_poll_queues_one_read_at_a_time_and_never_on_a_get(self) -> None:
        page = LogPage(
            "observed",
            (LogLine(raw="job started"),),
            newest="live:s=one",
            at_end=True,
        )
        record_background_site(self.server, application="laravel", workers=1, page=page)
        self.logs("?log=queue_workers&live=1")
        self.assertEqual(LogRead.objects.count(), 1)
        first = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/live/",
            {"source": "queue_workers"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(LogRead.objects.count(), 2)
        queued = LogRead.objects.get(status=RemoteOperation.Status.QUEUED)
        self.assertEqual(queued.cursor, "live:s=one")
        # While the read is active, another poll queues nothing.
        self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/live/",
            {"source": "queue_workers"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(LogRead.objects.count(), 2)

    def test_the_live_view_polls_only_while_visible_and_announces_new_lines(self) -> None:
        page = LogPage(
            "observed",
            (LogLine(raw="job started"),),
            newest="live:s=one",
            at_end=True,
        )
        record_background_site(
            self.server,
            application="laravel",
            workers=1,
            page=page,
            source="queue_workers",
        )
        page_html = self.logs("?log=queue_workers&live=1")
        self.assertIn("Following new lines while this page is visible.", page_html)
        self.assertIn("every 2s [document.visibilityState === 'visible']", page_html)
        self.assertIn('id="log-announcement"', page_html)
        self.assertIn('role="status"', page_html)
        self.assertNotIn("autofocus", page_html)

    def test_a_viewer_is_refused_a_live_poll(self) -> None:
        self.user.user_permissions.clear()
        self.grant("view_server", "view_siteobservation", "view_changes")
        record_background_site(self.server, application="laravel", workers=1)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/logs/live/",
            {"source": "queue_workers"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 403)

    def test_a_journal_canary_never_reaches_the_stored_page_or_the_response(self) -> None:
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        systemd = root / "systemd"
        systemd.mkdir()
        (systemd / "barectl-site-alpha-queue1.service").write_text("[Service]\n")
        private = root / "www" / "alpha" / "private"
        private.mkdir(parents=True)
        environment = private / "laravel.env"
        environment.write_text(f"APP_KEY=base64:{CANARY}\n")
        environment.chmod(0o600)

        def journal(
            units: Sequence[str], *, mode: str, cursor: str, since: str, until: str
        ) -> tuple[list[tuple[str, int, str]], bool]:
            return [("s=one", 1_793_000_000_000_000, f"worker printed {CANARY}")], True

        stored = read.read_page(
            "alpha",
            "queue_workers",
            root=str(root / "www"),
            systemd_root=str(systemd),
            cache_root=str(root / "valkey"),
            journal_entries=journal,
        )
        self.assertNotIn(CANARY, json.dumps(stored))
        page = LogPage.from_document(stored)
        if page is None:
            raise AssertionError("the journal page did not decode")
        record_background_site(self.server, application="laravel", workers=1, page=page)
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/?log=queue_workers")
        self.assertNotContains(response, CANARY)
        self.assertNotIn(CANARY, str(LogRead.objects.get().page))
