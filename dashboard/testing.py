import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import override

from playwright.sync_api import Page

# A fixed Vite manifest, so pages render without a production build.
TEST_MANIFEST = Path(__file__).resolve().parent / "testdata" / "manifest.json"


@contextmanager
def paused_progress_polls(page: Page) -> Iterator[None]:
    """docs/quality.md#native-browser-worker-polls"""
    handler = page.evaluate_handle("""() => {
        const pause = event => {
            const request = event.detail.ctx.request;
            const url = new URL(request.action, document.baseURI);
            if (request.method === 'GET' && (
                url.searchParams.has('shown') ||
                url.pathname.endsWith('/status/') ||
                url.pathname.endsWith('/discovery/')
            )) {
                event.preventDefault();
            }
        };
        document.addEventListener('htmx:before:request', pause);
        return pause;
    }""")
    try:
        yield
    finally:
        page.evaluate(
            "handler => document.removeEventListener('htmx:before:request', handler)", handler
        )
        handler.dispose()


class RecordedErrors(logging.Handler):
    """Keeps each error Django logs for a request, with its traceback."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(logging.ERROR)
        self.errors = errors

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.errors.append(logging.Formatter().format(record))
