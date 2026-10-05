import logging
from pathlib import Path
from typing import override

# A fixed Vite manifest, so pages render without a production build.
TEST_MANIFEST = Path(__file__).resolve().parent / "testdata" / "manifest.json"


class RecordedErrors(logging.Handler):
    """Keeps each error Django logs for a request, with its traceback."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(logging.ERROR)
        self.errors = errors

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.errors.append(logging.Formatter().format(record))
