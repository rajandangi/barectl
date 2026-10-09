"""An installed WordPress application as the maintenance actions' fixed reads and result
retrieval see it (docs/wordpress.md#maintaining-wordpress).

It is the inspection's simulated application, whose journal answers with the record the real
maintenance projection produces from fixed command outputs, so the workflow tests exercise the
production grammar end to end. The fake establishes nothing about real WP-CLI, MariaDB or
journald behaviour; ``test_maintenance_remote`` does.
"""

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import override

from . import maintenance_native
from .inspection_fakes import InspectionServer, Output
from .maintenance_models import Operation, RunWordpressMaintenance

REWRITE_OK: Output = (0, "Success: Rewrite rules flushed.\n", "")
REWRITE_EMPTY: Output = (
    0,
    "",
    (
        "Warning: Rewrite rules are empty, possibly because of a missing permalink_structure "
        "option. Use 'wp rewrite list' to verify, or 'wp rewrite structure' to update "
        "permalink_structure.\n"
    ),
)
CACHE_OK: Output = (0, "Success: The cache was flushed.\n", "")


def project(operation: str, flush: Output | None) -> str:
    """The record line the production projection prints for the flush command's output."""
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        if flush is not None:
            status, out, err = flush
            (base / "flush.rc").write_text(f"{status}\n")
            (base / "flush.out").write_text(out)
            (base / "flush.err").write_text(err)
        done = subprocess.run(  # noqa: S603 - the production projection on the tests' own files
            [sys.executable, "-I", "-c", maintenance_native.PROJECTION, directory, operation],
            capture_output=True,
            text=True,
            check=True,
        )
    return done.stdout.strip()


def default_record(operation: str) -> str:
    return project(operation, REWRITE_OK if operation == Operation.REWRITE else CACHE_OK)


class MaintenanceServer(InspectionServer):
    """The inspection's application whose journal holds maintenance records."""

    @override
    def record(self) -> str:
        operation = RunWordpressMaintenance.objects.get().operation
        return self.records.get(operation) or default_record(operation)
