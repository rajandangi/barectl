"""The catalog update body names its realisation step when realisation stops (#495, #501)."""

from contextlib import redirect_stdout
from io import StringIO
from unittest import mock

from django.test import SimpleTestCase

from operations import engine

from .bodies import update


class CatalogUpdateBodyTests(SimpleTestCase):
    def test_a_realisation_failure_reports_the_realisation_step(self) -> None:
        document: dict[str, object] = {
            "states": {},
            "entries": [
                {
                    "entry": "nodejs_22",
                    "kind": "node",
                    "from": "/nix/store/old",
                    "to": "/nix/store/new",
                }
            ],
        }
        output = StringIO()
        with (
            mock.patch.object(update, "profile_path", return_value="/nix/store/old"),
            mock.patch.object(update, "realise", side_effect=OSError("cache unreachable")),
            redirect_stdout(output),
        ):
            update.update_catalog(document)

        line = engine.parse_result_line(output.getvalue())
        self.assertIsNotNone(line)
        if line is None:
            self.fail("The update body printed no result line.")
        self.assertEqual((line.result_class, line.reason), ("refused", "runtime_realise"))
