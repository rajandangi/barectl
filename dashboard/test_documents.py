"""The qualification records hold measured evidence, never placeholders."""

from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class QualificationRecordTests(SimpleTestCase):
    def test_a_qualification_record_has_no_placeholders(self) -> None:
        for path in sorted((Path(settings.BASE_DIR) / "docs").glob("phase-*-qualification.md")):
            with self.subTest(record=path.name):
                self.assertNotIn("TBD", path.read_text(encoding="utf-8"), path.name)
                self.assertNotIn("TODO", path.read_text(encoding="utf-8"), path.name)
