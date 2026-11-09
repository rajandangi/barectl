"""The qualification records hold measured evidence, never placeholders."""

import ast
import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

TEST_REFERENCE = re.compile(
    r"`((?:disposable|operations|dashboard|sites|servers|security|backups|automation|"
    r"discovery|jobs|runtimes|wordpress|laravel|databases|cache|logs|bootstrap|contract)\."
    r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)`"
)


class QualificationRecordTests(SimpleTestCase):
    def test_a_qualification_record_has_no_placeholders(self) -> None:
        for path in sorted((Path(settings.BASE_DIR) / "docs").glob("phase-*-qualification.md")):
            with self.subTest(record=path.name):
                self.assertNotIn("TBD", path.read_text(encoding="utf-8"), path.name)
                self.assertNotIn("TODO", path.read_text(encoding="utf-8"), path.name)


class RecoveryGuaranteeMatrixTests(SimpleTestCase):
    def test_every_matrix_row_names_an_existing_test_and_a_non_promise(self) -> None:
        path = Path(settings.BASE_DIR) / "docs" / "recovery-guarantees.md"
        table = path.read_text(encoding="utf-8").split("## Matrix\n", 1)[1].split("\n## ", 1)[0]
        rows = [
            line
            for line in table.splitlines()
            if line.startswith("|") and not set(line) <= {"|", "-", " "}
        ]
        body = rows[1:]
        self.assertGreaterEqual(len(body), 8, "The matrix body was not parsed.")
        for row in body:
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            self.assertEqual(len(cells), 4, row)
            references = TEST_REFERENCE.findall(cells[1])
            self.assertTrue(references, f"A matrix row names no test: {cells[0]}")
            self.assertTrue(cells[3], f"A matrix row names no non-promise: {cells[0]}")
            for reference in references:
                with self.subTest(test=reference):
                    self.assert_test_exists(reference)

    def assert_test_exists(self, reference: str) -> None:
        module_name, class_name, method_name = reference.rsplit(".", 2)
        source = Path(settings.BASE_DIR).joinpath(*module_name.split(".")).with_suffix(".py")
        self.assertTrue(source.is_file(), f"{reference} names no module file.")
        tree = ast.parse(source.read_text(encoding="utf-8"))
        classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
        self.assertIn(class_name, classes, f"{reference} names no test class.")
        methods = {
            node.name
            for node in classes[class_name].body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn(method_name, methods, f"{reference} names no test method.")
