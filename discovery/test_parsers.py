"""The bounded Nginx tokenizer and declared-name extraction.

docs/ssh-connections.md#site-observations
"""

from django.test import SimpleTestCase

from .observations.parsers import declared_server_names


class DeclaredServerNamesTests(SimpleTestCase):
    def test_server_block_names_are_read_in_order_and_deduplicated(self) -> None:
        text = (
            "server {\n"
            "  listen 80;\n"
            "  server_name alpha.test www.alpha.test;\n"
            "}\n"
            "server {\n"
            "  server_name beta.test alpha.test;\n"
            "}\n"
        )
        self.assertEqual(declared_server_names(text), ("alpha.test", "www.alpha.test", "beta.test"))

    def test_only_server_blocks_contribute_names(self) -> None:
        text = (
            "server_name outside.test;\n"
            "http {\n  server_name http.test;\n}\n"
            "server {\n  server_name inside.test;\n}\n"
        )
        self.assertEqual(declared_server_names(text), ("inside.test",))

    def test_a_file_without_server_names_declares_none(self) -> None:
        self.assertEqual(declared_server_names("upstream backend { server 10.0.0.1:80; }\n"), ())
        self.assertEqual(declared_server_names("server { listen 80; }\n"), ())

    def test_unsupported_text_is_not_interpreted(self) -> None:
        for text in (
            "server {\n  server_name alpha.test;\n",
            "server { server_name alpha.test; } trailing",
            "server {\n  server_name alpha.test # comment\n}\n",
        ):
            with self.subTest(text=text):
                self.assertIsNone(declared_server_names(text))

    def test_quoted_names_lose_their_quotes(self) -> None:
        self.assertEqual(
            declared_server_names('server {\n  server_name "alpha.test";\n}\n'),
            ("alpha.test",),
        )
