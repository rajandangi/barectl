from django.test import SimpleTestCase

from .forms import SiteForm
from .names import (
    MAX_NAME_OCTETS,
    InvalidInput,
    canonical_name,
    identifier_problems,
    names,
    request,
)


class IdentifierTests(SimpleTestCase):
    def test_lowercase_letters_and_digits_starting_with_a_letter(self) -> None:
        for identifier in ("abc", "shop2", "a" * 24):
            self.assertEqual(identifier_problems(identifier), [], identifier)
        for identifier in ("ab", "a" * 25, "Shop", "2shop", "sh-op", "sh_op", "shöp", " shop"):
            self.assertNotEqual(identifier_problems(identifier), [], identifier)

    def test_reserved_identifiers_are_refused(self) -> None:
        for identifier in ("www", "html", "default", "nginx", "php", "barectl", "acme"):
            self.assertIn("reserved", " ".join(identifier_problems(identifier)), identifier)
        # s + "shd" would be the sshd account; s + "yslog" the syslog account.
        for identifier in ("shd", "yslog", "tunnel4"):
            self.assertIn("reserved", " ".join(identifier_problems(identifier)), identifier)


class NameTests(SimpleTestCase):
    def test_case_and_one_terminal_dot_are_canonicalized(self) -> None:
        self.assertEqual(
            names("Shop.Example.COM. www.shop.example.com"),
            (
                "shop.example.com",
                "www.shop.example.com",
            ),
        )

    def test_whitespace_and_new_lines_separate_names(self) -> None:
        self.assertEqual(
            names("a.example\n b.example\tc.example"),
            (
                "a.example",
                "b.example",
                "c.example",
            ),
        )

    def refused(self, name: str, fragment: str) -> None:
        canonical, problem = canonical_name(name)
        self.assertEqual(canonical, "", name)
        self.assertIn(fragment, problem, name)

    def test_invalid_names_are_refused_with_their_reason(self) -> None:
        self.refused("shop.example..", "fully qualified")
        self.refused("shop..example", "fully qualified")
        self.refused("localhost", "fully qualified")
        self.refused("shop", "fully qualified")
        self.refused("*.example.com", "wildcards")
        self.refused("shop_1.example.com", "letters, digits")
        self.refused("shop~.example.com", "letters, digits")
        self.refused("$shop.example.com", "letters, digits")
        self.refused("-shop.example.com", "fully qualified")
        self.refused("192.0.2.10", "IP addresses")
        self.refused("[2001:db8::1]", "letters, digits")
        self.refused("2001:db8::1", "letters, digits")
        self.refused("app.localhost", "reserved")
        self.refused("app.invalid", "reserved")
        self.refused("bücher.example", "punycode")
        self.refused("ab--cd.example", "punycode")
        self.refused("xn--abc.example", "not valid punycode")

    def test_punycode_labels_must_round_trip(self) -> None:
        self.assertEqual(canonical_name("xn--bcher-kva.example")[0], "xn--bcher-kva.example")

    def test_names_are_bounded_at_forty_six_octets(self) -> None:
        """docs/sites.md#names: nginx's stock server_names_hash_bucket_size of 64."""
        longest = "a" * (MAX_NAME_OCTETS - len(".example")) + ".example"
        self.assertEqual(canonical_name(longest)[0], longest)
        self.refused("a" + longest, f"longer than {MAX_NAME_OCTETS}")

    def test_one_to_ten_distinct_names(self) -> None:
        ten = " ".join(f"n{index}.example.com" for index in range(10))
        self.assertEqual(len(names(ten)), 10)
        with self.assertRaises(InvalidInput) as raised:
            names(f"{ten} n10.example.com")
        self.assertIn("at most 10", str(raised.exception))
        with self.assertRaises(InvalidInput) as raised:
            names(" \n ")
        self.assertIn("at least one", str(raised.exception))
        with self.assertRaises(InvalidInput) as raised:
            names("shop.example.com SHOP.example.com.")
        self.assertIn("more than once", str(raised.exception))

    def test_a_request_reports_every_problem(self) -> None:
        with self.assertRaises(InvalidInput) as raised:
            request("Shop", "*.example.com 192.0.2.1")
        self.assertEqual(len(raised.exception.problems), 3)
        self.assertEqual(request("shop", "shop.example.com"), ("shop", ("shop.example.com",)))


class FormTests(SimpleTestCase):
    def test_the_form_returns_canonical_names(self) -> None:
        form = SiteForm({"identifier": "shop", "names": "Shop.Example.com."})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["names"], ("shop.example.com",))

    def test_the_form_reports_each_problem_on_its_field(self) -> None:
        form = SiteForm({"identifier": "www", "names": "*.example.com"})
        self.assertFalse(form.is_valid())
        self.assertIn("reserved", form.errors["identifier"][0])
        self.assertIn("wildcards", form.errors["names"][0])
        self.assertIn("usa-input--error", str(form["names"]))
