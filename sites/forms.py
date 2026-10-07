from collections.abc import Mapping
from typing import override

from django import forms

from . import names as site_names


class SiteForm(forms.Form):
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "autocomplete": "off", "spellcheck": "false"}
        ),
        help_text=(
            "3 to 24 lowercase letters and digits, starting with a letter. It names the site "
            "user s<identifier>, /var/www/<identifier> and the pool."
        ),
        error_messages={"required": "Enter a site identifier."},
    )
    names = forms.CharField(
        label="DNS names",
        widget=forms.Textarea(attrs={"class": "usa-textarea", "rows": 3, "spellcheck": "false"}),
        max_length=1000,
        help_text=(
            f"1 to {site_names.MAX_NAMES} names, separated by spaces or new lines, each at most "
            f"{site_names.MAX_NAME_OCTETS} characters. Enter international names in their punycode "
            "(xn--) form. No wildcards or IP addresses."
        ),
        error_messages={"required": "Enter at least one DNS name."},
    )

    php_version = forms.ChoiceField(
        label="PHP branch",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
        help_text=(
            "Choose an installed PHP-FPM branch from the recorded server observation. "
            "A fresh review checks its packages, service and qualification."
        ),
        error_messages={
            "required": (
                "Choose an installed PHP branch. Refresh the connection if no branches "
                "are available."
            ),
            "invalid_choice": (
                "This PHP branch is unavailable in the current recorded observation. "
                "Refresh the connection and choose again."
            ),
        },
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        php_versions: tuple[str, ...] = (),
        initial: dict[str, str] | None = None,
        auto_id: str = "id_%s",
    ) -> None:
        super().__init__(data, initial=initial, auto_id=auto_id)
        field = self.fields["php_version"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose an installed PHP branch"),
                *((version, f"PHP {version}") for version in php_versions),
            ]

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"

    def clean_identifier(self) -> str:
        identifier: str = self.cleaned_data["identifier"]
        problems = site_names.identifier_problems(identifier)
        if problems:
            raise forms.ValidationError(problems)
        return identifier

    def clean_names(self) -> tuple[str, ...]:
        try:
            return site_names.names(self.cleaned_data["names"])
        except site_names.InvalidInput as invalid:
            raise forms.ValidationError(list(invalid.problems)) from None
