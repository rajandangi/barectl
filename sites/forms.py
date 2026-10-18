from collections.abc import Mapping
from typing import override

from django import forms

from . import names as site_names


class HttpSiteForm(forms.Form):
    names = forms.CharField(
        label="DNS names",
        widget=forms.Textarea(
            attrs={
                "class": "usa-textarea",
                "rows": 3,
                "spellcheck": "false",
                "data-site-names": "",
            }
        ),
        max_length=2540,
        help_text=(
            f"Enter the primary domain first, followed by up to {site_names.MAX_NAMES - 1} "
            "aliases, separated by spaces or new lines. Each name may have up to "
            f"{site_names.MAX_NAME_OCTETS} characters. Use punycode for international names. "
            "No wildcards or IP addresses."
        ),
        error_messages={"required": "Enter at least one DNS name."},
    )
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "autocomplete": "off",
                "spellcheck": "false",
                "data-site-identifier": "",
            }
        ),
        help_text=(
            "An editable name derived from the primary domain. Use 3 to 24 lowercase "
            "letters and digits, starting with a letter."
        ),
        error_messages={"required": "Enter a site identifier."},
    )
    php_version = forms.ChoiceField(
        label="PHP runtime",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
        help_text=(
            "Choose an installed runtime whose master was verified in the recorded "
            "observation. A fresh review checks it again."
        ),
        error_messages={
            "required": (
                "Choose an installed PHP runtime. Add one from Stack if none is available."
            ),
            "invalid_choice": (
                "This PHP runtime is unavailable in the current recorded observation. "
                "Refresh the observation and choose again."
            ),
        },
    )
    http_only = forms.BooleanField(
        label="Serve over HTTP only",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
        help_text=(
            "Leave off to serve the site over HTTPS with a certificate Caddy issues and "
            "renews. Turn this on only for a test site before DNS points here."
        ),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        php_versions: tuple[str, ...] = (),
        initial: dict[str, str] | None = None,
    ) -> None:
        super().__init__(data, initial=initial, auto_id="id_http_site_%s")
        field = self.fields["php_version"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose a verified PHP runtime"),
                *((entry, f"PHP {entry[3]}.{entry[4]} ({entry})") for entry in php_versions),
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


class SiteNodeForm(forms.Form):
    selection = forms.ChoiceField(
        label="Node runtime", choices=(), widget=forms.Select(attrs={"class": "usa-select"})
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[str, ...] = (),
        selected: str = "",
    ) -> None:
        super().__init__(data, initial={"selection": selected}, auto_id="id_site_node_%s")
        field = self.fields["selection"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose an installed Node runtime"),
                *((entry, entry) for entry in choices),
            ]
