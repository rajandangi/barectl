from collections.abc import Mapping

from django import forms


class SitePhpForm(forms.Form):
    """The PHP version the site's Settings switches to, checked against the offered list."""

    selection = forms.ChoiceField(
        label="PHP version",
        choices=(),
        widget=forms.HiddenInput,
        error_messages={
            "required": "Choose another PHP version.",
            "invalid_choice": "Choose another PHP version from the current observation.",
        },
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[str, ...] = (),
        selected: str = "",
    ) -> None:
        super().__init__(data, initial={"selection": selected}, auto_id="id_site_php_%s")
        field = self.fields["selection"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [(entry, entry) for entry in choices]
