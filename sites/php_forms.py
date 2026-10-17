from collections.abc import Mapping

from django import forms


class SitePhpForm(forms.Form):
    selection = forms.ChoiceField(
        label="PHP runtime", choices=(), widget=forms.Select(attrs={"class": "usa-select"})
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
            field.choices = [
                ("", "Choose an installed PHP runtime"),
                *((entry, f"PHP {entry[3]}.{entry[4]} ({entry})") for entry in choices),
            ]
