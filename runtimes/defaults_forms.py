from collections.abc import Mapping

from django import forms


class DefaultRuntimeForm(forms.Form):
    selection = forms.ChoiceField(label="Installed runtime")

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[str, ...],
        selected: str = "",
        family: str,
    ) -> None:
        super().__init__(data, initial={"selection": selected}, auto_id=f"id_default_{family}_%s")
        self.fields["selection"] = forms.ChoiceField(
            label=f"Default {'PHP' if family == 'php' else 'Node.js'} runtime",
            choices=[(entry, entry) for entry in choices],
            widget=forms.Select(attrs={"class": "usa-select"}),
        )
