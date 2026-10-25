from collections.abc import Mapping

from django import forms

from .presentation import runtime_label


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
            label=f"Default {'PHP' if family == 'php' else 'Node.js'} version",
            choices=[(entry, runtime_label(entry)) for entry in choices],
            widget=forms.Select(attrs={"class": "usa-select"}),
        )
