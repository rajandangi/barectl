from collections.abc import Mapping

from django import forms


class RollbackForm(forms.Form):
    """Choose one retained release to reactivate."""

    release = forms.ChoiceField(
        label="Release",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[str, ...] = (),
        selected: str = "",
    ) -> None:
        super().__init__(data, initial={"release": selected}, auto_id="id_site_rollback_%s")
        field = self.fields["release"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [("", "Choose a retained release"), *((name, name) for name in choices)]
