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


class DeploySettingsForm(forms.Form):
    """The site's Deploy switch: whether pending migrations run during a Deploy."""

    run_migrations = forms.BooleanField(
        label="Run pending migrations during Deploy",
        help_text=(
            "When off, a Deploy reports the migrations it finds in the run's journal "
            "and does not run them."
        ),
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
    )

    def __init__(
        self, data: Mapping[str, str] | None = None, *, run_migrations: bool = True
    ) -> None:
        super().__init__(data, initial={"run_migrations": run_migrations}, auto_id="id_deploy_%s")
