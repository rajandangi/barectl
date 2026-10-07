from typing import override

from django import forms

from bootstrap.models import Action
from bootstrap.php_supply import ELIGIBLE_BRANCHES
from sites import names as site_names

from . import binding

DRIVER_CHOICES = (
    (Action.PHP_MYSQL.value, Action.PHP_MYSQL.label),
    (Action.PHP_PGSQL.value, Action.PHP_PGSQL.label),
)
BINDING_CHOICES = tuple((spec.action.value, spec.engine.label) for spec in binding.ENGINES.values())
INSPECTION = Action.DATABASE_INSPECTION.value


class PrepareForm(forms.Form):
    action = forms.ChoiceField(choices=(*DRIVER_CHOICES, *BINDING_CHOICES, (INSPECTION, "")))


class DriverForm(forms.Form):
    php_version = forms.ChoiceField(
        label="PHP branch",
        required=False,
        choices=(("", "Ubuntu default"), *((branch, branch) for branch in ELIGIBLE_BRANCHES)),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    php_supply = forms.ChoiceField(
        label="PHP package supply",
        required=False,
        choices=(("ubuntu", "Ubuntu"), ("sury", "Reviewed unified PHP source")),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                self.fields[name].widget.attrs.update(
                    {
                        "class": "usa-select usa-input--error",
                        "aria-invalid": "true",
                        "aria-describedby": f"{self[name].auto_id}_error",
                    }
                )


class BindingForm(forms.Form):
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "autocomplete": "off", "spellcheck": "false"}
        ),
        help_text=(
            "The site whose Linux user s<identifier> becomes the database principal and names "
            "its database."
        ),
        error_messages={"required": "Enter a site identifier."},
    )

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
