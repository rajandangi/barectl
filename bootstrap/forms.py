from typing import override

from django import forms

from .actions import BUILT_IN
from .models import Action
from .php_supply import ELIGIBLE_BRANCHES


class PrepareForm(forms.Form):
    action = forms.ChoiceField(
        label="What to prepare",
        choices=[(value, label) for value, label in Action.choices if value in BUILT_IN],
        error_messages={
            "required": "Choose what to prepare.",
            "invalid_choice": "Choose one of the supported profiles or actions.",
        },
    )

    php_version = forms.ChoiceField(
        label="PHP branch (PHP profile only)",
        required=False,
        choices=[
            ("", "Ubuntu release default"),
            *((branch, branch) for branch in ELIGIBLE_BRANCHES),
        ],
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    php_supply = forms.ChoiceField(
        label="PHP supply (PHP profile only)",
        required=False,
        choices=[("ubuntu", "Ubuntu archive"), ("sury", "Approved unified PHP source")],
        initial="ubuntu",
        widget=forms.Select(attrs={"class": "usa-select"}),
    )

    @override
    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        supply = data.get("php_supply") or "ubuntu"
        data["php_supply"] = supply
        if data.get("action") != Action.PHP and (data.get("php_version") or supply != "ubuntu"):
            self.add_error("php_version", "PHP selection applies only to the PHP profile.")
        if data.get("action") == Action.PHP and supply == "sury" and not data.get("php_version"):
            self.add_error("php_version", "Choose an explicit PHP branch for the unified source.")
        return data

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in ("php_version", "php_supply"):
            if name in self.errors:
                widget = self.fields[name].widget
                widget.attrs["class"] = "usa-select usa-input--error"


class AcknowledgeForm(forms.Form):
    understood = forms.BooleanField(
        label=(
            "I understand that Barectl cannot tell whether this run changed the server, and "
            "that closing it does not mean nothing changed."
        ),
        error_messages={"required": "Confirm that you understand the outcome is unknown."},
    )
