from django import forms

from .models import Action


class PrepareForm(forms.Form):
    """The profile or maintenance action to prepare a plan for, and nothing else.

    Operators choose among the supported actions only: no package names, versions,
    commands or configuration can be submitted.
    """

    action = forms.ChoiceField(
        label="What to prepare",
        choices=Action.choices,
        error_messages={
            "required": "Choose what to prepare.",
            "invalid_choice": "Choose one of the supported profiles or actions.",
        },
    )
