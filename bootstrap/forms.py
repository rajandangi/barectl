from django import forms

from .models import Action


class PrepareForm(forms.Form):
    action = forms.ChoiceField(
        label="What to prepare",
        choices=Action.choices,
        error_messages={
            "required": "Choose what to prepare.",
            "invalid_choice": "Choose one of the supported profiles or actions.",
        },
    )


class AcknowledgeForm(forms.Form):
    understood = forms.BooleanField(
        label=(
            "I understand that Barectl cannot tell whether this run changed the server, and "
            "that closing it does not mean nothing changed."
        ),
        error_messages={"required": "Confirm that you understand the outcome is unknown."},
    )
