from typing import override

from django import forms

from sites import names as site_names


class ChallengeForm(forms.Form):
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "autocomplete": "off", "spellcheck": "false"}
        ),
        help_text="The identifier of an existing site that follows the convention.",
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
