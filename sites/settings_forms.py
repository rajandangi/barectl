"""Forms for one settings key action (Phase B #383).

Values are never asked for here: the review's confirm screen collects them into ADR 0032's
confidential channel.
"""

from django import forms

from operations.inputs import SETTING_KEY


class SettingsChangeForm(forms.Form):
    key = forms.CharField(
        max_length=64,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocapitalize": "characters"}
        ),
    )
    action = forms.ChoiceField(choices=(("set", "Set"), ("remove", "Remove")))

    def clean_key(self) -> str:
        value = str(self.cleaned_data["key"]).strip()
        if SETTING_KEY.fullmatch(value) is None:
            raise forms.ValidationError(
                "Use 1 to 64 uppercase letters, digits and underscores, starting with a letter."
            )
        return value
