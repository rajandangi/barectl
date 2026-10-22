"""The WordPress actions' forms (Phase B #381).

The new administrator password is not asked for here: it is typed on the review's confirm
screen and reaches the server only over the confidential input channel (ADR 0032).
"""

from django import forms

from .convention import ADMIN_USERNAME


class WordPressPasswordForm(forms.Form):
    """Reset one WordPress administrator's password."""

    admin_username = forms.CharField(
        label="Administrator username",
        max_length=60,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "spellcheck": "false",
                "autocomplete": "username",
            }
        ),
        help_text="The WordPress administrator whose password will be reset.",
        error_messages={"required": "Enter the administrator username."},
    )

    def clean_admin_username(self) -> str:
        value = str(self.cleaned_data["admin_username"])
        if ADMIN_USERNAME.fullmatch(value) is None:
            raise forms.ValidationError(
                "Use 1 to 60 letters, digits, dots, @, - and _ with no spaces."
            )
        return value
