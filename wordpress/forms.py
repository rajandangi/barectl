"""docs/wordpress.md#installation-review: the bounded metadata an installation review asks."""

from collections.abc import Sequence
from typing import override

from django import forms
from django.http import QueryDict

from . import inputs


class InstallForm(forms.Form):
    """The canonical name, title and administrator of one site's installation review.

    The form holds no password and no version: the password is generated on the server and
    the release is the reviewed pin.
    """

    prefix: str | None = "wordpress"

    canonical_name = forms.CharField(
        label="Canonical HTTPS name",
        max_length=200,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "autocomplete": "off", "spellcheck": "false"}
        ),
        help_text=(
            "One name the site's certificate covers, such as www.example.com. WordPress is "
            "installed at the root of this HTTPS address and the site's other names redirect "
            "to it."
        ),
        error_messages={"required": "Enter the canonical HTTPS name."},
    )
    title = forms.CharField(
        label="Site title",
        max_length=inputs.MAX_TITLE,
        strip=False,
        widget=forms.TextInput(attrs={"class": "usa-input"}),
        error_messages={"required": "Enter a site title."},
    )
    admin_login = forms.CharField(
        label="Administrator login",
        max_length=60,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "autocomplete": "off", "spellcheck": "false"}
        ),
        help_text="Lowercase letters, digits, dots, underscores or hyphens.",
        error_messages={"required": "Enter the administrator login."},
    )
    admin_email = forms.CharField(
        label="Administrator email",
        max_length=inputs.MAX_EMAIL,
        strip=True,
        widget=forms.EmailInput(attrs={"class": "usa-input", "autocomplete": "off"}),
        help_text=(
            "The account's address. Barectl sends no email: the first password is set in "
            "a terminal after installation."
        ),
        error_messages={"required": "Enter the administrator email."},
    )

    def __init__(
        self,
        data: QueryDict | None = None,
        *,
        names: Sequence[str] = (),
        initial: dict[str, str] | None = None,
        auto_id: str | bool = "id_wordpress_%s",
    ) -> None:
        super().__init__(data=data, initial=initial, prefix=self.prefix, auto_id=auto_id)
        self.names = tuple(names)

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs.get('class', '')} usa-input--error".strip()

    def clean_canonical_name(self) -> str:
        name, problem = inputs.https_name(self.cleaned_data["canonical_name"])
        if problem:
            raise forms.ValidationError(problem)
        if self.names and name not in self.names:
            raise forms.ValidationError(
                f"{name} is not one of the names this site serves: {', '.join(self.names)}."
            )
        return name

    def clean_title(self) -> str:
        title: str = self.cleaned_data["title"]
        problem = inputs.title_problem(title)
        if problem:
            raise forms.ValidationError(problem)
        return title

    def clean_admin_login(self) -> str:
        login: str = self.cleaned_data["admin_login"]
        problem = inputs.login_problem(login)
        if problem:
            raise forms.ValidationError(problem)
        return login

    def clean_admin_email(self) -> str:
        email: str = self.cleaned_data["admin_email"]
        problem = inputs.email_problem(email)
        if problem:
            raise forms.ValidationError(problem)
        return email

    def metadata(self) -> inputs.Metadata:
        data = self.cleaned_data
        return inputs.Metadata(
            data["canonical_name"], data["title"], data["admin_login"], data["admin_email"]
        )
