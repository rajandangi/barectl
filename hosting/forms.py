"""The ordinary site-creation form (docs/site-creation.md)."""

from typing import override

from django import forms

from sites import names as site_names
from wordpress import inputs

from .creation import CreationInput


class CreationForm(forms.Form):
    first_access_spki = forms.CharField(required=False, max_length=1024, widget=forms.HiddenInput)
    node_version = forms.ChoiceField(
        label="Node version",
        required=False,
        choices=(("", "No Node runtime"), ("24.21.0", "Node 24.21.0"), ("22.23.3", "Node 22.23.3")),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    domain = forms.CharField(
        label="Domain",
        max_length=site_names.MAX_NAME_OCTETS,
        widget=forms.TextInput(attrs={"class": "usa-input", "placeholder": "example.com"}),
    )
    application = forms.ChoiceField(
        choices=(("php", "PHP site"), ("wordpress", "WordPress")),
        widget=forms.HiddenInput,
    )
    discovery_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    title = forms.CharField(
        label="Site title",
        required=False,
        max_length=inputs.MAX_TITLE,
        widget=forms.TextInput(attrs={"class": "usa-input"}),
    )
    admin_login = forms.CharField(
        label="Administrator username",
        required=False,
        max_length=60,
        initial="admin",
        widget=forms.TextInput(attrs={"class": "usa-input"}),
    )
    admin_email = forms.EmailField(
        label="Administrator email",
        required=False,
        widget=forms.EmailInput(attrs={"class": "usa-input"}),
    )
    https = forms.BooleanField(
        label="Enable HTTPS",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
    )
    email = forms.EmailField(
        label="Certificate contact email",
        required=False,
        widget=forms.EmailInput(attrs={"class": "usa-input"}),
    )
    accept_agreement = forms.BooleanField(
        label="Accept the certificate authority agreement",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
    )
    php_version = forms.ChoiceField(
        label="PHP version",
        required=False,
        choices=(
            ("", "Use server default"),
            ("8.3", "PHP 8.3"),
            ("8.4", "PHP 8.4"),
            ("8.5", "PHP 8.5"),
        ),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    database_engine = forms.ChoiceField(
        label="Database",
        required=False,
        choices=(("", "No database"), ("mariadb", "MariaDB"), ("postgresql", "PostgreSQL")),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    aliases = forms.CharField(
        label="Additional domains",
        required=False,
        max_length=1000,
        widget=forms.Textarea(attrs={"class": "usa-textarea", "rows": 2}),
    )

    def clean_domain(self) -> str:
        domain, problem = site_names.canonical_name(self.cleaned_data["domain"])
        if problem:
            raise forms.ValidationError(problem)
        return domain

    @override
    def clean(self) -> dict[str, object]:
        cleaned = super().clean()
        if cleaned is None:
            return {}
        if cleaned.get("application") == "wordpress":
            self._clean_wordpress(cleaned)
        if cleaned.get("https"):
            if not cleaned.get("email"):
                self.add_error("email", "Enter the certificate contact email.")
            if not cleaned.get("accept_agreement"):
                self.add_error("accept_agreement", "Accept the agreement to enable HTTPS.")
        elif cleaned.get("email"):
            self.add_error("email", "Enable HTTPS to use a certificate contact.")
        try:
            cleaned["names"] = site_names.names(
                f"{cleaned.get('domain', '')}\n{cleaned.get('aliases', '')}"
            )
        except site_names.InvalidInput as invalid:
            self.add_error("aliases", forms.ValidationError(list(invalid.problems)))
        return cleaned

    def _clean_wordpress(self, cleaned: dict[str, object]) -> None:
        from wordpress.first_access import validate_key

        try:
            validate_key(str(cleaned.get("first_access_spki", "")))
        except ValueError as invalid:
            self.add_error(None, str(invalid))
        for field, check in (
            ("title", inputs.title_problem),
            ("admin_login", inputs.login_problem),
            ("admin_email", inputs.email_problem),
        ):
            problem = check(str(cleaned.get(field, "")))
            if problem:
                self.add_error(field, problem)
        cleaned["database_engine"] = "mariadb"
        cleaned["https"] = True
        cleaned["email"] = cleaned.get("admin_email", "")

    def intent(self) -> CreationInput:
        values = self.cleaned_data
        return CreationInput(
            names=values["names"],
            php_version=values["php_version"],
            discovery_revision=values["discovery_revision"],
            database_engine=values["database_engine"],
            https=values["https"],
            email=values["email"] if values["https"] else "",
            application=values["application"],
            title=values["title"],
            admin_login=values["admin_login"] if values["application"] == "wordpress" else "",
            admin_email=values["admin_email"],
            first_access_spki=values["first_access_spki"],
            node_version=values["node_version"],
        )
