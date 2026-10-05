from typing import override

from django import forms
from django.http import QueryDict

from servers.models import Server
from sites import names as site_names

from . import readiness


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
                widget.attrs["class"] = f"{widget.attrs.get('class', '')} usa-input--error".strip()

    def clean_identifier(self) -> str:
        identifier: str = self.cleaned_data["identifier"]
        problems = site_names.identifier_problems(identifier)
        if problems:
            raise forms.ValidationError(problems)
        return identifier


class ReadinessForm(ChallengeForm):
    """One site identifier; the review reads and changes nothing."""

    prefix: str | None = "readiness"


class ActivationForm(ChallengeForm):
    """The activation's site identifier; the review shows the lineage and candidates."""

    prefix: str | None = "activation"


class IssuanceForm(ChallengeForm):
    """The order's site, its contact address and the terms' acceptance.

    docs/tls.md#issuance: the production authority is the one Barectl's settings name, so
    the review shows it instead of offering a choice.
    """

    prefix: str | None = "issuance"

    email = forms.EmailField(
        label="Contact address",
        max_length=254,
        widget=forms.EmailInput(attrs={"class": "usa-input"}),
        help_text=(
            "The production account registers with this address; the authority's expiry and "
            "order notices go there. It is stored with the plan and never with a private key."
        ),
    )


class StagingForm(ChallengeForm):
    """The order's site, its contact address, the authority and the terms' acceptance."""

    prefix: str | None = "staging"

    email = forms.EmailField(
        label="Contact address",
        max_length=254,
        widget=forms.EmailInput(attrs={"class": "usa-input"}),
        help_text=(
            "The staging account registers with this address; the authority's expiry and "
            "order notices go there. It is stored with the plan and never with a private key."
        ),
    )
    authority = forms.ChoiceField(
        label="Authority",
        choices=[],
        help_text="The allowlisted authority the order is reviewed against.",
    )

    def __init__(self, data: QueryDict | None = None, prefix: str | None = None) -> None:
        super().__init__(data=data, prefix=prefix or self.prefix)
        authorities = readiness.authorities()
        authority = self.fields["authority"]
        if isinstance(authority, forms.ChoiceField):
            authority.choices = [(entry["directory"], entry["name"]) for entry in authorities]
            if len(authorities) == 1:
                authority.initial = authorities[0]["directory"]
                authority.widget = forms.HiddenInput()

    def clean_authority(self) -> str:
        directory: str = self.cleaned_data["authority"]
        if readiness.authority_of(directory) is None:
            raise forms.ValidationError("Choose a listed authority.")
        return directory


class InstallationContactForm(forms.Form):
    """docs/tls.md#create-and-install: the observation revision the page showed and the email."""

    snapshot = forms.IntegerField(widget=forms.HiddenInput())
    email = forms.EmailField(
        label="Contact email",
        max_length=254,
        widget=forms.EmailInput(attrs={"class": "usa-input", "autocomplete": "email"}),
        help_text="The authority's expiry and order notices go to this address.",
    )

    def __init__(self, server: Server, data: QueryDict | None = None) -> None:
        from .installation import available_sites

        super().__init__(data=data, prefix="installation")
        self.available = available_sites(server)
        self.fields["snapshot"].initial = self.available.revision


class SiteInstallationForm(InstallationContactForm):
    """The site comes from the page; only the email is typed."""


class InstallationForm(InstallationContactForm):
    """The server-wide form, with a choice of discovered site."""

    identifier = forms.ChoiceField(
        label="Site", choices=[], widget=forms.Select(attrs={"class": "usa-select"})
    )

    def __init__(self, server: Server, data: QueryDict | None = None) -> None:
        super().__init__(server, data)
        self.order_fields(["snapshot", "identifier", "email"])
        field = self.fields["identifier"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                (site.identifier, f"{site.identifier}: {', '.join(site.server_names)}")
                for site in self.available.sites
            ]
