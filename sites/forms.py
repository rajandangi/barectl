import re
from collections.abc import Mapping
from typing import override

from django import forms

from laravel import configuration as laravel_configuration

from . import names as site_names


class HttpSiteForm(forms.Form):
    names = forms.CharField(
        label="DNS names",
        widget=forms.Textarea(
            attrs={
                "class": "usa-textarea",
                "rows": 3,
                "spellcheck": "false",
                "data-site-names": "",
            }
        ),
        max_length=2540,
        help_text=(
            f"Enter the primary domain first, followed by up to {site_names.MAX_NAMES - 1} "
            "aliases, separated by spaces or new lines. Each name may have up to "
            f"{site_names.MAX_NAME_OCTETS} characters. Use punycode for international names. "
            "No wildcards or IP addresses."
        ),
        error_messages={"required": "Enter at least one DNS name."},
    )
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "autocomplete": "off",
                "spellcheck": "false",
                "data-site-identifier": "",
            }
        ),
        help_text=(
            "An editable name derived from the primary domain. Use 3 to 24 lowercase "
            "letters and digits, starting with a letter."
        ),
        error_messages={"required": "Enter a site identifier."},
    )
    php_version = forms.ChoiceField(
        label="PHP runtime",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
        help_text=(
            "Choose an installed runtime whose master was verified in the recorded "
            "observation. A fresh review checks it again."
        ),
        error_messages={
            "required": (
                "Choose an installed PHP runtime. Add one from Stack if none is available."
            ),
            "invalid_choice": (
                "This PHP runtime is unavailable in the current recorded observation. "
                "Refresh the observation and choose again."
            ),
        },
    )
    http_only = forms.BooleanField(
        label="Serve over HTTP only",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
        help_text=(
            "Leave off to serve the site over HTTPS with a certificate Caddy issues and "
            "renews. Turn this on only for a test site before DNS points here."
        ),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        php_versions: tuple[str, ...] = (),
        initial: dict[str, str] | None = None,
    ) -> None:
        super().__init__(data, initial=initial, auto_id="id_http_site_%s")
        field = self.fields["php_version"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose a verified PHP runtime"),
                *((entry, f"PHP {entry[3]}.{entry[4]} ({entry})") for entry in php_versions),
            ]

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

    def clean_names(self) -> tuple[str, ...]:
        try:
            return site_names.names(self.cleaned_data["names"])
        except site_names.InvalidInput as invalid:
            raise forms.ValidationError(list(invalid.problems)) from None


def _derive_identifier(domain: str) -> str:
    """The identifier the create form derives from the primary domain and lets the operator
    edit under More options (the same rule as ``frontend/site-identifier.ts``)."""
    value = domain.lower().removeprefix("www.").split(".")[0]
    value = re.sub(r"[^a-z0-9]", "", value)[:24]
    if value and not value[0].isalpha():
        value = ("site" + value)[:24]
    if value and len(value) < 3:
        value += "site"
    return value


class LaravelSiteForm(forms.Form):
    """Create a Laravel site: its domain, its Git repository and a branch or tag."""

    names = forms.CharField(
        label="Primary domain",
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "spellcheck": "false",
                "autocomplete": "off",
                "data-site-names": "",
            }
        ),
        max_length=2540,
        help_text=(
            "The site's primary domain. Use punycode for international names. No wildcards "
            "or IP addresses."
        ),
        error_messages={"required": "Enter the site's primary domain."},
    )
    repository = forms.CharField(
        label="Repository",
        max_length=512,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text=(
            "A credential-free https:// URL or an SSH locator such as "
            "git@github.com:acme/shop.git. Public repositories need no credentials; a "
            "private SSH repository gets a deploy key generated on the server."
        ),
        error_messages={"required": "Enter the repository URL or SSH locator."},
    )
    branch = forms.CharField(
        label="Branch or tag",
        max_length=255,
        initial="main",
        strip=True,
        required=False,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text="The branch or tag Deploy resolves to an exact commit. Defaults to main.",
    )
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "autocomplete": "off",
                "spellcheck": "false",
                "data-site-identifier": "",
            }
        ),
        help_text=(
            "An editable name derived from the primary domain. Use 3 to 24 lowercase "
            "letters and digits, starting with a letter."
        ),
    )
    php_version = forms.ChoiceField(
        label="PHP runtime",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
        help_text=(
            "Choose an installed runtime whose master was verified in the recorded "
            "observation. Laravel 13 runs on PHP 8.4 and 8.5."
        ),
        error_messages={
            "required": (
                "Choose an installed PHP runtime. Add one from Stack if none is available."
            ),
            "invalid_choice": (
                "This PHP runtime is unavailable in the current recorded observation. "
                "Refresh the observation and choose again."
            ),
        },
    )
    fingerprint = forms.CharField(
        label="Repository host key fingerprint",
        max_length=64,
        strip=True,
        required=False,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text=(
            "For an SSH repository, paste the SHA256 host key fingerprint from your Git "
            "host's documentation. The repository host is trusted only when it matches "
            "exactly."
        ),
    )
    http_only = forms.BooleanField(
        label="Serve over HTTP only",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
        help_text=(
            "Leave off to serve the site over HTTPS with a certificate Caddy issues and "
            "renews. Turn this on only for a test site before DNS points here."
        ),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        php_versions: tuple[str, ...] = (),
        initial: dict[str, str] | None = None,
    ) -> None:
        super().__init__(data, initial=initial, auto_id="id_laravel_site_%s")
        field = self.fields["php_version"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose a verified PHP runtime"),
                *((entry, f"PHP {entry[3]}.{entry[4]} ({entry})") for entry in php_versions),
            ]

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"

    def clean_identifier(self) -> str:
        identifier: str = self.cleaned_data["identifier"]
        if not identifier:
            names = self.cleaned_data.get("names")
            if not names:
                return ""
            return _derive_identifier(str(names[0]))
        problems = site_names.identifier_problems(identifier)
        if problems:
            raise forms.ValidationError(problems)
        return identifier

    def clean_names(self) -> tuple[str, ...]:
        try:
            return site_names.names(self.cleaned_data["names"])
        except site_names.InvalidInput as invalid:
            raise forms.ValidationError(list(invalid.problems)) from None

    def clean_repository(self) -> str:
        try:
            return laravel_configuration.repository_locator(self.cleaned_data["repository"])
        except ValueError as error:
            raise forms.ValidationError(str(error)) from None

    def clean_branch(self) -> str:
        try:
            return laravel_configuration.repository_ref(self.cleaned_data["branch"] or "main")
        except ValueError as error:
            raise forms.ValidationError(str(error)) from None

    @override
    def clean(self) -> dict[str, object]:
        cleaned = dict(super().clean() or {})
        repository = cleaned.get("repository")
        fingerprint = cleaned.get("fingerprint", "")
        if not isinstance(repository, str) or not repository:
            return cleaned
        ssh = not repository.startswith("https://")
        if ssh and not fingerprint:
            self.add_error(
                "fingerprint",
                "Paste your Git host's SSH host key fingerprint so the repository host "
                "is trusted only when it matches exactly.",
            )
        elif fingerprint and not ssh:
            self.add_error(
                "fingerprint",
                "An https:// repository authenticates its host with TLS; leave the "
                "fingerprint empty.",
            )
        elif fingerprint and not laravel_configuration.valid_fingerprint(str(fingerprint)):
            self.add_error(
                "fingerprint",
                "Enter the SHA256: fingerprint exactly as your Git host shows it, such as "
                "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s.",
            )
        return cleaned


class WordPressSiteForm(forms.Form):
    """Create a WordPress site: its domain, title, administrator and PHP runtime.

    The administrator password is asked for on the confirm screen, through the confidential
    input channel, so its ten-minute lifetime covers only the apply (Phase B #380).
    """

    names = forms.CharField(
        label="Primary domain",
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "spellcheck": "false",
                "autocomplete": "off",
                "data-site-names": "",
            }
        ),
        max_length=2540,
        help_text=(
            "The site's primary domain. Use punycode for international names. No wildcards "
            "or IP addresses."
        ),
        error_messages={"required": "Enter the site's primary domain."},
    )
    title = forms.CharField(
        label="Site title",
        max_length=200,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text="The WordPress site title, shown to visitors and in the dashboard.",
        error_messages={"required": "Enter the site's title."},
    )
    admin_username = forms.CharField(
        label="Administrator username",
        max_length=60,
        strip=True,
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text="The first WordPress administrator. Letters, digits, dots, @, - and _.",
        error_messages={"required": "Enter the administrator username."},
    )
    admin_email = forms.EmailField(
        label="Administrator email",
        max_length=100,
        widget=forms.EmailInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text="WordPress sends no email during installation; this address is stored.",
        error_messages={"required": "Enter the administrator email."},
    )
    identifier = forms.CharField(
        label="Site identifier",
        max_length=24,
        strip=True,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "usa-input",
                "autocomplete": "off",
                "spellcheck": "false",
                "data-site-identifier": "",
            }
        ),
        help_text=(
            "An editable name derived from the primary domain. Use 3 to 24 lowercase "
            "letters and digits, starting with a letter."
        ),
    )
    php_version = forms.ChoiceField(
        label="PHP runtime",
        choices=(),
        widget=forms.Select(attrs={"class": "usa-select"}),
        help_text=(
            "Choose an installed runtime whose master was verified in the recorded "
            "observation. WordPress runs on PHP 8.4 and 8.5."
        ),
        error_messages={
            "required": (
                "Choose an installed PHP runtime. Add one from Stack if none is available."
            ),
            "invalid_choice": (
                "This PHP runtime is unavailable in the current recorded observation. "
                "Refresh the observation and choose again."
            ),
        },
    )
    http_only = forms.BooleanField(
        label="Serve over HTTP only",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "usa-checkbox__input"}),
        help_text=(
            "Leave off to serve the site over HTTPS with a certificate Caddy issues and "
            "renews. Turn this on only for a test site before DNS points here."
        ),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        php_versions: tuple[str, ...] = (),
        initial: dict[str, str] | None = None,
    ) -> None:
        super().__init__(data, initial=initial, auto_id="id_wordpress_site_%s")
        field = self.fields["php_version"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose a verified PHP runtime"),
                *((entry, f"PHP {entry[3]}.{entry[4]} ({entry})") for entry in php_versions),
            ]

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"

    def clean_identifier(self) -> str:
        identifier: str = self.cleaned_data["identifier"]
        if not identifier:
            names = self.cleaned_data.get("names")
            if not names:
                return ""
            return _derive_identifier(str(names[0]))
        problems = site_names.identifier_problems(identifier)
        if problems:
            raise forms.ValidationError(problems)
        return identifier

    def clean_names(self) -> tuple[str, ...]:
        try:
            return site_names.names(self.cleaned_data["names"])
        except site_names.InvalidInput as invalid:
            raise forms.ValidationError(list(invalid.problems)) from None

    def clean_admin_username(self) -> str:
        username: str = self.cleaned_data["admin_username"]
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,60}", username):
            raise forms.ValidationError(
                "Use 1 to 60 letters, digits, dots, @ signs, hyphens or underscores."
            )
        return username


class SiteReadinessForm(forms.Form):
    readiness = forms.CharField(
        label="Readiness path",
        max_length=site_names.MAX_READINESS_PATH,
        strip=True,
        initial="/",
        widget=forms.TextInput(
            attrs={"class": "usa-input", "spellcheck": "false", "autocomplete": "off"}
        ),
        help_text=(
            "Barectl requests this path from the site after a change. The default / accepts "
            "any answer below a server error; a path you choose must answer 200."
        ),
        error_messages={"required": "Enter a readiness path, or / for the home page."},
    )

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"

    def clean_readiness(self) -> str:
        path, problem = site_names.readiness_path(self.cleaned_data["readiness"])
        if problem:
            raise forms.ValidationError(problem)
        return path


class SiteNodeForm(forms.Form):
    selection = forms.ChoiceField(
        label="Node runtime", choices=(), widget=forms.Select(attrs={"class": "usa-select"})
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[str, ...] = (),
        selected: str = "",
    ) -> None:
        super().__init__(data, initial={"selection": selected}, auto_id="id_site_node_%s")
        field = self.fields["selection"]
        if isinstance(field, forms.ChoiceField):
            field.choices = [
                ("", "Choose an installed Node runtime"),
                *((entry, entry) for entry in choices),
            ]
