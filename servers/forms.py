from typing import TYPE_CHECKING, ClassVar, override

from django import forms
from django.http import QueryDict

from .connections import normalize_address, saved_alias, validate_username
from .models import Server
from .ssh_config import AliasCatalog

if TYPE_CHECKING:
    ServerFormBase = forms.ModelForm[Server]
else:
    ServerFormBase = forms.ModelForm


class ServerSearchForm(forms.Form):
    q = forms.CharField(label="Search servers", required=False, max_length=100)


class ServerForm(ServerFormBase):
    """docs/ssh-aliases.md#revalidation"""

    class Meta:
        model = Server
        fields: ClassVar[list[str]] = ["name", "address", "username", "port", "ssh_alias"]
        labels: ClassVar[dict[str, str]] = {"name": "Name", "username": "SSH user"}
        help_texts: ClassVar[dict[str, str]] = {
            "name": "Shown in Barectl only. It does not change the server.",
            "address": "ASCII host name, IPv4 or IPv6 address. No URL or port. Ubuntu 26.04 only.",
            "username": "Use root or an account with passwordless sudo.",
        }
        widgets: ClassVar[dict[str, forms.Widget]] = {
            "name": forms.TextInput(attrs={"class": "usa-input"})
        }
        error_messages: ClassVar[dict[str, dict[str, str]]] = {
            "name": {
                "required": "Enter a name for this server.",
                "unique": "Another server already uses this name.",
            }
        }

    @override
    def __init__(
        self,
        data: QueryDict | None = None,
        *,
        instance: Server | None = None,
        catalog: AliasCatalog,
    ) -> None:
        super().__init__(data, instance=instance)
        if instance is not None and instance.connection_mode != "alias":
            self.initial["ssh_alias"] = ""
        for field in ("address", "username", "port"):
            self.fields[field].widget.attrs["class"] = "usa-input"
        self.fields["username"].required = False
        self.fields["port"].required = False
        self.fields["ssh_alias"] = forms.ChoiceField(
            required=False,
            label="SSH alias",
            choices=[("", "- Select an alias -")] + [(a, a) for a in catalog.aliases],
            help_text=(
                f"Host entries from {catalog.source} on the controller host. "
                "Connection settings, keys and host trust stay there."
            ),
            widget=forms.Select(attrs={"class": "usa-select"}),
            error_messages={
                "required": "Choose the SSH alias for this server.",
                "invalid_choice": (
                    "Choose an alias that is currently configured on the controller host."
                ),
            },
        )

    def clean_address(self) -> str:
        value: str = self.cleaned_data.get("address", "")
        return normalize_address(value) if value else ""

    def clean_username(self) -> str:
        value: str = self.cleaned_data.get("username") or "root"
        validate_username(value)
        return value

    def clean_port(self) -> int:
        value = self.cleaned_data.get("port")
        value = 22 if value is None else int(value)
        if not 1 <= value <= 65535:
            raise forms.ValidationError("Enter a port from 1 to 65535.")
        return value

    @override
    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        if data.get("ssh_alias"):
            self.instance.connection_mode = "alias"
        elif data.get("address"):
            self.instance.connection_mode = "agent"
            data["ssh_alias"] = saved_alias(
                str(data["address"]), str(data.get("username", "root")), int(data.get("port", 22))
            )
            self.instance.ssh_alias = str(data["ssh_alias"])
        elif "address" not in self.errors and "ssh_alias" not in self.errors:
            if "ssh_alias" in self.data and "address" not in self.data:
                self.add_error("ssh_alias", "Choose the SSH alias for this server.")
            else:
                self.add_error(
                    "address", "Enter the server address, or choose an advanced SSH alias."
                )
        return data

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"
