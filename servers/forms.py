from typing import TYPE_CHECKING, ClassVar, override

from django import forms
from django.http import QueryDict

from .models import Server
from .ssh_config import AliasCatalog

if TYPE_CHECKING:
    ServerFormBase = forms.ModelForm[Server]
else:
    ServerFormBase = forms.ModelForm


class ServerSearchForm(forms.Form):
    q = forms.CharField(label="Search servers", required=False, max_length=100)


class ServerForm(ServerFormBase):
    """Register or edit a server by display name and a configured SSH alias.

    The alias choices come from a catalog read while handling this request, so a submitted
    alias is checked against the controller's current configuration, not the rendered page.
    """

    class Meta:
        model = Server
        fields: ClassVar[list[str]] = ["name", "ssh_alias"]
        labels: ClassVar[dict[str, str]] = {"name": "Name"}
        help_texts: ClassVar[dict[str, str]] = {
            "name": "Shown in Barectl only. It does not change the server."
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
        self.fields["ssh_alias"] = forms.ChoiceField(
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

    @override
    def full_clean(self) -> None:
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                widget = self.fields[name].widget
                widget.attrs["class"] = f"{widget.attrs['class']} usa-input--error"

    @override
    def save(self, commit: bool = True) -> Server:
        # Choosing an alias reconciles a migrated record; its old details are no longer used.
        self.instance.legacy_connection = ""
        return super().save(commit)
