from collections.abc import Mapping

from django import forms


class ObjectCacheForm(forms.Form):
    """The site Settings action: turn the cache on, off, or load its PHP client."""

    action = forms.ChoiceField(
        choices=(("on", "Turn on"), ("off", "Turn off"), ("client", "Load the client")),
        error_messages={"invalid_choice": "Choose a supported object cache action."},
    )
    memory = forms.TypedChoiceField(
        choices=(),
        required=False,
        coerce=int,
        empty_value=None,
        error_messages={"invalid_choice": "Choose a reviewed cache memory size."},
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        choices: tuple[tuple[int, str], ...] = (),
        selected: int = 0,
    ) -> None:
        super().__init__(data, initial={"memory": selected}, auto_id="id_object_cache_%s")
        field = self.fields["memory"]
        if isinstance(field, forms.TypedChoiceField):
            field.choices = [(size, label) for size, label in choices]
