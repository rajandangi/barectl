"""The scheduled-tasks action on a site's Settings section."""

from collections.abc import Mapping

from django import forms

STATES = (("on", "Turn on"), ("off", "Turn off"))
SCHEDULER_STATES = (("on", "Turn on"), ("off", "Turn off"), ("run", "Run now"))


class ScheduleForm(forms.Form):
    """The one reviewed action: turn server cron on or off."""

    state = forms.ChoiceField(choices=(), error_messages={"required": "Choose an action."})

    def __init__(
        self,
        data: Mapping[str, object] | None = None,
        *,
        choices: tuple[tuple[str, str], ...] = STATES,
    ) -> None:
        super().__init__(data=data, auto_id="id_automation_%s")
        field = self.fields["state"]
        if isinstance(field, forms.ChoiceField):
            field.choices = choices
