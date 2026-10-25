"""The queue-worker definition and action on a site's Settings section."""

from collections.abc import Mapping
from typing import Final, override

from django import forms

from . import workers

ACTIONS: Final = (
    ("start", "Save and start"),
    ("stop", "Stop"),
    ("restart", "Restart"),
)


class WorkerForm(forms.Form):
    """The reviewed action and, for a start, the full worker definition."""

    action = forms.ChoiceField(choices=(), error_messages={"required": "Choose an action."})
    queues = forms.CharField(required=False)
    processes = forms.IntegerField(required=False)
    timeout = forms.IntegerField(required=False)

    def __init__(
        self,
        data: Mapping[str, object] | None = None,
        *,
        definition: workers.WorkerDefinition | None = None,
    ) -> None:
        super().__init__(data=data, auto_id="id_queue_workers_%s")
        field = self.fields["action"]
        if isinstance(field, forms.ChoiceField):
            field.choices = ACTIONS
        if definition is not None:
            self.fields["queues"].initial = ", ".join(definition.queues)
            self.fields["processes"].initial = definition.processes
            self.fields["timeout"].initial = definition.timeout
        else:
            self.fields["processes"].initial = 1
            self.fields["timeout"].initial = workers.DEFAULT_TIMEOUT

    @property
    def definition(self) -> workers.WorkerDefinition | None:
        return self.cleaned_data.get("definition") if hasattr(self, "cleaned_data") else None

    @override
    def clean(self) -> dict[str, object]:
        cleaned = dict(super().clean() or {})
        action = cleaned.get("action")
        if action != "start":
            return cleaned
        queues = cleaned.get("queues")
        processes = cleaned.get("processes")
        timeout = cleaned.get("timeout")
        if queues in (None, "") or processes is None or timeout is None:
            raise forms.ValidationError(
                "Type the queue names, the number of processes and the job timeout."
            )
        try:
            definition = workers.parse_definition(str(queues), processes, timeout)
        except ValueError as error:
            raise forms.ValidationError(str(error)) from None
        cleaned["definition"] = definition
        return cleaned
