"""The Logs section's search and time-range form (Phase C #389)."""

from collections.abc import Mapping
from typing import override

from django import forms

DATETIME_FORMATS = ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S")


class LogFilterForm(forms.Form):
    term = forms.CharField(
        required=False,
        max_length=100,
        error_messages={"max_length": "Search for at most 100 characters."},
    )
    since = forms.DateTimeField(
        required=False,
        input_formats=DATETIME_FORMATS,
        error_messages={"invalid": "Choose a valid start time."},
    )
    until = forms.DateTimeField(
        required=False,
        input_formats=DATETIME_FORMATS,
        error_messages={"invalid": "Choose a valid end time."},
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        initial: dict[str, object] | None = None,
        auto_id: str = "id_logs_%s",
    ) -> None:
        super().__init__(data, initial=initial, auto_id=auto_id)

    @override
    def clean(self) -> dict[str, object]:
        cleaned = dict(super().clean() or {})
        since, until = cleaned.get("since"), cleaned.get("until")
        if since is not None and until is not None and since > until:
            raise forms.ValidationError("Choose a start time before the end time.")
        return cleaned

    def document(self) -> dict[str, str]:
        """The bounded strings the read request stores and the worker sends."""
        if not self.is_valid():
            return {}
        return {
            "term": str(self.cleaned_data.get("term") or ""),
            "since": self._iso(self.cleaned_data.get("since")),
            "until": self._iso(self.cleaned_data.get("until")),
        }

    @staticmethod
    def _iso(value: object) -> str:
        return value.isoformat() if hasattr(value, "isoformat") else ""
