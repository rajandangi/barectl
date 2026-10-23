"""The site's bounded PHP-FPM settings form (docs/site-conventions.md)."""

from collections.abc import Mapping
from typing import override

from django import forms

from .bodies.pool import SitePool


class SitePoolForm(forms.Form):
    process_manager = forms.ChoiceField(
        label="Process manager",
        choices=(
            ("ondemand", "On demand"),
            ("static", "Static"),
            ("dynamic", "Dynamic"),
        ),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    max_children = forms.IntegerField(
        label="Maximum child processes",
        min_value=1,
        max_value=64,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    start_servers = forms.IntegerField(
        label="Start servers",
        min_value=1,
        max_value=64,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    min_spare_servers = forms.IntegerField(
        label="Minimum spare servers",
        min_value=1,
        max_value=64,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    max_spare_servers = forms.IntegerField(
        label="Maximum spare servers",
        min_value=1,
        max_value=64,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    process_idle_timeout = forms.IntegerField(
        label="Idle timeout (seconds)",
        min_value=1,
        max_value=300,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    slowlog_timeout = forms.IntegerField(
        label="Slow request log threshold (seconds)",
        min_value=1,
        max_value=300,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    terminate_timeout = forms.IntegerField(
        label="Request time limit (seconds)",
        min_value=1,
        max_value=300,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    memory_limit = forms.IntegerField(
        label="Memory limit (MB)",
        min_value=16,
        max_value=1024,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    upload_max_filesize = forms.IntegerField(
        label="Maximum upload size (MB)",
        min_value=1,
        max_value=256,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )
    post_max_size = forms.IntegerField(
        label="Maximum post size (MB)",
        min_value=1,
        max_value=256,
        required=False,
        widget=forms.NumberInput(attrs={"class": "usa-input"}),
    )

    def __init__(
        self,
        data: Mapping[str, str] | None = None,
        *,
        pool: SitePool | None = None,
        auto_id: str = "id_site_pool_%s",
    ) -> None:
        super().__init__(
            data, initial=pool.document() if pool is not None else None, auto_id=auto_id
        )

    @override
    def clean(self) -> dict[str, object]:
        cleaned = dict(super().clean() or {})
        process_manager = cleaned.get("process_manager")
        max_children = cleaned.get("max_children")
        if not isinstance(process_manager, str) or not isinstance(max_children, int):
            return cleaned
        dynamic = (
            cleaned.get("start_servers"),
            cleaned.get("min_spare_servers"),
            cleaned.get("max_spare_servers"),
        )
        if process_manager != "dynamic" and any(value is not None for value in dynamic):
            raise forms.ValidationError(
                "Start and spare server counts apply only to the dynamic process manager."
            )
        idle = cleaned.get("process_idle_timeout")
        if process_manager != "ondemand" and idle is not None:
            raise forms.ValidationError(
                "The idle timeout applies only to the on-demand process manager."
            )
        pool = SitePool(
            process_manager=process_manager,
            max_children=max_children,
            start_servers=dynamic[0] if process_manager == "dynamic" else None,
            min_spare_servers=dynamic[1] if process_manager == "dynamic" else None,
            max_spare_servers=dynamic[2] if process_manager == "dynamic" else None,
            process_idle_timeout=idle if process_manager == "ondemand" else None,
            slowlog_timeout=cleaned.get("slowlog_timeout"),
            terminate_timeout=cleaned.get("terminate_timeout"),
            memory_limit=cleaned.get("memory_limit"),
            upload_max_filesize=cleaned.get("upload_max_filesize"),
            post_max_size=cleaned.get("post_max_size"),
        )
        if not pool.valid():
            raise forms.ValidationError(
                "The dynamic spare counts must be between 1 and the maximum children, in the "
                "order minimum, start, maximum."
            )
        cleaned["pool"] = pool
        return cleaned
