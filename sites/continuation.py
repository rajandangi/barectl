"""The create answers a Step 1 install keeps until the operator continues the site.

docs/sites.md#step-1-a-missing-runtime-or-database-engine
"""

from dataclasses import dataclass, field

from django.http import HttpRequest
from django.urls import reverse

SESSION_KEY = "site_creation_step"
PLATFORM_LABELS: dict[str, str] = {
    "http": "HTTP site",
    "wordpress": "WordPress site",
    "laravel": "Laravel site",
}
ANCHORS: dict[str, str] = {
    "http": "http-site-create",
    "wordpress": "wordpress-site-create",
    "laravel": "laravel-site-create",
}
ANSWER_FIELDS: dict[str, tuple[str, ...]] = {
    "http": ("names", "identifier", "php_version", "http_only"),
    "wordpress": (
        "names",
        "identifier",
        "title",
        "admin_username",
        "admin_email",
        "php_version",
        "http_only",
    ),
    "laravel": (
        "names",
        "identifier",
        "repository",
        "branch",
        "fingerprint",
        "php_version",
        "http_only",
    ),
}


@dataclass(frozen=True)
class CreationStep:
    """One queued Step 1 install, and the create answers waiting behind it."""

    preparation_id: int
    server_id: int
    platform: str
    kind: str
    selection: str
    step_title: str
    continue_label: str
    answers: dict[str, object] = field(default_factory=dict)

    @property
    def platform_label(self) -> str:
        return PLATFORM_LABELS.get(self.platform, "site")

    @property
    def anchor(self) -> str:
        return ANCHORS.get(self.platform, "site-plans")

    def initial(self) -> dict[str, object]:
        fields = ANSWER_FIELDS.get(self.platform, ())
        return {key: value for key, value in self.answers.items() if key in fields}

    def continue_url(self) -> str:
        if self.platform == "http":
            base = reverse("server_site_create", args=[self.server_id])
            return f"{base}?create={self.preparation_id}"
        if self.platform in ("wordpress", "laravel"):
            base = reverse("site_create_platform", args=[self.server_id, self.platform])
            return f"{base}?create={self.preparation_id}"
        base = reverse("server_sites", args=[self.server_id])
        return f"{base}?create={self.preparation_id}#{self.anchor}"

    @property
    def resume_note(self) -> str:
        return (
            f"Your answers from Step 1 are kept. Prepare the {self.platform_label} review "
            "when you are ready."
        )

    def document(self) -> dict[str, object]:
        return {
            "preparation_id": self.preparation_id,
            "server_id": self.server_id,
            "platform": self.platform,
            "kind": self.kind,
            "selection": self.selection,
            "step_title": self.step_title,
            "continue_label": self.continue_label,
            "answers": self.answers,
        }

    @classmethod
    def from_document(cls, value: object) -> CreationStep | None:
        if not isinstance(value, dict):
            return None
        integer_fields = ("preparation_id", "server_id")
        text_fields = ("platform", "kind", "selection", "step_title", "continue_label")
        if not all(type(value.get(key)) is int for key in integer_fields) or not all(
            isinstance(value.get(key), str) for key in text_fields
        ):
            return None
        answers = value.get("answers")
        if not isinstance(answers, dict) or not all(
            isinstance(key, str) and isinstance(answer, (str, bool))
            for key, answer in answers.items()
        ):
            return None
        platform = str(value["platform"])
        if platform not in PLATFORM_LABELS:
            return None
        return cls(
            preparation_id=int(str(value["preparation_id"])),
            server_id=int(str(value["server_id"])),
            platform=platform,
            kind=str(value["kind"]),
            selection=str(value["selection"]),
            step_title=str(value["step_title"]),
            continue_label=str(value["continue_label"]),
            answers=dict(answers),
        )


@dataclass(frozen=True)
class StepBanner:
    """The Step 1 wording on a change or run page."""

    title: str
    note: str
    continue_url: str = ""
    continue_label: str = ""


def remember(request: HttpRequest, step: CreationStep) -> None:
    request.session[SESSION_KEY] = step.document()


def forget(request: HttpRequest) -> None:
    request.session.pop(SESSION_KEY, None)


def stored(request: HttpRequest) -> CreationStep | None:
    return CreationStep.from_document(request.session.get(SESSION_KEY))


def for_preparation(
    request: HttpRequest, preparation_id: int, server_id: int
) -> CreationStep | None:
    step = stored(request)
    if step is None or step.preparation_id != preparation_id or step.server_id != server_id:
        return None
    return step


def requested_step(request: HttpRequest, server_id: int) -> CreationStep | None:
    """The Step 1 answers a create page may prefill after ``?create=<preparation>``."""
    raw = request.GET.get("create", "")
    if not raw.isdecimal():
        return None
    return for_preparation(request, int(raw), server_id)


def change_banner(step: CreationStep) -> StepBanner:
    return StepBanner(
        title=step.step_title,
        note=(
            f"This is the first step for the {step.platform_label} you are creating. "
            "Your answers are kept; the run page continues the site once this step "
            "finishes."
        ),
    )


def run_banner(step: CreationStep, *, succeeded: bool, finished: bool) -> StepBanner:
    if not finished:
        return StepBanner(
            title=step.step_title,
            note=(
                f"This is the first step for the {step.platform_label} you are creating. "
                "Your answers are kept."
            ),
        )
    note = (
        f"Step 1 is complete. Continue creating your {step.platform_label} with the "
        "answers you entered."
        if succeeded
        else (
            "Step 1 did not complete. Your answers are kept; return to the create form "
            "to try again."
        )
    )
    return StepBanner(
        title=step.step_title,
        note=note,
        continue_url=step.continue_url(),
        continue_label=step.continue_label if succeeded else "Return to Create site",
    )
