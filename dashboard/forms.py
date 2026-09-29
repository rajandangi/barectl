from typing import override

from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpRequest


class SignInForm(AuthenticationForm):
    @override
    def __init__(self, request: HttpRequest | None = None, *args: object, **kwargs: object) -> None:
        super().__init__(request, *args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "usa-input"

    @override
    def full_clean(self) -> None:
        super().full_clean()
        if self.errors:
            # The error summary receives focus instead of the first field.
            self.fields["username"].widget.attrs.pop("autofocus", None)
