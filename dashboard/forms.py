from typing import override

from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.models import User
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


class AccountPasswordForm(PasswordChangeForm):
    @override
    def __init__(self, user: User, *args: object, **kwargs: object) -> None:
        super().__init__(user, *args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "usa-input"
        self.fields["old_password"].widget.attrs.pop("autofocus", None)
        self.fields["old_password"].label = "Current password"
        self.fields["new_password2"].label = "Confirm new password"
