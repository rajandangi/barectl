from django import forms


class SharedApplyForm(forms.Form):
    """The acknowledgement a Shared change's operator gives the listed affected sites."""

    affected_sites = forms.BooleanField(
        label=(
            "I understand this change touches shared resources and reaches the affected "
            "sites listed above."
        ),
        error_messages={"required": "Confirm the listed affected sites to apply this change."},
    )


class ChangeApplyForm(forms.Form):
    """The acknowledgement a kind's own review requires before it can be applied."""

    acknowledged = forms.BooleanField(
        error_messages={"required": "Confirm the review's acknowledgement to apply this change."},
    )


class ChangeConfirmationForm(forms.Form):
    """The exact value a destructive kind's review asks the operator to type."""

    confirmation = forms.CharField(
        error_messages={"required": "Type the value shown on the review to apply this change."},
    )


class AcknowledgeForm(forms.Form):
    understood = forms.BooleanField(
        label=(
            "I understand that Barectl cannot tell whether this run changed the server, and "
            "that closing it does not mean nothing changed."
        ),
        error_messages={"required": "Confirm that you understand the outcome is unknown."},
    )
