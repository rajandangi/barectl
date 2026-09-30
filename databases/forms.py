from django import forms

from bootstrap.models import Action

DRIVER_CHOICES = (
    (Action.PHP_MYSQL.value, Action.PHP_MYSQL.label),
    (Action.PHP_PGSQL.value, Action.PHP_PGSQL.label),
)


class DriverForm(forms.Form):
    action = forms.ChoiceField(choices=DRIVER_CHOICES)
