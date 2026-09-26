from django import forms


class ServerSearchForm(forms.Form):
    q = forms.CharField(label="Search servers", required=False, max_length=100)
