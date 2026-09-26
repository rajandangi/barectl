from django import template
from django.utils.safestring import SafeString

from dashboard.vite import entry_tags

register = template.Library()


@register.simple_tag
def vite_entry(entry: str, *, classic: bool = False) -> SafeString:
    """Render the script and stylesheet tags for a Vite entry, such as ``"main.ts"``.

    Pass ``classic=True`` for a small script that must run before first paint.
    """
    return entry_tags(entry, classic=classic)
