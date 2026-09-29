from django import template
from django.utils.safestring import SafeString

from dashboard.vite import entry_tags

register = template.Library()


@register.simple_tag
def vite_entry(entry: str, *, classic: bool = False) -> SafeString:
    """docs/frontend-assets.md#development-and-production"""
    return entry_tags(entry, classic=classic)
