"""The one WordPress plugin Barectl installs, pinned in source like the core archive.

docs/wordpress.md and #392. The archive's size and SHA-256 are checked before WordPress
installs it, and the native mirror serves the same bytes offline
(docs/quality.md#native-layer); ``disposable/mirror.py`` and the drift job keep the pinned
copy current, exactly as they do for Phase B's WordPress archive.
"""

from typing import Final

PLUGIN_NAME: Final = "Redis Object Cache"
PLUGIN_SLUG: Final = "redis-cache"
PLUGIN_VERSION: Final = "3.0.0"
PLUGIN_ARCHIVE_URL: Final = (
    f"https://downloads.wordpress.org/plugin/{PLUGIN_SLUG}.{PLUGIN_VERSION}.zip"
)
PLUGIN_ARCHIVE_SIZE: Final = 730620
PLUGIN_ARCHIVE_SHA256: Final = "7a03342d3defbe94cac8d0470b42dc1a1c34331b19c47205df20ceccd3c8f54a"
