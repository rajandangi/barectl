"""Static references for Django's implicit uses. Never imported by the application.

Review each reference before adding it. Vulture matches names across scopes, so a
reference can also hide an unrelated symbol with the same name. Keep this list small.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.db.migrations import Migration

    from config import asgi, settings, urls, wsgi
    from servers.admin import ServerAdmin
    from servers.apps import ServersConfig
    from servers.models import Server
    from servers.tests import InventoryTests

    # Django loads these settings by name, rather than through Python references.
    _settings = (
        settings.ALLOWED_HOSTS,
        settings.INSTALLED_APPS,
        settings.MIDDLEWARE,
        settings.ROOT_URLCONF,
        settings.TEMPLATES,
        settings.WSGI_APPLICATION,
        settings.DATABASES,
        settings.AUTH_PASSWORD_VALIDATORS,
        settings.LANGUAGE_CODE,
        settings.TIME_ZONE,
        settings.USE_I18N,
        settings.USE_TZ,
        settings.STATIC_URL,
        settings.STATICFILES_DIRS,
        settings.STATIC_ROOT,
        settings.DEFAULT_AUTO_FIELD,
        settings.LOGIN_URL,
        settings.LOGIN_REDIRECT_URL,
        settings.LOGOUT_REDIRECT_URL,
        settings.SESSION_COOKIE_SECURE,
        settings.CSRF_COOKIE_SECURE,
        settings.SECURE_SSL_REDIRECT,
        settings.SECURE_HSTS_SECONDS,
        settings.SECURE_HSTS_INCLUDE_SUBDOMAINS,
        settings.SECURE_HSTS_PRELOAD,
    )
    # Deployment servers, URL resolution, app discovery and admin registration.
    _entry_points = (asgi.application, wsgi.application, urls.urlpatterns, ServersConfig)
    _admin = (ServerAdmin.list_display, ServerAdmin.search_fields)
    # The ORM and templates read field descriptors and model options dynamically.
    _model = (Server.hostname, Server.ssh_port, Server.ssh_user, Server.created_at)
    _model_options = Server.Meta.ordering
    # Django's migration loader reads this metadata on each Migration subclass.
    _migration = (Migration.initial, Migration.dependencies, Migration.operations)
    # Django invokes this hook before running the discovered unittest methods.
    _test_hook = InventoryTests.setUpTestData
