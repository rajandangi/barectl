"""Static references for Django's implicit uses. Never imported by the application.

Review each reference before adding it. Vulture matches names across scopes, so a
reference can also hide an unrelated symbol with the same name. Keep this list small.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.db.migrations import Migration

    from config import asgi, settings, urls, wsgi
    from dashboard.apps import DashboardConfig
    from dashboard.checks import check_built_assets
    from dashboard.middleware import HtmxAuthenticationMiddleware
    from dashboard.templatetags.vite import vite_entry
    from dashboard.test_browser import BrowserTestCase, DevelopmentAssetBrowserTests
    from discovery.apps import DiscoveryConfig
    from discovery.models import (
        DiscoveryAttempt,
    )
    from discovery.services import RecordedDiscovery
    from discovery.snapshot import CollectedSnapshot, OsRelease
    from discovery.ssh import _RejectUntrusted
    from discovery.test_ssh import _Handler
    from servers.apps import ServersConfig
    from servers.discovery_state import ServerRow, Status
    from servers.forms import ServerForm, ServerSearchForm
    from servers.models import Server
    from servers.testing import ControllerConfigTestCase
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
        settings.TASKS,
        settings.LOGGING,
    )
    # Deployment servers, URL resolution and app discovery.
    _entry_points = (
        asgi.application,
        wsgi.application,
        urls.urlpatterns,
        ServersConfig,
        DiscoveryConfig,
    )
    # App discovery calls ready(), which registers the deployment check. MIDDLEWARE names the
    # middleware class, and templates load the Vite tag through {% load vite %}.
    _dashboard = (
        DashboardConfig,
        DashboardConfig.ready,
        check_built_assets,
        HtmxAuthenticationMiddleware,
        vite_entry,
    )
    # The ORM and templates read field descriptors and model options dynamically.
    _model = (Server.created_at,)
    # Server detail templates read this attempt field.
    _discovery = (DiscoveryAttempt.queued_at,)
    # The removal page reads these fields of the server's recorded discovery.
    _removal = RecordedDiscovery(active=False, attempt_count=0, has_snapshot=False)
    _removal_fields = (_removal.attempt_count, _removal.has_snapshot)
    # The discovery template reads these snapshot properties.
    _snapshot = (
        CollectedSnapshot.capacity,
        CollectedSnapshot.capacity_sources,
        CollectedSnapshot.component_sources,
        OsRelease.display_name,
    )
    # paramiko calls the host-key policy and the test server's hooks during negotiation.
    _paramiko_hooks = (
        _RejectUntrusted.missing_host_key,
        _Handler.get_allowed_auths,
        _Handler.check_auth_publickey,
        _Handler.check_channel_request,
        _Handler.check_channel_exec_request,
    )
    _model_options = (Server.Meta.ordering, Server.Meta.constraints)
    # Form metaclasses collect declared fields and Meta options; templates render the search
    # field as form.q.
    _forms = (
        ServerSearchForm.q,
        ServerForm.Meta.model,
        ServerForm.Meta.labels,
        ServerForm.Meta.help_texts,
        ServerForm.Meta.widgets,
        ServerForm.Meta.error_messages,
    )
    # Templates read each row's status.
    _views = ServerRow(Server(), Status.NOT_VERIFIED).status
    # Django's template engine reads this to compare with Status members instead of calling it.
    _template_enum = Status.do_not_call_in_templates
    # Django's migration loader reads this metadata on each Migration subclass.
    _migration = (Migration.initial, Migration.dependencies, Migration.operations)
    # Django and unittest invoke these hooks around the discovered test methods.
    _test_hooks = (
        ControllerConfigTestCase.setUpClass,
        ControllerConfigTestCase.setUpTestData,
        ControllerConfigTestCase.setUp,
        InventoryTests.setUpTestData,
        BrowserTestCase.setUp,
        BrowserTestCase.tearDown,
    )
    # LiveServerTestCase serves static files through this handler class.
    _static_handler = DevelopmentAssetBrowserTests.static_handler
