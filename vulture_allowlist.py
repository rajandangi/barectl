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
    from dashboard.test_browser import ProductionAssetBrowserTests
    from discovery.apps import DiscoveryConfig
    from discovery.models import (
        CapacityObservation,
        ComponentObservation,
        DiscoveryAttempt,
        DiscoverySnapshot,
        NginxSiteObservation,
        PhpFpmPoolObservation,
    )
    from discovery.ssh import _RejectUntrusted
    from discovery.test_ssh import _Handler
    from servers.admin import ServerAdmin
    from servers.apps import ServersConfig
    from servers.forms import ServerForm, ServerSearchForm
    from servers.models import Server
    from servers.tests import (
        ConnectionMetadataMigrationTests,
        ControllerConfigTestCase,
        InventoryTests,
    )
    from servers.views import ServerRow, Status

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
    # Deployment servers, URL resolution, app discovery and admin registration.
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
    # The admin site reads these options and permission hooks while rendering its pages.
    _admin = (
        ServerAdmin.list_display,
        ServerAdmin.search_fields,
        ServerAdmin.has_add_permission,
        ServerAdmin.has_change_permission,
    )
    # The ORM and templates read field descriptors and model options dynamically.
    _model = (Server.created_at,)
    # Server detail templates read these attempt and snapshot fields.
    _discovery = (
        DiscoveryAttempt.queued_at,
        DiscoveryAttempt.is_active,
        DiscoverySnapshot.os_warning,
        DiscoverySnapshot.capacity,
        DiscoverySnapshot.service_sources,
        DiscoverySnapshot.nginx_site_files_warning,
        DiscoverySnapshot.php_fpm_pools_warning,
        CapacityObservation.status_label,
    )
    # Server detail templates read each component's stored observation.
    _services = (
        ComponentObservation.component,
        ComponentObservation.package_status,
        ComponentObservation.packages,
        ComponentObservation.package_warning,
        ComponentObservation.service_status,
        ComponentObservation.units,
        ComponentObservation.service_warning,
    )
    # Server detail templates read each observed site and pool.
    _sites = (
        NginxSiteObservation.name,
        NginxSiteObservation.server_names,
        NginxSiteObservation.listens,
        NginxSiteObservation.source,
        NginxSiteObservation.warning,
        PhpFpmPoolObservation.version,
        PhpFpmPoolObservation.listen,
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
        ServerForm.Meta.labels,
        ServerForm.Meta.help_texts,
        ServerForm.Meta.widgets,
        ServerForm.Meta.error_messages,
    )
    # Templates read each row's status.
    _views = ServerRow(Server(), Status.NOT_VERIFIED).status
    # Django's migration loader reads this metadata on each Migration subclass.
    _migration = (Migration.initial, Migration.dependencies, Migration.operations)
    # Django and unittest invoke these hooks around the discovered test methods.
    _test_hooks = (
        ControllerConfigTestCase.setUpClass,
        ControllerConfigTestCase.setUpTestData,
        ControllerConfigTestCase.setUp,
        InventoryTests.setUpTestData,
        ConnectionMetadataMigrationTests.tearDown,
        ProductionAssetBrowserTests.setUp,
        ProductionAssetBrowserTests.tearDown,
    )
