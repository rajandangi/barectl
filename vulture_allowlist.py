"""Never imported by the application. docs/quality.md#dead-code-checks"""

import tarfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import UTC, datetime

    from django.db.migrations import Migration

    from bootstrap.apps import BootstrapConfig
    from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation
    from bootstrap.presentation import ApplyView, Outcome, PlanReview, PreparationView
    from bootstrap.services import ServerPlans
    from bootstrap.views import ActionChoice
    from config import asgi, settings, urls, wsgi
    from dashboard.apps import DashboardConfig
    from dashboard.checks import check_built_assets
    from dashboard.middleware import HtmxAuthenticationMiddleware
    from dashboard.templatetags.vite import vite_entry
    from dashboard.test_browser import BrowserTestCase, DevelopmentAssetBrowserTests
    from databases.apps import DatabasesConfig
    from databases.models import BindingRecord, DatabaseRequest
    from discovery.apps import DiscoveryConfig
    from discovery.models import SiteState
    from discovery.presentation import ShownResource, ShownSite
    from discovery.services import RecordedDiscovery
    from discovery.test_ssh import _Handler
    from disposable.fault_proxy import AcmeHandler, ControlHandler, DualStackServer
    from disposable.test_fault_proxy import QuietControlHandler
    from operations.apps import OperationsConfig
    from operations.models import RemoteOperation
    from servers.activity import InstallationView
    from servers.apps import ServersConfig
    from servers.discovery_state import AttemptView, DiscoveryState, ServerRow, Status
    from servers.forms import ServerForm, ServerSearchForm
    from servers.models import Server
    from servers.testing import ControllerConfigTestCase
    from servers.tests import InventoryTests
    from sites.apps import SitesConfig
    from sites.forms import SiteForm
    from sites.models import PlanAccountChange, PlanFileChange, PlanSite
    from tls.apps import TlsConfig
    from tls.forms import StagingForm
    from tls.models import PlanTlsReadiness, ReadinessName, StagingRunResult
    from tls.presentation import ActivationReview, SetupReview
    from tls.progress import SiteInstallation, StageView
    from wordpress.apps import WordpressConfig
    from wordpress.forms import InstallForm
    from wordpress.inspection_models import InspectionItem
    from wordpress.inspection_presentation import InspectionReviewView, ResultView
    from wordpress.models import PlanWordpressInstall
    from wordpress.presentation import InstallReview, Prerequisite
    from wordpress.presentation import SetupReview as WpcliSetupReview

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
        OperationsConfig,
        DiscoveryConfig,
        BootstrapConfig,
        SitesConfig,
        DatabasesConfig,
        TlsConfig,
        WordpressConfig,
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
    # Django creates the database plan permissions from this model's Meta.
    _database_permissions = DatabaseRequest
    # The ORM and templates read field descriptors and model options dynamically.
    _model = (Server.created_at,)
    # The removal page reads these fields of the server's recorded discovery.
    _removal = RecordedDiscovery(active=False, attempt_count=0, has_snapshot=False)
    _removal_fields = (_removal.attempt_count, _removal.has_snapshot)
    # paramiko calls the test server's hooks during negotiation.
    _paramiko_hooks = (
        _Handler.get_allowed_auths,
        _Handler.check_auth_publickey,
        _Handler.check_channel_request,
        _Handler.check_channel_exec_request,
        _Handler.check_channel_pty_request,
        _Handler.check_channel_env_request,
        _Handler.check_channel_forward_agent_request,
    )
    # http.server reads these class attributes and dispatches requests to do_<METHOD>; the
    # fault proxy's tests silence its request log.
    _http_handlers = (
        DualStackServer.address_family,
        DualStackServer.daemon_threads,
        AcmeHandler.protocol_version,
        AcmeHandler.do_GET,
        AcmeHandler.do_HEAD,
        AcmeHandler.do_POST,
        ControlHandler.protocol_version,
        ControlHandler.do_GET,
        ControlHandler.do_POST,
        ControlHandler.do_DELETE,
        QuietControlHandler.log_message,
    )
    _model_options = (Server.Meta.ordering, Server.Meta.constraints)
    # Django reads these Meta options: access is granted per kind, and plan permissions
    # (reviewing, preparing, applying and clearing native results) live on the plan model.
    _permissions = (
        RemoteOperation.Meta.default_permissions,
        PlanPreparation.Meta.default_permissions,
        ApplyRun.Meta.default_permissions,
        ConfigurationPlan.Meta.default_permissions,
        ConfigurationPlan.Meta.permissions,
        ImmutableRecord.Meta.abstract,
    )
    # The binding review renders the site user; the run's audit copies it by name.
    _binding_fields = BindingRecord.site_user
    # The apply services write this field by name in queryset updates and reads.
    _apply_fields = ApplyRun.dpkg_status_before
    # Plan pages render these stored fields.
    _plan_fields = (
        ConfigurationPlan.profile_revision,
        ConfigurationPlan.dpkg_version,
        ConfigurationPlan.systemd_version,
    )
    # The site review template renders these stored fields, and the roles are stored choices.
    _site_fields = (
        PlanSite.document_root,
        PlanSite.pool_name,
        PlanFileChange.content_sha256,
        PlanFileChange.preimage_absent,
        PlanFileChange.Role.NGINX_SOURCE,
        PlanFileChange.Role.NGINX_LINK,
        PlanFileChange.Role.PLACEHOLDER,
        PlanAccountChange.login_shell,
        PlanAccountChange.gid_min,
        PlanAccountChange.gid_max,
        PlanReview.extension_template,
    )
    # tarfile writes a link member's target from TarInfo.linkname, which the admission test sets.
    _archive_link = tarfile.TarInfo("").linkname
    # Django's form validation calls clean_<field> by name.
    _site_form = (SiteForm.clean_identifier, SiteForm.clean_names)
    _staging_form = StagingForm.clean_authority
    # The readiness review's template renders the CAA records and the server's recorded
    # expected destinations through these properties.
    _readiness_names = (ReadinessName.a_list, ReadinessName.aaaa_list, ReadinessName.caa_list)
    _readiness_addresses = (PlanTlsReadiness.ipv4_list, PlanTlsReadiness.ipv6_list)
    # The run page shows the staged certificate's evidence through the template's fields.
    _staging_result = (
        StagingRunResult.subject,
        StagingRunResult.not_before,
        StagingRunResult.not_after,
    )
    # Plan and Activity templates read these fields and properties.
    _choice = ActionChoice("", "", "", checked=False).description
    _preparation = PreparationView(
        0, 0, "", "", Outcome.QUEUED, "", datetime.min.replace(tzinfo=UTC), None, None, "", None
    ).server_name
    _plan_views = (
        PreparationView.is_preparation,
        PreparationView.is_apply,
        ApplyView.is_apply,
        ApplyView.reconciling,
        ApplyView.execution_label,
        ApplyView.verification_label,
        ApplyView.snapshot_freshness,
        ApplyView.unknown,
        ApplyView.native_record_missing,
        ApplyView.closure_pending,
        ApplyView.partly_applied,
        AttemptView.is_apply,
        PlanReview.expired,
        ServerPlans.can_prepare,
        DiscoveryState.poll_token,
        AttemptView.is_preparation,
    )
    # The renewal setup review shows renewal's state as the plan read it; the WP-CLI setup
    # review shows the reviewed pins and its permission contract.
    _renewal = (SetupReview.last_run, WpcliSetupReview.authority)
    # The installation review's template renders these stored fields, and an installation
    # run consumes the same fields, so none is dropped.
    _install_fields = (
        PlanWordpressInstall.certificate_not_after,
        PlanWordpressInstall.core_locale,
        PlanWordpressInstall.max_archive_bytes,
        PlanWordpressInstall.max_tree_bytes,
        PlanWordpressInstall.max_entries,
        PlanWordpressInstall.max_file_bytes,
        PlanWordpressInstall.memory_max_bytes,
        PlanWordpressInstall.runtime_limit_seconds,
        PlanWordpressInstall.private_configuration,
        InstallReview.password_step,
        Prerequisite.state_label,
    )
    # The inspection review and result templates read these properties and choices.
    _inspection = (
        InspectionReviewView.operation_label,
        InspectionReviewView.runs_application,
        InspectionReviewView.plugin_slugs,
        ResultView.operation_label,
        ResultView.integrity_reason,
        ResultView.mismatches,
        InspectionItem.Kind.PLUGIN,
        InspectionItem.Kind.MU_PLUGIN,
        InspectionItem.Kind.DROPIN,
        InspectionItem.Kind.THEME,
    )
    # Django's form validation calls clean_<field> by name.
    _install_form = (
        InstallForm.clean_canonical_name,
        InstallForm.clean_title,
        InstallForm.clean_admin_login,
        InstallForm.clean_admin_email,
    )
    # A site's Activity shows each certificate installation's recorded status.
    _installation = InstallationView(
        0, "", datetime.min.replace(tzinfo=UTC), None, "", []
    ).status_label
    # The activation review shows the redirect target and the shared rejection server's path.
    _activation = (ActivationReview.redirect_target, ActivationReview.default_path)
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
    # The site's Enable HTTPS card chooses its unconfirmed and failed wording from these.
    _site_installation = (
        SiteInstallation.order_unconfirmed,
        SiteInstallation.activation_unconfirmed,
        SiteInstallation.activation_failed,
        StageView.not_applied,
    )
    # The server page reads the snapshot's presentation from its discovery state, and the
    # Sites section each site's domains, PHP version, facts, its database and certificate
    # entries, whether a resource's warning is an alert, and whether a site page's change
    # sections repeat the convention flag.
    _shown = ShownResource("", "", "", (), (), "", alert=False)
    _site = ShownSite("", (), "", SiteState.MANAGED, "", "", "", "", (), (), _shown, _shown)
    _presentation = (
        DiscoveryState.presentation,
        DiscoveryState.hosting_guidance,
        _site.domains,
        _site.php_version,
        _site.state,
        _site.verdict,
        _site.summary,
        _site.file,
        _site.expected,
        _site.missing,
        _site.facts,
        _site.database,
        _site.certificate,
        _site.complete,
        _site.unread,
        _shown.alert,
        _shown.certificate,
        _shown.present,
    )
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
