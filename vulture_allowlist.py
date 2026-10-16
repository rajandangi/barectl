"""Never imported by the application. docs/quality.md#dead-code-checks"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import SimpleNamespace

    from django.db.migrations import Migration

    from bootstrap.apps import BootstrapConfig
    from config import asgi, settings, urls, wsgi
    from dashboard.apps import DashboardConfig
    from dashboard.checks import check_built_assets
    from dashboard.middleware import HtmxAuthenticationMiddleware
    from dashboard.templatetags.vite import vite_entry
    from dashboard.test_browser import BrowserTestCase, DevelopmentAssetBrowserTests
    from discovery.apps import DiscoveryConfig
    from discovery.models import RuntimeObservation, SiteState
    from discovery.presentation import ShownSite
    from discovery.services import RecordedDiscovery
    from discovery.ssh_testing import _Handler
    from discovery.test_host_standing import RecordedHostStandingTests
    from disposable.native_mirror import dns as mirror_dns
    from disposable.native_mirror import forward as mirror_forward
    from disposable.native_mirror import serve as mirror_serve
    from disposable.native_mirror.serve import _Handler as MirrorHandler
    from disposable.test_egress_control import EgressControl

    # Django's test discovery loads these scenario and transcript test classes by module scan.
    from disposable.test_foundation import (
        FoundationAdmission,
        FoundationSudoDiscovery,
        FoundationValidators,
        HostFoundation,
        SupportedFoundationResume,
    )
    from disposable.test_foundation_passive import PassiveFoundationDiscovery
    from disposable.test_foundation_recognition import (
        FoundationDeniedPrivilege,
        FoundationRouteRecognition,
    )
    from disposable.test_foundation_retired import RetiredFoundationRecognition
    from disposable.test_host_standing import (
        ApacheStanding,
        AptDailyActive,
        AptPhpStanding,
        EarlierBarectlStanding,
        NginxStanding,
        NixBuildUserCollision,
        PartialNixInstall,
        UnsupportedUbuntuStanding,
    )
    from disposable.test_http_site_consent import HttpSiteConsent
    from disposable.test_http_site_identities import HttpSiteIdentityAdmission
    from disposable.test_http_site_reconstruction import HttpSiteReconstruction
    from disposable.test_http_site_recovery import HttpSiteControllerRecovery
    from disposable.test_http_site_security import HttpSiteSecurityBehavior
    from disposable.test_http_site_transactions import HttpSiteTransactions
    from disposable.test_http_site_validators import HttpSiteValidators
    from disposable.test_http_sites import HttpSiteNativeBehavior
    from disposable.test_l0_discovery import PlainL0Discovery
    from disposable.test_mirror_nix import MirrorNixSignature
    from disposable.test_php_drain import SitePHPDetachedDrain, SitePHPLongDrain, SitePHPQueuedDrain
    from disposable.test_php_recovery import (
        SitePHPControllerRecovery,
        SitePHPPartialFilesystemFinish,
        SitePHPPartialFilesystemReverse,
    )
    from disposable.test_php_serving import (
        DiagnosticProbeAtIdleBoundary,
        ForeignPHPAdmission,
        SiteMasterWorkerChurn,
        SitePHPIsolation,
        SitePHPServing,
    )
    from disposable.test_runtime_defaults import RuntimeDefaultValidators, ServerRuntimeDefaults
    from disposable.test_runtime_retention import RuntimeClientRetention
    from disposable.test_runtimes import RuntimeNativeBehavior, RuntimeSmallHost
    from disposable.test_site_node import (
        SiteNodeInterruptedTransition,
        SiteNodeSelection,
        SiteNodeValidators,
    )
    from disposable.test_target_race import TwoControllerNativeLock
    from disposable.test_target_reconstruction import FreshControllerReconstruction
    from disposable.test_target_shape import JudgeByShape
    from operations.apps import OperationsConfig
    from operations.forms import AcknowledgeForm, SharedApplyForm
    from operations.models import (
        ChangePreparation,
        ChangeRecord,
        ChangeReview,
        ChangeRun,
        Consent,
        RemoteOperation,
    )
    from operations.presentation import ReviewView, RunOutcome, RunView
    from runtimes.apps import RuntimesConfig
    from runtimes.presentation import ShownBuild, ShownCatalog
    from servers.apps import ServersConfig
    from servers.discovery_state import AttemptView, DiscoveryState, ServerRow, Status
    from servers.forms import ServerForm, ServerSearchForm
    from servers.models import ConnectionDefinition, Server
    from servers.testing import ControllerConfigTestCase
    from servers.tests import InventoryTests
    from sites.apps import SitesConfig
    from sites.bodies.common import membership
    from sites.bodies.php_runtime import switch_php
    from sites.bodies.pool_boundary import PoolParser
    from sites.configuration import SiteSettings
    from sites.forms import HttpSiteForm
    from sites.test_target_discovery import RecordedHttpSiteTests

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
        RuntimesConfig,
        SitesConfig,
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
    _model_options = (Server.Meta.ordering, Server.Meta.constraints)
    # Django reads each model's Meta options: access is granted per kind and the shared
    # record base is abstract; no Python reference reads them.
    _meta_options = (
        RemoteOperation.Meta.default_permissions,
        ChangeRecord.Meta.abstract,
        ChangePreparation.Meta.default_permissions,
        ChangePreparation.Meta.base_manager_name,
        ChangeReview.Meta.default_permissions,
        ChangeReview.Meta.permissions,
        ChangeRun.Meta.default_permissions,
        ConnectionDefinition.Meta.default_permissions,
        RuntimeObservation.Meta.default_permissions,
    )
    # The mirror servers subclass http.server and socketserver, which read these class
    # attributes; the test handler silences its request log.
    _mirror_handlers = (
        mirror_serve._Server.daemon_threads,
        MirrorHandler.log_message,
        mirror_dns._Server.daemon_threads,
        mirror_forward._Server.daemon_threads,
    )
    # Django selects the guarded immutable preparation queryset through this Meta option.
    _preparation_manager = ChangePreparation.Meta.base_manager_name
    # The change pages render the derived consent and immutable review fields; a run's audit
    # also renders who acknowledged Shared changes and when.
    _shown_change_review = ReviewView(ChangeReview(), "", (), [], [], [], [], [])
    _shown_change_run = RunView(ChangeRun(), RunOutcome.QUEUED, "", "", "")
    _change_fields = (
        ChangeReview.consent,
        ChangeReview.affected_sites,
        ChangeReview.effects,
        ChangeReview.document,
        ChangeReview.preparation,
        ChangeRun.review,
        ChangeRun.sites_acknowledged_by,
        ChangeRun.sites_acknowledged_at,
        ChangePreparation.kind_slug,
        Consent.READ,
        _shown_change_review.consent_label,
        _shown_change_run.consent_label,
    )
    # The lifecycle writes these fields by name in queryset filters and records them when an
    # unknown outcome is acknowledged; no Python reference reads them.
    _operation_fields = (
        RemoteOperation.dispatched_at,
        ChangeRun.acknowledged_at,
        ChangeRun.unknown_acknowledged_by_name,
        ChangeRun.unknown_acknowledged_at,
    )
    # Django's form validation calls clean_<field> by name.
    _site_form = (HttpSiteForm.clean_identifier, HttpSiteForm.clean_names)
    # The Stack page's runtime catalog template reads these fields.
    _shown_build = ShownBuild("", "", "", 0, 0)
    _runtime_catalog = (
        ShownCatalog(None, "", (), (), "").runtimes,
        ShownCatalog(None, "", (), (), "").tools,
        _shown_build.language,
        _shown_build.unpacked_size,
    )
    # The Status poll token keys the discovery fragment.
    _discovery_views = (DiscoveryState.poll_token,)
    # The run page's template reads these properties.
    _run_views = (
        RunView.native_record_missing,
        RunView.execution_label,
        RunView.verification_label,
    )
    # Form metaclasses collect declared fields and Meta options; templates render the search
    # field as form.q.
    # The HTTP creation template renders each field's configured help text.
    _http_site_field_help = HttpSiteForm.base_fields["identifier"].help_text
    _forms = (
        ServerSearchForm.q,
        ServerForm.Meta.model,
        ServerForm.Meta.labels,
        ServerForm.Meta.help_texts,
        ServerForm.Meta.widgets,
        ServerForm.Meta.error_messages,
    )
    # The run page's acknowledgement form is validated by its field name.
    _acknowledge_forms = (AcknowledgeForm.understood, SharedApplyForm.affected_sites)
    # Templates read each row's status.
    _views = ServerRow(Server(), Status.NOT_VERIFIED).status
    # The server page reads the snapshot's presentation from its discovery state, and the
    # Sites section each site's domains, PHP version, facts and state.
    _site = ShownSite("", (), "", SiteState.MANAGED, "", "", "", (), ())
    _presentation = (
        DiscoveryState.presentation,
        DiscoveryState.hosting_guidance,
        _site.domains,
        _site.php_version,
        _site.state,
        _site.verdict,
        _site.summary,
        _site.file,
        _site.missing,
        _site.facts,
        _site.complete,
        _site.unread,
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
    # HTTP routes each mirror request by Host through this override, and the scenario runner
    # discovers the scenario class by Django's test tag.
    _mirror_handler = MirrorHandler.translate_path
    _scenario_class = (
        FoundationDeniedPrivilege,
        FoundationRouteRecognition,
        # The native runner discovers this scenario through Django test loading.
        RetiredFoundationRecognition,
        # Passive native scenarios use the same dynamic Django discovery boundary.
        PassiveFoundationDiscovery,
        HostFoundation,
        RuntimeNativeBehavior,
        RuntimeDefaultValidators,
        ServerRuntimeDefaults,
        RuntimeSmallHost,
        FoundationAdmission,
        FoundationSudoDiscovery,
        FoundationValidators,
        SupportedFoundationResume,
        PlainL0Discovery,
        EgressControl,
        MirrorNixSignature,
        NginxStanding,
        ApacheStanding,
        AptPhpStanding,
        EarlierBarectlStanding,
        UnsupportedUbuntuStanding,
        NixBuildUserCollision,
        PartialNixInstall,
        AptDailyActive,
    )
    # Django's native scenario discovery scans these classes; ConfigParser calls its override.
    _http_native_scenarios = (
        SitePHPServing,
        SitePHPIsolation,
        SiteMasterWorkerChurn,
        DiagnosticProbeAtIdleBoundary,
        ForeignPHPAdmission,
        SitePHPQueuedDrain,
        SitePHPLongDrain,
        SitePHPDetachedDrain,
        SiteNodeInterruptedTransition,
        SiteNodeSelection,
        SiteNodeValidators,
        JudgeByShape,
        TwoControllerNativeLock,
        FreshControllerReconstruction,
        HttpSiteNativeBehavior,
        HttpSiteTransactions,
        HttpSiteValidators,
        HttpSiteConsent,
        HttpSiteIdentityAdmission,
        HttpSiteReconstruction,
        RuntimeClientRetention,
        HttpSiteSecurityBehavior,
        HttpSiteControllerRecovery,
        SitePHPControllerRecovery,
        SitePHPPartialFilesystemFinish,
        SitePHPPartialFilesystemReverse,
    )
    _pool_parser_override = PoolParser.optionxform
    # The master's pool listing lives in the packed native body that every site transcript
    # records verbatim; removing it would change the payload bytes and require re-recording
    # every site transcript.
    _packed_pool_body = (membership,)
    # The fixed PHP payload invokes its entry point; Caddy rendering formats the socket property.
    _site_php_payload = switch_php
    _private_admission_template = SiteSettings.proxy_socket
    # JSON wire schemas are read through string keys, so these field symbols are dynamic uses.
    _native_wire_fields = SimpleNamespace()
    _native_json_uses = (
        _native_wire_fields.disk_digest,
        _native_wire_fields.next_id,
        _native_wire_fields.next_proxy_id,
        _native_wire_fields.validation,
        _native_wire_fields.master_present,
        _native_wire_fields.pool_validation,
    )
    # Transcript replay tests are found by Django's test discovery.
    _snapshot_validator_selection = HttpSiteValidators.validator
    _host_standing_transcripts = (RecordedHostStandingTests, RecordedHttpSiteTests)

    # Django validates these saved connection fields through clean_<field> names.
    _saved_connection_fields = (
        ServerForm.clean_address,
        ServerForm.clean_username,
        ServerForm.clean_port,
    )
    # templates/servers/_connection.html presents this recorded dispatch delay.
    _saved_connection_worker_delay = AttemptView.worker_unavailable
    # Registration forms and their history/audit templates read these fields dynamically.
    _connection_revision_presentation = (
        ServerForm.expected_revision,
        ServerForm.credential_catalogue,
        AttemptView.original_target,
        AttemptView.older_connection,
    )
