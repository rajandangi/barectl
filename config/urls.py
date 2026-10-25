from django.contrib.auth import views as auth_views
from django.urls import path
from django.views.generic import RedirectView

from bootstrap.certificate_email_views import prepare_certificate_email
from cache.views import object_cache_prepare
from dashboard.forms import SignInForm
from dashboard.settings_views import settings_page
from databases.site_views import prepare_site_database
from databases.views import database_prepare
from laravel.settings_views import prepare_environment
from logs.views import log_page, prepare_rotation, read_log
from operations.views import (
    change_apply,
    change_detail,
    change_prepare_again,
    run_acknowledge,
    run_check,
    run_detail,
    run_status,
    server_change_prepare,
)
from runtimes.defaults_views import prepare_default
from servers.views import (
    activity,
    activity_rows,
    server_add,
    server_confirm_host,
    server_detail,
    server_discovery,
    server_edit,
    server_list,
    server_remove,
    server_status,
    server_verify,
    site_detail,
)
from sites.deploy_views import prepare_deploy, prepare_rollback, save_deploy_settings
from sites.domains_views import prepare_domains
from sites.node_views import prepare_node
from sites.php_views import prepare_php
from sites.pool_views import prepare_pool
from sites.readiness_views import prepare_readiness
from sites.remove_views import prepare_remove
from sites.views import (
    server_http_site_prepare,
    server_laravel_site_prepare,
    server_wordpress_site_prepare,
    site_create,
    site_create_continue,
    site_create_platform,
    site_list,
)
from wordpress.settings_views import prepare_settings as prepare_wordpress_settings
from wordpress.views import prepare_core, prepare_password

urlpatterns = [
    path(
        "servers/<int:pk>/sites/<str:identifier>/runtime/php/prepare/",
        prepare_php,
        name="site_php_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/runtime/node/prepare/",
        prepare_node,
        name="site_node_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/runtime/php-settings/prepare/",
        prepare_pool,
        name="site_pool_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/readiness/prepare/",
        prepare_readiness,
        name="site_readiness_prepare",
    ),
    path(
        "servers/<int:pk>/settings/defaults/<str:family>/prepare/",
        prepare_default,
        name="runtime_default_prepare",
    ),
    path(
        "servers/<int:pk>/stack/defaults/<str:family>/prepare/",
        RedirectView.as_view(
            pattern_name="runtime_default_prepare", permanent=False, query_string=True
        ),
        name="runtime_default_prepare_legacy",
    ),
    path("sites/", site_list, name="sites"),
    path("sites/create/", site_create, name="site_create"),
    path(
        "servers/<int:pk>/sites/create/",
        site_create,
        name="server_site_create",
    ),
    path(
        "servers/<int:pk>/sites/create/continue/",
        site_create_continue,
        name="site_create_continue",
    ),
    path(
        "servers/<int:pk>/sites/create/<str:platform>/",
        site_create_platform,
        name="site_create_platform",
    ),
    path("", server_list, name="servers"),
    path("activity/", activity, name="activity"),
    path("activity/rows/", activity_rows, name="activity_rows"),
    path("settings/", settings_page, name="settings"),
    path("servers/add/", server_add, name="server_add"),
    path("servers/<int:pk>/", server_detail, name="server_detail"),
    path(
        "servers/<int:pk>/setup/",
        RedirectView.as_view(pattern_name="server_detail", permanent=False),
        name="server_setup",
    ),
    path(
        "servers/<int:pk>/activity/", server_detail, {"section": "activity"}, name="server_activity"
    ),
    path(
        "servers/<int:pk>/advanced/", server_detail, {"section": "advanced"}, name="server_advanced"
    ),
    path("servers/<int:pk>/sites/", server_detail, {"section": "sites"}, name="server_sites"),
    path(
        "servers/<int:pk>/stack/",
        RedirectView.as_view(pattern_name="server_advanced", permanent=False, query_string=True),
        name="server_stack",
    ),
    path(
        "servers/<int:pk>/settings/",
        server_detail,
        {"section": "settings"},
        name="server_settings",
    ),
    path(
        "servers/<int:pk>/settings/database/prepare/",
        database_prepare,
        name="database_prepare",
    ),
    path(
        "servers/<int:pk>/settings/object-cache/prepare/",
        object_cache_prepare,
        name="object_cache_prepare",
    ),
    path(
        "servers/<int:pk>/settings/certificate-email/prepare/",
        prepare_certificate_email,
        name="certificate_email_prepare",
    ),
    path("servers/<int:pk>/edit/", server_edit, name="server_edit"),
    path("servers/<int:pk>/discovery/", server_discovery, name="server_discovery"),
    path("servers/<int:pk>/status/", server_status, name="server_status"),
    path("servers/<int:pk>/confirm-host/", server_confirm_host, name="server_confirm_host"),
    path("servers/<int:pk>/verify/", server_verify, name="server_verify"),
    path("servers/<int:pk>/remove/", server_remove, name="server_remove"),
    path(
        "servers/<int:pk>/sites/http/prepare/",
        server_http_site_prepare,
        name="server_http_site_prepare",
    ),
    path(
        "servers/<int:pk>/sites/laravel/prepare/",
        server_laravel_site_prepare,
        name="server_laravel_site_prepare",
    ),
    path(
        "servers/<int:pk>/sites/wordpress/prepare/",
        server_wordpress_site_prepare,
        name="server_wordpress_site_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/",
        site_detail,
        {"section": "overview"},
        name="site_detail",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/runtime/",
        RedirectView.as_view(pattern_name="site_settings", permanent=False),
        name="site_runtime",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/logs/",
        site_detail,
        {"section": "logs"},
        name="site_logs",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/logs/read/",
        read_log,
        name="site_log_read",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/logs/page/",
        log_page,
        name="site_log_page",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/logs/rotation/prepare/",
        prepare_rotation,
        name="site_log_rotation_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/deployments/",
        site_detail,
        {"section": "deployments"},
        name="site_deployments",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/deployments/deploy/prepare/",
        prepare_deploy,
        name="site_deploy_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/deployments/rollback/prepare/",
        prepare_rollback,
        name="site_rollback_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/deployments/settings/",
        save_deploy_settings,
        name="site_deploy_settings",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/database/",
        site_detail,
        {"section": "database"},
        name="site_database",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/settings/",
        site_detail,
        {"section": "settings"},
        name="site_settings",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/settings/domains/prepare/",
        prepare_domains,
        name="site_domains_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/settings/remove/prepare/",
        prepare_remove,
        name="site_remove_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/environment/",
        site_detail,
        {"section": "environment"},
        name="site_environment",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/environment/prepare/",
        prepare_environment,
        name="site_environment_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/",
        site_detail,
        {"section": "wordpress"},
        name="site_wordpress",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/settings/prepare/",
        prepare_wordpress_settings,
        name="site_wordpress_settings_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/password/prepare/",
        prepare_password,
        name="site_wordpress_password_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/core/prepare/",
        prepare_core,
        name="site_wordpress_core_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/database/prepare/",
        prepare_site_database,
        name="site_database_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/activity/",
        site_detail,
        {"section": "activity"},
        name="site_activity",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/advanced/",
        RedirectView.as_view(pattern_name="site_logs", permanent=False),
        name="site_advanced",
    ),
    path(
        "servers/<int:pk>/changes/",
        RedirectView.as_view(pattern_name="server_activity", permanent=False),
        name="server_changes",
    ),
    path(
        "servers/<int:pk>/changes/prepare/",
        server_change_prepare,
        name="server_change_prepare",
    ),
    path("changes/<int:operation_id>/", change_detail, name="change_detail"),
    path(
        "changes/<int:operation_id>/again/",
        change_prepare_again,
        name="change_prepare_again",
    ),
    path("changes/<int:operation_id>/apply/", change_apply, name="change_apply"),
    path("runs/<int:operation_id>/", run_detail, name="run_detail"),
    path("runs/<int:operation_id>/status/", run_status, name="run_status"),
    path("runs/<int:operation_id>/check/", run_check, name="run_check"),
    path("runs/<int:operation_id>/acknowledge/", run_acknowledge, name="run_acknowledge"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(authentication_form=SignInForm),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]
