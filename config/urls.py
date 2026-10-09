from django.contrib.auth import views as auth_views
from django.urls import path

from bootstrap.views import (
    apply_acknowledge,
    apply_check,
    apply_detail,
    apply_status,
    plan_apply,
    plan_detail,
    server_plans,
    server_prepare,
)
from dashboard.forms import SignInForm
from databases.views import (
    server_database_plans,
    server_database_prepare,
    site_database_plans,
    site_database_prepare,
)
from servers.views import (
    activity,
    server_add,
    server_detail,
    server_discovery,
    server_edit,
    server_list,
    server_remove,
    server_verify,
    site_detail,
)
from sites.views import server_site_plans, server_site_prepare
from tls.views import (
    server_activation_prepare,
    server_certificate_install,
    server_challenge_prepare,
    server_issuance_prepare,
    server_readiness_prepare,
    server_setup_prepare,
    server_staging_prepare,
    server_tls_plans,
    site_certificate_install,
    site_installation_progress,
    site_readiness_plans,
    site_readiness_prepare,
)
from wordpress.inspection_views import site_inspection_plans, site_inspection_prepare
from wordpress.maintenance_views import site_maintenance_plans, site_maintenance_prepare
from wordpress.views import (
    server_wordpress_plans,
    server_wpcli_prepare,
    site_finish_plans,
    site_finish_prepare,
    site_install_plans,
    site_install_prepare,
    site_runtime_plans,
    site_runtime_prepare,
)

urlpatterns = [
    path("", server_list, name="servers"),
    path("activity/", activity, name="activity"),
    path("servers/add/", server_add, name="server_add"),
    path("servers/<int:pk>/", server_detail, name="server_detail"),
    path("servers/<int:pk>/setup/", server_detail, {"section": "setup"}, name="server_setup"),
    path(
        "servers/<int:pk>/activity/", server_detail, {"section": "activity"}, name="server_activity"
    ),
    path(
        "servers/<int:pk>/advanced/", server_detail, {"section": "advanced"}, name="server_advanced"
    ),
    path("servers/<int:pk>/sites/", server_site_plans, name="server_sites"),
    path("servers/<int:pk>/edit/", server_edit, name="server_edit"),
    path("servers/<int:pk>/discovery/", server_discovery, name="server_discovery"),
    path("servers/<int:pk>/verify/", server_verify, name="server_verify"),
    path("servers/<int:pk>/remove/", server_remove, name="server_remove"),
    path("servers/<int:pk>/plans/", server_plans, name="server_plans"),
    path("servers/<int:pk>/plans/prepare/", server_prepare, name="server_prepare"),
    path("servers/<int:pk>/sites/prepare/", server_site_prepare, name="server_site_prepare"),
    path(
        "servers/<int:pk>/sites/<str:identifier>/overview/",
        site_detail,
        {"section": "overview"},
        name="site_detail",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/database/",
        site_detail,
        {"section": "database"},
        name="site_database",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/https/",
        site_detail,
        {"section": "https"},
        name="site_https",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/",
        site_detail,
        {"section": "wordpress"},
        name="site_wordpress",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/activity/",
        site_detail,
        {"section": "activity"},
        name="site_activity",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/advanced/",
        site_detail,
        {"section": "advanced"},
        name="site_advanced",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/runtime/",
        site_runtime_plans,
        name="site_runtime_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/runtime/prepare/",
        site_runtime_prepare,
        name="site_runtime_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/install/",
        site_install_plans,
        name="site_install_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/install/prepare/",
        site_install_prepare,
        name="site_install_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/finish/",
        site_finish_plans,
        name="site_finish_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/finish/prepare/",
        site_finish_prepare,
        name="site_finish_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/inspection/",
        site_inspection_plans,
        name="site_inspection_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/inspection/prepare/",
        site_inspection_prepare,
        name="site_inspection_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/maintenance/",
        site_maintenance_plans,
        name="site_maintenance_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/wordpress/maintenance/prepare/",
        site_maintenance_prepare,
        name="site_maintenance_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/database/plans/",
        site_database_plans,
        name="site_database_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/database/prepare/",
        site_database_prepare,
        name="site_database_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/https/readiness/",
        site_readiness_plans,
        name="site_readiness_plans",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/https/readiness/prepare/",
        site_readiness_prepare,
        name="site_readiness_prepare",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/https/install/",
        site_certificate_install,
        name="site_certificate_install",
    ),
    path(
        "servers/<int:pk>/sites/<str:identifier>/https/installation/",
        site_installation_progress,
        name="site_installation_progress",
    ),
    path("servers/<int:pk>/databases/", server_database_plans, name="server_database_plans"),
    path(
        "servers/<int:pk>/databases/prepare/",
        server_database_prepare,
        name="server_database_prepare",
    ),
    path("servers/<int:pk>/tls/", server_tls_plans, name="server_tls_plans"),
    path(
        "servers/<int:pk>/tls/install/",
        server_certificate_install,
        name="server_certificate_install",
    ),
    path(
        "servers/<int:pk>/tls/certbot/prepare/", server_setup_prepare, name="server_setup_prepare"
    ),
    path(
        "servers/<int:pk>/tls/challenge/prepare/",
        server_challenge_prepare,
        name="server_challenge_prepare",
    ),
    path(
        "servers/<int:pk>/tls/readiness/prepare/",
        server_readiness_prepare,
        name="server_readiness_prepare",
    ),
    path(
        "servers/<int:pk>/tls/activation/prepare/",
        server_activation_prepare,
        name="server_activation_prepare",
    ),
    path(
        "servers/<int:pk>/tls/issuance/prepare/",
        server_issuance_prepare,
        name="server_issuance_prepare",
    ),
    path(
        "servers/<int:pk>/tls/staging/prepare/",
        server_staging_prepare,
        name="server_staging_prepare",
    ),
    path(
        "servers/<int:pk>/wordpress/",
        server_wordpress_plans,
        name="server_wordpress_plans",
    ),
    path(
        "servers/<int:pk>/wordpress/wp-cli/prepare/",
        server_wpcli_prepare,
        name="server_wpcli_prepare",
    ),
    path("plans/<int:pk>/", plan_detail, name="plan_detail"),
    path("plans/<int:pk>/apply/", plan_apply, name="plan_apply"),
    path("applies/<int:pk>/", apply_detail, name="apply_detail"),
    path("applies/<int:pk>/status/", apply_status, name="apply_status"),
    path("applies/<int:pk>/check/", apply_check, name="apply_check"),
    path("applies/<int:pk>/acknowledge/", apply_acknowledge, name="apply_acknowledge"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(authentication_form=SignInForm),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]
