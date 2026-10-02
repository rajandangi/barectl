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
from databases.views import server_database_plans, server_database_prepare
from servers.views import (
    activity,
    server_add,
    server_detail,
    server_discovery,
    server_edit,
    server_list,
    server_remove,
    server_verify,
)
from sites.views import server_site_plans, server_site_prepare
from tls.views import (
    server_challenge_prepare,
    server_readiness_prepare,
    server_setup_prepare,
    server_staging_prepare,
    server_tls_plans,
)

urlpatterns = [
    path("", server_list, name="servers"),
    path("activity/", activity, name="activity"),
    path("servers/add/", server_add, name="server_add"),
    path("servers/<int:pk>/", server_detail, name="server_detail"),
    path("servers/<int:pk>/edit/", server_edit, name="server_edit"),
    path("servers/<int:pk>/discovery/", server_discovery, name="server_discovery"),
    path("servers/<int:pk>/verify/", server_verify, name="server_verify"),
    path("servers/<int:pk>/remove/", server_remove, name="server_remove"),
    path("servers/<int:pk>/plans/", server_plans, name="server_plans"),
    path("servers/<int:pk>/plans/prepare/", server_prepare, name="server_prepare"),
    path("servers/<int:pk>/sites/", server_site_plans, name="server_site_plans"),
    path("servers/<int:pk>/sites/prepare/", server_site_prepare, name="server_site_prepare"),
    path("servers/<int:pk>/databases/", server_database_plans, name="server_database_plans"),
    path(
        "servers/<int:pk>/databases/prepare/",
        server_database_prepare,
        name="server_database_prepare",
    ),
    path("servers/<int:pk>/tls/", server_tls_plans, name="server_tls_plans"),
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
        "servers/<int:pk>/tls/staging/prepare/",
        server_staging_prepare,
        name="server_staging_prepare",
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
