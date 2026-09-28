from django.contrib.auth import views as auth_views
from django.urls import path

from bootstrap.views import (
    apply_check,
    apply_detail,
    plan_apply,
    plan_detail,
    server_plans,
    server_prepare,
)
from dashboard.forms import SignInForm
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
    path("plans/<int:pk>/", plan_detail, name="plan_detail"),
    path("plans/<int:pk>/apply/", plan_apply, name="plan_apply"),
    path("applies/<int:pk>/", apply_detail, name="apply_detail"),
    path("applies/<int:pk>/check/", apply_check, name="apply_check"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(authentication_form=SignInForm),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]
