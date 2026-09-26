from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path

from dashboard.forms import SignInForm
from servers.views import server_add, server_edit, server_list

urlpatterns = [
    path("", server_list, name="servers"),
    path("servers/add/", server_add, name="server_add"),
    path("servers/<int:pk>/edit/", server_edit, name="server_edit"),
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(authentication_form=SignInForm),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
]
