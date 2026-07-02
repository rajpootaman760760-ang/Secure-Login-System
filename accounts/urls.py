from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("2fa/setup/", views.setup_2fa_view, name="setup_2fa"),
    path("2fa/disable/", views.disable_2fa_view, name="disable_2fa"),
    path("2fa/verify/", views.verify_2fa_view, name="verify_2fa"),
]
