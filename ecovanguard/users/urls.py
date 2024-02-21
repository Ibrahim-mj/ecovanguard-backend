from django.urls import path

from .views import (
    AccountCreationView,
    AccountVerificationView,
    LoginView,
    GoogleAuthView,
    RequestPasswordResetView,
    ResetPasswordView,
)

app_name = "users"
urlpatterns = [
    path("register/", AccountCreationView.as_view(), name="register"),
    path("verify/<str:token>/", AccountVerificationView.as_view(), name="verify-email"),
    path("login/", LoginView.as_view(), name="login"),
    path("google/", GoogleAuthView.as_view(), name="google-auth"),
    path(
        "request-password-reset/",
        RequestPasswordResetView.as_view(),
        name="request-password-reset",
    ),
    path(
        "reset-password/<str:token>/",
        ResetPasswordView.as_view(),
        name="reset-password",
    ),
]
