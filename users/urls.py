from django.urls import path

from .views import (
    AccountCreationView,
    AccountVerificationView,
    ResendVerificationEmailView,
    LoginView,
    GoogleAuthView,
    RequestPasswordResetView,
    ResetPasswordTokenCheckView,
    ResetPasswordView,
    UserListView,
    UserDetailView,
    ExecutiveUserAccoutCreationView,
    UniversityStudentProfileView,
    UniversityStudentProfileDetailView,
    SecondaryStudentProfileView,
    SecondaryStudentProfileDetailView,
    ExecutiveProfileView,
    ExecutiveProfileDetailView,
    ExecutivePositionView,
    ExecutivePositionDetailView,
)

app_name = "users"
urlpatterns = [
    path("register/", AccountCreationView.as_view(), name="register"),
    path("verify/<str:token>/", AccountVerificationView.as_view(), name="verify-email"),
    path('resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path("login/", LoginView.as_view(), name="login"),
    path("google/", GoogleAuthView.as_view(), name="google-auth"),
    path(
        "request-password-reset/",
        RequestPasswordResetView.as_view(),
        name="request-password-reset",
    ),
    path(
        "password-reset-check/<str:token>/",
        ResetPasswordTokenCheckView.as_view(),
        name="password-reset-check",
    ),
    path("reset-password/", ResetPasswordView.as_view(), name="reset-password"),
    path("users-list/", UserListView.as_view(), name="user-list"),
    path("user-detail/<int:pk>/", UserDetailView.as_view(), name="user-detail"),
    path(
        "create-executive-account/",
        ExecutiveUserAccoutCreationView.as_view(),
        name="create-executive-account",
    ),
    path(
        "university-student-profile/",
        UniversityStudentProfileView.as_view(),
        name="university-student-profile",
    ),
    path(
        "university-student-profile/<int:pk>/",
        UniversityStudentProfileDetailView.as_view(),
        name="university-student-profile-detail",
    ),
    path(
        "secondary-student-profile/",
        SecondaryStudentProfileView.as_view(),
        name="secondary-student-profile",
    ),
    path(
        "secondary-student-profile/<int:pk>/",
        SecondaryStudentProfileDetailView.as_view(),
        name="secondary-student-profile-detail",
    ),
    path(
        "executive-profile/",
        ExecutiveProfileView.as_view(),
        name="executive-profile",
    ),
    path(
        "executive-profile/<int:pk>/",
        ExecutiveProfileDetailView.as_view(),
        name="executive-profile-detail",
    ),
    path(
        "executive-position/",
        ExecutivePositionView.as_view(),
        name="executive-position",
    ),
    path(
        "executive-position/<int:pk>/",
        ExecutivePositionDetailView.as_view(),
        name="executive-position-detail",
    ),
]
