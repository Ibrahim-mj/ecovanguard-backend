import datetime

import jwt

from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.urls import reverse
from django.db import transaction
from django.conf import settings

from rest_framework_simplejwt.tokens import RefreshToken


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    @transaction.atomic  # Ensures that the entire operation is atomic
    def get_or_create(self, **kwargs):
        password = kwargs.pop("password", None)
        try:
            return self.get(**kwargs), False
        except self.model.DoesNotExist:
            return self.create_user(**kwargs, password=password), True

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):

    USER_TYPES = (
        ("EXECUTIVE", "Executive"),
        ("UNIVERSITY_STUDENT", "University Student"),
        ("SECONDARY_STUDENT", "Secondary Student"),
    )

    AUTH_PROVIDERS = {
        "email": "email",
        "google": "google",
    }

    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    age = models.PositiveIntegerField(null=True, blank=True)
    city_of_residence = models.CharField(max_length=255, null=True, blank=True)
    user_type = models.CharField(
        max_length=255, choices=USER_TYPES, blank=True, null=True
    )
    auth_provider = models.CharField(max_length=255, default=AUTH_PROVIDERS["email"])
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.full_name

    def generate_jwt_token(self):
        token = jwt.encode(
            {
                "id": self.pk,
                "email": self.email,
                "full_name": self.full_name,
                "user_type": self.user_type,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            },
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        return token

    def send_verification_email(self, request):
        """Sends verification email to user"""

        # Generate verification token
        token = self.generate_jwt_token()

        # Send verification email
        subject = "EcoVanguard Club - Verify your email"
        site = get_current_site(request)
        verification_link = request.build_absolute_uri(
            reverse("users:verify-email", kwargs={"token": token})
        )
        message = f"Hello {self.full_name},\n\nWelcome to EcoVanguard Club. Please verify your email by clicking on the link below:\n\n{verification_link}\n\n This link will expire in 5 minutes.\n\nIf you did not register for an account, please ignore this email.\n\nBest regards,\nEcoVanguard Club"
        html_message = f"<p>Hello {self.full_name},</p><p>Welcome to EcoVanguard Club. Please verify your email by clicking on the link below:</p><p><a href='{verification_link}'>Verify Email</a></p><p>This link will expire in 5 minutes.</p><p>If you did not register for an account, please ignore this email.</p><p>Best regards,<br>EcoVanguard Club</p>"

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [self.email],
            html_message=html_message,
        )

    def get_tokens_for_user(self):
        """
        Generates refresh and access tokens for user
        """
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

    def send_password_reset_email(self, request):
        """Sends password reset email to user"""

        # Generate password reset token
        token = self.generate_jwt_token()

        # Send password reset email
        subject = "EcoVanguard Club - Reset your password"
        site = get_current_site(request)
        password_reset_link = request.build_absolute_uri(
            reverse("users:reset-password", kwargs={"token": token})
        )
        message = f"Hello {self.full_name},\n\nYou requested a password reset. Please reset your password by clicking on the link below:\n\n{password_reset_link}\n\n This link will expire in 5 minutes.\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nEcoVanguard Club"
        html_message = f"<p>Hello {self.full_name},</p><p>You requested a password reset. Please reset your password by clicking on the link below:</p><p><a href='{password_reset_link}'>Reset Password</a></p><p>This link will expire in 5 minutes.</p><p>If you did not request a password reset, please ignore this email.</p><p>Best regards,<br>EcoVanguard Club</p>"

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [self.email],
            html_message=html_message,
        )


class BaseUserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    bio = models.TextField()
    # profile_picture = models.ImageField(upload_to="profile_pictures/")
    branch = models.CharField(max_length=255)
    year_of_admission = models.DateField()
    year_of_graduation = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.full_name


class UniversityStudentProfile(BaseUserProfile):
    institution = models.CharField(max_length=255)
    faculty = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    level = models.CharField(max_length=255)


class ExecutiveProfile(UniversityStudentProfile):
    position = models.CharField(max_length=255)


class SecondaryStudentProfile(BaseUserProfile):
    school_name = models.CharField(max_length=255)
    school_location = models.CharField(max_length=255)
    student_class = models.CharField(max_length=255)
