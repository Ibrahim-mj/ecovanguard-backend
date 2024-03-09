import datetime

import jwt

from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.db import transaction
from django.conf import settings
from django.http import HttpRequest

import cloudinary

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
    username = models.CharField(unique=True, max_length=255, blank=True, null=True)
    full_name = models.CharField(max_length=255)
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
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            },
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        return token

    def get_tokens_for_user(self):
        """
        Generates refresh and access tokens for user
        """
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    membership_id = models.CharField(max_length=255, unique=True)
    age = models.PositiveIntegerField(null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    city_of_residence = models.CharField(max_length=255, null=True, blank=True)
    profile_picture = models.URLField(blank=True, null=True)
    branch = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=255, null=True, blank=True)
    year_of_admission = models.DateField(null=True, blank=True)
    year_of_graduation = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Fields for UniversityStudentProfile
    institution = models.CharField(max_length=255, null=True, blank=True)
    faculty = models.CharField(max_length=255, null=True, blank=True)
    department = models.CharField(max_length=255, null=True, blank=True)
    level = models.CharField(max_length=255, null=True, blank=True)

    # Fields for SecondaryStudentProfile
    school_name = models.CharField(max_length=255, null=True, blank=True)
    school_location = models.CharField(max_length=255, null=True, blank=True)
    student_class = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        ordering = ["membership_id"]

    def __str__(self):
        return self.user.full_name


class ExecutivePosition(models.Model):
    position = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.position


class ExecutiveProfile(UserProfile):
    position = models.ForeignKey(ExecutivePosition, on_delete=models.PROTECT, null=True, blank=True)
