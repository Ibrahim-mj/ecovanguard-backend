import datetime

from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth.password_validation import validate_password

# Everything above to be removed

from google.auth.transport import requests
from google.oauth2 import id_token

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from django.core.validators import EmailValidator, RegexValidator
from django.conf import settings

from .models import User

# from .utils import handle_social_user


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        validators=[
            EmailValidator(),
            UniqueValidator(
                queryset=User.objects.all(), message="Email already exists"
            ),
        ],
    )

    full_name = serializers.CharField(
        max_length=100,
        validators=[
            RegexValidator(
                r"^[a-zA-Z-' ]+$",
                "Name must include letters, hyphens, or apostrophes only",
            ),
        ],
        required=False,
    )
    password = serializers.CharField(write_only=True)
    age = serializers.IntegerField(required=False)
    city_of_residence = serializers.CharField(max_length=100, required=False)
    user_type = serializers.ChoiceField(choices=User.USER_TYPES)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "password",
            "full_name",
            "age",
            "city_of_residence",
            "user_type",
            "is_active",
            "is_staff",
        )

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    def get_fields(self):
        fields = super().get_fields()
        request = self.context.get("request")
        if request and getattr(request, "user", None):
            user = request.user
            if not user.is_staff:  # If not staff, remove these fields
                # fields.pop("is_superuser")
                fields.pop("is_staff")
                # fields.pop("user_type")
                fields.pop("is_active")
        return fields


class Google:
    """
    Class to check and validate user data from Google
    """

    @staticmethod
    def validate(auth_token):
        """
        Queries user info from Google and returns it
        """
        try:
            idinfo = id_token.verify_oauth2_token(auth_token, requests.Request())
            if idinfo["iss"] not in [
                "accounts.google.com",
                "https://accounts.google.com",
            ]:
                raise ValueError("Wrong issuer.")
            if idinfo["aud"] != settings.GOOGLE_CLIENT_ID:
                raise ValueError("Wrong client.")
            if (
                datetime.datetime.fromtimestamp(idinfo["exp"])
                < datetime.datetime.utcnow()
            ):
                raise ValueError("Token expired.")
            return idinfo
        except Exception as e:
            raise e


def handle_social_user(provider, email, name):
    """
    Takes the name, email and provider of  a user coming from a social platform and creates an account for them if they do not have one
    """
    user, created = User.objects.get_or_create(
        email=email,
        password=settings.SOCIAL_AUTH_PASSWORD,
        full_name=name,
        auth_provider=User.AUTH_PROVIDERS[provider],
    )
    # The password is passed as a parameter to the get_or_create method to avoid the error of not providing a password when creating a user
    # In the custom get_or_create method, the password is popped from the kwargs before calling the .get method to avoid potential error
    # TODO: Generate a random password for the user if not already existing and ensure compatibility withe previous code

    if not created:
        if user.auth_provider != provider:
            if not user.is_active:
                user.auth_provider = provider
                user.is_active = True  # we can choose to verify them here instead of sending them back to the email verification route.
                # Apparently, is_active will be False if user used the email route to sign up without verifying their email
                user.save()
            raise ValueError(
                f"Please continue using the {user.auth_provider} route. You signed up with {user.auth_provider}"
            )
        logged_in_user = authenticate(
            email=email, password=settings.SOCIAL_AUTH_PASSWORD
        )
        if logged_in_user:
            return {
                "user": UserSerializer(logged_in_user).data,
                "tokens": logged_in_user.get_tokens_for_user(),
            }
    else:
        user.is_active = True
        user.auth_provider = provider
        user.save()
        new_user = authenticate(email=email, password=settings.SOCIAL_AUTH_PASSWORD)
        return {
            "user": UserSerializer(new_user).data,
            "tokens": new_user.get_tokens_for_user(),
        }


class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer for Google authentication
    """

    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        try:
            user_data = Google.validate(auth_token)
            print(user_data)
        except Exception as e:
            raise serializers.ValidationError(str(e))
        if user_data["email_verified"] is False:
            raise serializers.ValidationError("The email is not verified by Google.")
        if user_data["aud"] != settings.GOOGLE_CLIENT_ID:
            raise serializers.ValidationError(
                "We could not verify your Google account. Please try again."
            )

        provider = "google"
        email = user_data["email"]
        name = user_data["name"] if user_data.get("name") else ""

        return handle_social_user(provider, email, name)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ("email",)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data
