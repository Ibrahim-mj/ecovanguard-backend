import datetime

import cloudinary

from django.contrib.auth import authenticate
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.core.validators import EmailValidator, RegexValidator

from google.auth.transport import requests
from google.oauth2 import id_token

from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import ValidationError

from .models import User, UserProfile, ExecutivePosition, ExecutiveProfile

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
    user_type = serializers.ChoiceField(choices=User.USER_TYPES, required=False)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "password",
            "full_name",
            "user_type",
            "is_active",
            "is_staff",
        )

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.user_type = validated_data["user_type"]
        user.save()
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


class UniversityStudentProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    profile_picture = serializers.ImageField(write_only=True, required=False)
    membership_id = serializers.CharField(read_only=True)

    class Meta:
        model = UserProfile
        fields = (
            "user",
            "membership_id",
            "age",
            "bio",
            "city_of_residence",
            "profile_picture",
            "branch",
            "phone_number",
            "year_of_admission",
            "year_of_graduation",
            "institution",
            "faculty",
            "department",
            "level",
            "created_at",
            "updated_at",
        )

    def create(self, validated_data):
        user = self.context.get("request").user
        user.user_type = User.USER_TYPES[1][0]
        user.save()
        profile = UserProfile.objects.create(user=user, **validated_data)
        return profile

    def validate_phone_number(self, value):
        phone_regex = RegexValidator(
            regex=r"^\+234\d{10}$",
            message="Phone number must be entered in the format: '+2341234567890'. Up to 14 digits allowed.",
        )
        phone_regex(value)
        return value

    # def validate_year_of_admission(self, value):
    #     if value < 1900 or value > datetime.now().year:
    #         raise serializers.ValidationError("Invalid year of admission.")
    #     return value

    # def validate_year_of_graduation(self, value):
    #     if value < 1900 or value > datetime.now().year + 6:
    #         raise serializers.ValidationError("Invalid year of graduation.")
    #     return value

    def validate_level(self, value):
        if value not in ["100", "200", "300", "400", "500", "600", "700", "800", "900"]:
            raise serializers.ValidationError("Invalid level.")
        return value

    def validate_city_of_residence(self, value):
        if len(value) < 3:
            raise serializers.ValidationError("City of residence is too short.")
        if value.isdigit():
            raise serializers.ValidationError("City of residence cannot be a number.")
        return value
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['profile_picture'] = instance.profile_picture if instance.profile_picture else None
        return representation

class ExecutiveProfileSerializer(UniversityStudentProfileSerializer):
    position = serializers.PrimaryKeyRelatedField(
        queryset=ExecutivePosition.objects.all(), required=False
    )
    class Meta(UniversityStudentProfileSerializer.Meta):
        model = ExecutiveProfile
        fields = UniversityStudentProfileSerializer.Meta.fields + ("position",)

    def create(self, validated_data):
        user = self.context.get("request").user
        user.user_type = User.USER_TYPES[0][0]
        user.save()
        profile = ExecutiveProfile.objects.create(user=user, **validated_data)
        return profile


class SecondaryStudentProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    profile_picture = serializers.ImageField(write_only=True, required=False)
    membership_id = serializers.CharField(read_only=True)

    class Meta:
        model = UserProfile
        fields = (
            "user",
            "membership_id",
            "age",
            "bio",
            "city_of_residence",
            "profile_picture",
            "branch",
            "phone_number",
            "year_of_admission",
            "year_of_graduation",
            "school_name",
            "school_location",
            "student_class",
            "created_at",
            "updated_at",
        )

    def create(self, validated_data):
        user = self.context.get("request").user
        user.user_type = User.USER_TYPES[2][0]
        user.save()
        profile = UserProfile.objects.create(user=user, **validated_data)
        return profile

    # def validate_age(self, value):
    #     if value < 18:
    #         raise serializers.ValidationError("Age must be at least 18.")
    #     return value

    def validate_phone_number(self, value):
        phone_regex = RegexValidator(
            regex=r"^\+234\d{10}$",
            message="Phone number must be entered in the format: '+2341234567890'. Up to 14 digits allowed.",
        )
        phone_regex(value)
        return value

    # def validate_year_of_admission(self, value):
    #     if value < 1900 or value > datetime.now().year:
    #         raise serializers.ValidationError("Invalid year of admission.")
    #     return value

    # def validate_year_of_graduation(self, value):
    #     if value < 1900 or value > datetime.now().year + 6:
    #         raise serializers.ValidationError("Invalid year of graduation.")
    #     return value

    def validate_student_class(self, value):
        if value not in ["JSS1", "JSS2", "JSS3", "SS1", "SS2", "SS3"]:
            raise serializers.ValidationError("Invalid student class. Class must be in the format: JSS1, JSS2, JSS3, SS1, SS2, SS3")
        return value
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['profile_picture'] = instance.profile_picture if instance.profile_picture else None
        return representation


class ExecutivePositionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExecutivePosition
        fields = (
            "id",
            "position",
            "description",
        )


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


def handle_social_user(provider, email, name, *args, **kwargs):
    """
    Takes the name, email and provider of  a user coming from a social platform and creates an account for them if they do not have one
    """
    try:
        user = User.objects.get(email=email)
        if user.auth_provider != provider:
            if not user.is_active:
                user.auth_provider = provider
                user.is_active = True  # we can choose to verify them here instead of sending them back to the email verification route.
                # Apparently, is_active will be False if user used the email route to sign up without verifying their email
                # We can choose to delete this if we want to be deactivating some users so they do not use this opportunity to reactivate their accounts
                user.save()
                return generate_response(user)
            raise ValidationError(
                f"Please continue using the {user.auth_provider} route. You signed up with {user.auth_provider}"
            )
        return generate_response(user)
    except User.DoesNotExist:
        user = User.objects.create_user(
            email=email,
            full_name=name,
            password=get_random_string(
                50,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(-_=+)",
            ),
            is_active=True,
            auth_provider=provider,
            user_type=kwargs.get("user_type"),
        )
        return generate_response(user)


def generate_response(user):
    """
    Generates a response dictionary containing user data and tokens
    """
    return {
        "user": UserSerializer(user).data,
        "tokens": user.get_tokens_for_user(),
    }


class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer for Google authentication
    """

    auth_token = serializers.CharField()
    user_type = serializers.ChoiceField(choices=User.USER_TYPES)

    def validate_auth_token(self, auth_token):
        try:
            user_data = Google.validate(auth_token)
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
        user_type = self.validated_data.get("user_type")

        return handle_social_user(provider, email, name, user_type=user_type)

    def validate_user_type(self, user_type):
        if user_type not in User.USER_TYPES:
            raise serializers.ValidationError("Invalid user type.")
        if user_type == User.USER_TYPES[0]:
            raise serializers.ValidationError(
                "You cannot sign up as an executive here."
            )
        return user_type


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    redirect_url = serializers.CharField()

    class Meta:
        fields = ("email",)


class SetNewPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(
        min_length=8
    )  # TODO: Add validators to ensure strong password
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

class ResendVerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(
        validators=[
            EmailValidator(message="Please, Enter a valid email address"),
        ]
    ),
    redirect_url = serializers.CharField()


class ExecutiveCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating an executive account by the admin
    """

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

    class Meta:
        model = User
        fields = (
            "id",
            "full_name",
            "email",
        )
        read_only_fields = ("id",)

    def create(self, validated_data):
        password = get_random_string(10)
        validated_data["password"] = password
        validated_data["user_type"] = User.USER_TYPES[0][0]
        user = User.objects.create_user(**validated_data)
        user.is_active = True  # Since The user is a verified executive
        user.is_staff = True
        user.save()
        html_message = f"""
            <p>Dear {user.full_name},</p>

            <p>Your EcoVanguard executive account has been created successfully.</p>

            <p>Your login credentials are:</p>
            <ul>
                <li>Email: {user.email}</li>
                <li>Password: {password}</li>
            </ul>

            <p>Regards,</p>
            <p>Admin</p>
            """
        send_mail(
            subject="EcoVanguard - Executive Account Created Successfully",
            message=(
                f"Dear {user.full_name},\n\n"
                "Your EcoVanguard executive account has been created successfully.\n\n"
                "Your login credentials are:\n"
                f"Email: {user.email}\n"
                f"Password: {password}\n\n"
                "Regards,\n"
                "Admin"
            ),
            from_email="EcoVanguard Club",
            recipient_list=[user.email],
            fail_silently=False,
            html_message=html_message,
        )
        return user