# TODO: Add docstrings to all views and handle permissions for each view properly
# Write one function to send email whenever the email template is ready and use it in all views that send email

import jwt
import cloudinary

from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.mail import send_mail
from django.urls import reverse
from django.shortcuts import redirect, get_object_or_404

from rest_framework import generics
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated, IsAdminUser

# from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import User, UserProfile, ExecutivePosition, ExecutiveProfile
from .serializers import (
    UserSerializer,
    GoogleAuthSerializer,
    PasswordResetSerializer,
    SetNewPasswordSerializer,
    ExecutiveCreateSerializer,
    UniversityStudentProfileSerializer,
    SecondaryStudentProfileSerializer,
    ExecutiveProfileSerializer,
    ExecutivePositionSerializer,
    ResendVerificationEmailSerializer,
)


class AccountCreationView(generics.CreateAPIView):
    """
    Creates account for user and send verification email to them.
    Takes in redirect_url as query parameter to include in the verification link.
    """

    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = user.generate_jwt_token()
        subject = "EcoVanguard Club - Verify your email"
        redirect_url = self.request.query_params.get(
            "redirect_url", ""
        )  # Gets redirect URL if provided
        base_url = request.build_absolute_uri(
            reverse("users:verify-email", kwargs={"token": token})
        )
        if redirect_url:
            verification_link = f"{base_url}?redirect_url={redirect_url}"  # Adds redirect URL to verification link if provided
        else:
            verification_link = base_url
        message = f"Hello {user.full_name},\n\nWelcome to EcoVanguard Club. Please verify your email by clicking on the link below:\n\n{verification_link}\n\n This link will expire in 24 hours.\n\nIf you did not register for an account, please ignore this email.\n\nBest regards,\nEcoVanguard Club"
        html_message = f"<p>Hello {user.full_name},</p><p>Welcome to EcoVanguard Club. Please verify your email by clicking on the link below:</p><p><a href='{verification_link}'>Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not register for an account, please ignore this email.</p><p>Best regards,<br>EcoVanguard Club</p>"

        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
            )
            message = {
                "message": "Your account has been created. Kindly check your email for verification link."
            }
            return Response(message, status=status.HTTP_201_CREATED)
        except Exception as e:
            user.delete()
            message = {
                "error": f"An error occurred while sending the verification email. {e}. Please try again later."
            }
            return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AccountVerificationView(generics.RetrieveAPIView):
    """
    Handles decoding of verification token and verifies user if valid.
    Redirects the user to the provided redirect URL in the verification link. Example: https://redirect-url?verified=true or https://redirect-url?verified=false
    Else, redirects to https://localhost:5173/login?verified=true or https://localhost:5173/login?verified=false&exception=error_message
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_object(self):
        """
        Decodes the token and gets the user object
        """

        token = self.kwargs.get("token")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
        except jwt.ExpiredSignatureError:
            raise ValueError("Verification link has expired. Please request a new one.")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token. Please request a new one.")
        return user

    def retrieve(self, request, *args, **kwargs):
        """
        Activates the user account
        """
        redirect_url = request.query_params.get("redirect_url", "")
        try:
            user = self.get_object()
            user.is_active = True
            user.save()
            if redirect_url:
                redirect_url = f"{redirect_url}?verified=true"
                return HttpResponseRedirect(redirect_url)
            else:
                redirect_url = f"{settings.FRONTEND_URL}/login?verified=true"
                return HttpResponseRedirect(redirect_url)
        except Exception as e:
            redirect_url = f"{settings.FRONTEND_URL}/login?verified=false&exception={e}"
            return HttpResponseRedirect(redirect_url)

class ResendVerificationEmailView(generics.GenericAPIView):
    """
    Takes email address, redirect_url and resend verification email to user.
    """
    serializer_class = ResendVerificationEmailSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        redirect_url = request.dat.get('redirect_url')
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({"message": "Account is already verified."}, status=status.HTTP_400_BAD_REQUEST)
            token = user.generate_jwt_token()
            subject = "EcoVanguard Club - Verify your email"
            base_url = request.build_absolute_uri(
                reverse("users:verify-email", kwargs={"token": token})
            )
            if redirect_url:
                verification_link = f"{base_url}?redirect_url={redirect_url}"  # Adds redirect URL to verification link if provided
            else:
                verification_link = base_url
            message = f"Hello {user.full_name},\n\nPlease verify your email by clicking on the link below:\n\n{verification_link}\n\n This link will expire in 24 hours.\n\nIf you did not request a new verification email, please ignore this email.\n\nBest regards,\nEcoVanguard Club"
            html_message = f"<p>Hello {user.full_name},</p><p>Please verify your email by clicking on the link below:</p><p><a href='{verification_link}'>Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not request a new verification email, please ignore this email.</p><p>Best regards,<br>EcoVanguard Club</p>"
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
            )
            return Response({"message": "Verification email has been sent."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An error occurred while sending the verification email. {e}. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(TokenObtainPairView):

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh = response.data["refresh"]
        access = response.data["access"]
        tokens = {"refresh": str(refresh), "access": str(access)}
        user = User.objects.get(email=request.data["email"])
        user_info = UserSerializer(user).data
        response.data = {"user": user_info, "tokens": tokens}
        return response

    # TODO: Restrict this endpoint to users who registered with email and password


class GoogleAuthView(
    generics.CreateAPIView
):  # TODO: Make sure executives can't use this endpoint
    """
    Endpoint for Google authentication
    Accepts the Google ID token and returns the user's information after doing the necessary checks
    """

    serializer_class = GoogleAuthSerializer

    def post(self, request, *args, **kwargs):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        return Response(
            data["auth_token"], status=status.HTTP_200_OK
        )  # To maintain uniformity in response


class RequestPasswordResetView(generics.GenericAPIView):
    """
    Sends a password reset link to the provided email if user with that email exists
    Includes redirect_url in the link, if provided.
    """

    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        redirect_url = request.data.get("redirect_url", "")
        user = User.objects.filter(email=email).first()
        if user:
            if user.auth_provider != User.AUTH_PROVIDERS["email"]:
                message = {"error": "You did not sign up with email and password"}
                return Response(message, status=status.HTTP_400_BAD_REQUEST)
            elif user.is_active:
                token = user.generate_jwt_token()
                subject = "EcoVanguard Club - Reset your password"
                absolute_link = request.build_absolute_uri(
                    reverse("users:password-reset-check", kwargs={"token": token})
                )
                password_reset_link = f"{absolute_link}?redirect_url={redirect_url}"

                message = f"Hello {user.full_name},\n\nYou requested a password reset. Please reset your password by clicking on the link below:\n\n{password_reset_link}\n\n This link will expire in 24 hours.\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nEcoVanguard Club"
                html_message = f"<p>Hello {user.full_name},</p><p>You requested a password reset. Please reset your password by clicking on the link below:</p><p><a href='{password_reset_link}'>Reset Password</a></p><p>This link will expire in 24 hours.</p><p>If you did not request a password reset, please ignore this email.</p><p>Best regards,<br>EcoVanguard Club</p>"

                try:
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        html_message=html_message,
                    )
                except Exception as e:
                    return {"detail": f"An error occurred while sending the password reset email. {e}. Please try again later."}
                message = {
                    "detail": "A password reset link has been sent to your email."
                }
                return Response(message, status=status.HTTP_200_OK)

        else:
            message = {"message": "No active user with that email exists."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)


def is_valid_jwt(token):
    """Checks for validity of a JWT token"""
    try:
        jwt.get_unverified_header(token)
        return True
    except jwt.InvalidTokenError:
        return False


class ResetPasswordTokenCheckView(generics.GenericAPIView):
    """
    Checks the validity of the password reset token
    Redirects to the provided redirect URL with the token and token_valid query parameters
    Else, it assumes the redirect_url is http://localhost:5173
    """

    serializer_class = SetNewPasswordSerializer

    def get(self, request, *args, **kwargs):
        token = self.kwargs.get("token")
        redirect_url = request.query_params.get("redirect_url", getattr(settings, 'FRONTEND_URL', 'http://localhost:5173'))
        try:
            token_is_valid = is_valid_jwt(token)
            if token_is_valid:
                return HttpResponseRedirect(f"{redirect_url}?token={token}&token_valid=True")
            else:
                return HttpResponseRedirect(f"{redirect_url}?token_valid=False")
        except jwt.InvalidTokenError:
            return HttpResponseRedirect(f"{redirect_url}?token_valid=False")
class ResetPasswordView(generics.GenericAPIView):
    """
    Takes the token and a new password and resets the user's password
    """

    serializer_class = SetNewPasswordSerializer

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = request.data.get("token")
        password = serializer.validated_data["password"]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(pk=payload["id"])
            user.set_password(password)
            user.save()
            message = {"details": "Password reset successful."}
            return Response(message, status=status.HTTP_200_OK)
        except jwt.InvalidTokenError:
            message = {"details": "Invalid token. Please request a new one."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)


class UserListView(generics.ListAPIView):
    """Returns Only activated Users"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # TODO Restrict to only executive users
    # authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        queryset = User.objects.filter(is_active=True)
        user_type = self.request.query_params.get("user_type", None)
        if user_type is not None:
            queryset = queryset.filter(user_type=user_type)
        return queryset


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Returns Only activated Users"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # TODO Restrict to only executive users
    # authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        queryset = User.objects.filter(is_active=True)
        return queryset

    def get_object(self):
        user = self.get_queryset().get(pk=self.kwargs.get("pk"))
        if user:
            return user
        raise ValueError("User does not exist or is not verified.")


class ExecutiveUserAccoutCreationView(generics.CreateAPIView):
    """
    This allows an admin to create an account for an executive user
    """

    serializer_class = ExecutiveCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        message = {"message": f"Account created successfully. Ask {user.full_name[0]} to check their email"}
        return Response(message, status=status.HTTP_201_CREATED)

class FileUploadMixin:
    """
    Provides a method for handling profile picture uploads
    """

    def _handle_profile_picture_upload(self, data, instance=None, partial=False):
        serializer = self.get_serializer(instance, data=data, partial=partial)
        if serializer.is_valid(raise_exception=True):
            try:
                profile_picture = data["profile_picture"]
                file_url = cloudinary.uploader.upload(
                    profile_picture, folder="EcoVanguard"
                )["secure_url"]
                serializer.save(profile_picture=file_url)
            except KeyError:
                serializer.save(profile_picture=None)
            return Response(
                serializer.data,
                status=status.HTTP_200_OK if instance else status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UniversityStudentProfileView(FileUploadMixin, generics.CreateAPIView):
    """
    This handles the creation of a university student profile
    """

    serializer_class = UniversityStudentProfileSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(request.data)


class UniversityStudentProfileDetailView(FileUploadMixin, generics.RetrieveUpdateAPIView):
    """
    This handles the retrieval, update and deletion of a university student profile
    """

    serializer_class = UniversityStudentProfileSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserProfile.objects.all()

    def get_object(self):
        user_id = self.kwargs.get('pk')
        user = get_object_or_404(User, pk=user_id)
        profile = get_object_or_404(UserProfile, user=user)
        return profile
    
    def patch(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(
            request.data, instance=self.get_object(), partial=True
        )


class SecondaryStudentProfileView(FileUploadMixin, generics.CreateAPIView):
    """
    This handles the creation of a secondary student profile
    """

    serializer_class = SecondaryStudentProfileSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(request.data)


class SecondaryStudentProfileDetailView(FileUploadMixin, generics.RetrieveUpdateAPIView):
    """
    This handles the retrieval and update of a secondary student profile
    """

    serializer_class = SecondaryStudentProfileSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserProfile.objects.all()

    def get_object(self):
        user_id = self.kwargs.get('pk')
        user = get_object_or_404(User, pk=user_id)
        profile = get_object_or_404(UserProfile, user=user)
        return profile

    def patch(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(
            request.data, instance=self.get_object(), partial=True
        )


class ExecutiveProfileView(FileUploadMixin, generics.CreateAPIView):
    """
    This handles the creation of an executive profile
    """

    serializer_class = ExecutiveProfileSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(request.data)


class ExecutiveProfileDetailView(FileUploadMixin, generics.RetrieveUpdateAPIView):
    """
    This handles the retrieval and update of an executive profile
    """

    serializer_class = ExecutiveProfileSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserProfile.objects.all()

    def get_object(self):
        user_id = self.kwargs.get('pk')
        user = get_object_or_404(User, pk=user_id)
        profile = get_object_or_404(UserProfile, user=user)
        return profile

    def patch(self, request, *args, **kwargs):
        return self._handle_profile_picture_upload(
            request.data, instance=self.get_object(), partial=True
        )


class ExecutivePositionView(generics.ListCreateAPIView):
    """
    This handles the list and creation of an executive position
    """

    serializer_class = ExecutivePositionSerializer
    permission_classes = [IsAuthenticated]


class ExecutivePositionDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    This handles the retrieval, update and deletion of an executive position
    """

    serializer_class = ExecutivePositionSerializer
    permission_classes = [IsAuthenticated]