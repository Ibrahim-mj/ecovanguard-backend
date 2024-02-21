import jwt

from django.conf import settings

from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

# from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import User
from .serializers import (
    UserSerializer,
    GoogleAuthSerializer,
    PasswordResetSerializer,
    SetNewPasswordSerializer,
)


class AccountCreationView(generics.CreateAPIView):
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.send_verification_email(request)
        message = {
            "message": "Your account has been created. Kindly check your email for verification link."
        }
        return Response(message, status=status.HTTP_201_CREATED)


class AccountVerificationView(generics.RetrieveAPIView):

    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_object(self):
        """
        Decodes the token and gets the user object
        """

        token = self.kwargs.get("token")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(pk=payload["id"])
        except jwt.ExpiredSignatureError:
            raise ValueError("Verification link has expired. Please request a new one.")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token. Please request a new one.")
        return user

    def retrieve(self, request, *args, **kwargs):
        """
        Activates the user account
        """
        try:
            user = self.get_object()
            user.is_active = True
            user.save()
            message = {"message": "Your account has been verified. You can now login."}
            return Response(message, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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


class GoogleAuthView(generics.CreateAPIView):
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
    Sends a password reset link to the user's email
    """

    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()
        if user:
            if user.auth_provider != User.AUTH_PROVIDERS["email"]:
                message = {"error": "You did not sign up with email and password"}
                return Response(message, status=status.HTTP_400_BAD_REQUEST)
            elif user.is_active:
                user.send_password_reset_email(request)
                message = {
                    "message": "A password reset link has been sent to your email."
                }
                return Response(message, status=status.HTTP_200_OK)

        else:
            message = {"message": "No active user with that email exists."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(generics.GenericAPIView):
    """
    Resets the user's password
    """

    serializer_class = SetNewPasswordSerializer

    def post(self, request, *args, **kwargs):
        token = self.kwargs.get("token")
        password = request.data.get("password")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(pk=payload["id"])
            user.set_password(password)
            user.save()
            message = {"message": "Your password has been reset."}
            return Response(message, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            message = {
                "message": "Password reset link has expired. Please request a new one."
            }
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            message = {"message": "Invalid token. Please request a new one."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            message = {"message": "User does not exist."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
