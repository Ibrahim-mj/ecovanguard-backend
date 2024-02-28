from django.contrib.auth import authenticate
from django.conf import settings
from django.utils.crypto import get_random_string

from .models import User
from .serializers import UserSerializer


def handle_social_user(provider, email, name):
    """
    Takes the name, email and provider of  a user coming from a social platform and creates an account for them if they do not have one
    """
    user, created = User.objects.get_or_create(
        email=email,
        password=settings.SOCIAL_AUTH_PASSWORD,
        defaults={"full_name": name, "auth_provider": provider},
    )
    # The password is passed as a parameter to the get_or_create method to avoid the error of not providing a password when creating a user
    # In the custom get_or_create method, the password is popped from the kwargs before calling the .get method to avoid potential error
    # TODO: Generate a random password for the user if not alreay existing and ensure compatibility withe previous code

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
                "tokens": logged_in_user.get_tokens_for_user,
            }
    else:
        user.is_active = True
        user.auth_provider = provider
        user.save()
        new_user = authenticate(email=email, password=settings.SOCIAL_AUTH_PASSWORD)
        return {
            "user": UserSerializer(new_user).data,
            "tokens": new_user.get_tokens_for_user,
        }
