from .models import UserProfile, ExecutiveProfile
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings


def generate_membership_id():
    """
    Gets the last membership id and increments it by 1
    The format of the ID it returns is "Ecov-UI-001"
    """
    last_member = UserProfile.objects.all().order_by("membership_id").last()
    if not last_member:
        return "Ecov-UI-001"
    membership_id = last_member.membership_id
    membership_int = int(membership_id.split("-")[-1])
    new_membership_int = membership_int + 1
    new_membership_id = f"Ecov-UI-{new_membership_int:03}"
    return new_membership_id


@receiver(pre_save, sender=UserProfile)
def create_membership_id(sender, instance, **kwargs):
    if not instance.membership_id and not isinstance(
        instance, ExecutiveProfile
    ):  # This is to avoid creating membership id for executive profile
        instance.membership_id = generate_membership_id()


@receiver(pre_save, sender=ExecutiveProfile)
def create_executive_membership_id(sender, instance, **kwargs):
    if not instance.membership_id:
        instance.membership_id = generate_membership_id()

@receiver(post_save, sender=UserProfile)
def send_welcome_email(sender, instance, created, **kwargs):
    if created:
        name = instance.user.full_name[0]
        email = instance.user.email
        membership_id = instance.membership_id
        subject = "EcoVaguard Club UI - Welcome!!!"
        message = f"Hello {name},\n\nWelcome to EcoVaguard Club UI. Your membership ID is {membership_id}."
        html_message = f"<p>Hello {name},</p><p>Welcome to EcoVaguard Club UI. Your membership ID is {membership_id}.</p>"
        try:
            send_mail(subject, message, html_message=html_message, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])
        except Exception:
            send_mail(subject, message, html_message=html_message, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])