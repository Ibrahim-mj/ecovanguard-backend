# Generated by Django 5.0.2 on 2024-02-19 21:15

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("full_name", models.CharField(max_length=255)),
                ("age", models.PositiveIntegerField()),
                ("city_of_residence", models.CharField(max_length=255)),
                (
                    "user_type",
                    models.CharField(
                        choices=[
                            ("EXECUTIVE", "Executive"),
                            ("UNIVERSITY_STUDENT", "University Student"),
                            ("SECONDARY_STUDENT", "Secondary Student"),
                        ],
                        max_length=255,
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="BaseUserProfile",
            fields=[
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        serialize=False,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("bio", models.TextField()),
                ("branch", models.CharField(max_length=255)),
                ("year_of_admission", models.DateField()),
                ("year_of_graduation", models.DateField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="SecondaryStudentProfile",
            fields=[
                (
                    "baseuserprofile_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="users.baseuserprofile",
                    ),
                ),
                ("school_name", models.CharField(max_length=255)),
                ("school_location", models.CharField(max_length=255)),
                ("student_class", models.CharField(max_length=255)),
            ],
            bases=("users.baseuserprofile",),
        ),
        migrations.CreateModel(
            name="UniversityStudentProfile",
            fields=[
                (
                    "baseuserprofile_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="users.baseuserprofile",
                    ),
                ),
                ("institution", models.CharField(max_length=255)),
                ("faculty", models.CharField(max_length=255)),
                ("department", models.CharField(max_length=255)),
                ("level", models.CharField(max_length=255)),
            ],
            bases=("users.baseuserprofile",),
        ),
        migrations.CreateModel(
            name="ExecutiveProfile",
            fields=[
                (
                    "universitystudentprofile_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="users.universitystudentprofile",
                    ),
                ),
                ("position", models.CharField(max_length=255)),
            ],
            bases=("users.universitystudentprofile",),
        ),
    ]
