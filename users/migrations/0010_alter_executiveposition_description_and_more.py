# Generated by Django 5.0.2 on 2024-02-28 17:00

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0009_alter_userprofile_profile_picture"),
    ]

    operations = [
        migrations.AlterField(
            model_name="executiveposition",
            name="description",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="executiveposition",
            name="position",
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name="executiveprofile",
            name="position",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="users.executiveposition",
            ),
        ),
    ]
