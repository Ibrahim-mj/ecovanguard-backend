# Generated by Django 5.0.2 on 2024-03-09 14:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0010_alter_executiveposition_description_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="username",
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
    ]