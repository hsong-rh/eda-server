# Generated by Django 3.2.18 on 2023-08-11 18:57

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0009_add_git_hash_to_activations"),
    ]

    operations = [
        migrations.AddField(
            model_name="activation",
            name="status_updated_at",
            field=models.DateTimeField(null=True),
        ),
    ]
