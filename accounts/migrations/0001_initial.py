# Generated by Django 5.2.4 on 2025-07-09 08:50

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_UUID', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('profile_UUID', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('access_token', models.CharField(blank=True, max_length=512, null=True)),
                ('client_token', models.CharField(blank=True, max_length=128, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('server_id', models.CharField(max_length=128)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.profile')),
            ],
            options={
                'unique_together': {('profile', 'server_id')},
            },
        ),
    ]
