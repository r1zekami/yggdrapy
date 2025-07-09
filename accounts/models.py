from django.db import models
from django.contrib.auth.models import User
import uuid

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_UUID = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    profile_UUID = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    access_token = models.CharField(max_length=512, blank=True, null=True)
    client_token = models.CharField(max_length=128, blank=True, null=True)

    def __str__(self):
        return str(self.user) if hasattr(self, 'user') and self.user else 'Profile'

class Session(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    server_id = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('profile', 'server_id')

#python manage.py makemigrations
#python manage.py migrate
