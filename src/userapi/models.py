from django.db import models
from django.utils import timezone
import uuid

class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True, db_index=True)  # Index the username field
    hashed_password = models.CharField(max_length=128)
    encrypted_email = models.CharField(max_length=128, unique=True)
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

class SessionToken(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    encrypted_token = models.CharField(max_length=128, unique=True)
    encrypted_client_info = models.CharField(max_length=128)
    expiry_date = models.DateTimeField(default=timezone.now() + timezone.timedelta(days=30))
    creation_date = models.DateTimeField(default=timezone.now)

class OTPSecret(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    encrypted_totp_code = models.CharField(max_length=128)

class OTPBackup(models.Model):
    otp_secret = models.ForeignKey(OTPSecret, on_delete=models.CASCADE)
    encrypted_backup_code = models.TextField()
