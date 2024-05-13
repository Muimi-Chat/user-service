from django.db import models
from django.utils import timezone
import uuid

from .enums.log_severity import LogSeverity

class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True, db_index=True)
    hashed_password = models.CharField(max_length=128)
    encrypted_email = models.CharField(max_length=512)
    hashed_email = models.CharField(max_length=64, unique=True)
    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(default=None, null=True)
    created_at = models.DateTimeField(default=timezone.now)

class SessionToken(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    hashed_token = models.CharField(max_length=64, unique=True)
    encrypted_client_info = models.CharField(max_length=1024)
    expiry_date = models.DateTimeField()
    creation_date = models.DateTimeField(default=timezone.now)

class TwoFASecret(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    encrypted_twofa_code = models.CharField(max_length=512)

class TwoFABackup(models.Model):
    otp_secret = models.ForeignKey(TwoFASecret, on_delete=models.CASCADE)
    hashed_backup_code = models.CharField(max_length=128)

class ServiceLog(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    severity = models.CharField(max_length=10, choices=LogSeverity.choices, default=LogSeverity.LOG)
