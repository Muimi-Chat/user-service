from django.db import models

class AccountStatus(models.TextChoices):
    OK = 'OK', 'Ok'
    LOCKED = 'LOCKED', 'Locked'
    BANNED = 'BANNED', 'Banned'