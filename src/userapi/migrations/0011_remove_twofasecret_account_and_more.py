# Generated by Django 4.2.8 on 2024-07-04 16:13

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userapi', '0010_emailhistorylog'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='twofasecret',
            name='account',
        ),
        migrations.RemoveField(
            model_name='emailauthenticationtoken',
            name='consumed',
        ),
        migrations.RemoveField(
            model_name='emailauthenticationtoken',
            name='created_at',
        ),
        migrations.RemoveField(
            model_name='emailauthenticationtoken',
            name='expire_at',
        ),
        migrations.RemoveField(
            model_name='emailauthenticationtoken',
            name='hashed_token',
        ),
        migrations.RemoveField(
            model_name='emailauthenticationtoken',
            name='purpose',
        ),
        migrations.DeleteModel(
            name='TwoFABackup',
        ),
        migrations.DeleteModel(
            name='TwoFASecret',
        ),
    ]
