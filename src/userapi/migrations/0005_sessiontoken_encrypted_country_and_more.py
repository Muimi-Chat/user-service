# Generated by Django 4.2.8 on 2024-05-20 14:12

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('userapi', '0004_account_authenticated_account_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='sessiontoken',
            name='encrypted_country',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='sessiontoken',
            name='encrypted_client_info',
            field=models.TextField(),
        ),
        migrations.CreateModel(
            name='EmailAuthenticationToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hashed_token', models.CharField(db_index=True, max_length=128)),
                ('expire_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='userapi.account')),
            ],
        ),
    ]
