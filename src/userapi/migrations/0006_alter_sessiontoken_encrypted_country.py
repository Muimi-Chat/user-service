# Generated by Django 4.2.8 on 2024-05-20 14:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userapi', '0005_sessiontoken_encrypted_country_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sessiontoken',
            name='encrypted_country',
            field=models.TextField(),
        ),
    ]
