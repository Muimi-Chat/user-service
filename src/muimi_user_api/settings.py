"""
Django settings for muimi_user_api project.

Generated by 'django-admin startproject' using Django 5.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'key-not-set')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("IS_RELEASE") == "FALSE"

CLIENT_HOST_ADDRESS = os.getenv('CLIENT_HOST_ADDRESS', 'localhost')
ALLOWED_HOSTS = [
    CLIENT_HOST_ADDRESS,
    'localhost'
]


# Application definition

INSTALLED_APPS = [
    'userapi.apps.UserapiConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:44818',
    'https://localhost:44818',
    'http://' + CLIENT_HOST_ADDRESS,
    'https://' + CLIENT_HOST_ADDRESS
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'muimi_user_api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'muimi_user_api.wsgi.application'

# Redis Cache

REDIS_PORT = os.environ.get('REDIS_PORT', '6379')
REDIS_ADDRESS = os.environ.get('REDIS_ADDRESS', 'user-cache')
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', 'yourpassword')

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://:{REDIS_PASSWORD}@{REDIS_ADDRESS}:{REDIS_PORT}",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

# PostgreSQL Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

POSTGRES_ADDRESS = os.environ.get('POSTGRESQL_ADDRESS', 'user-database')
POSTGRES_PORT = os.environ.get('POSTGRESQL_PORT', '5432')
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'myproject')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'myprojectuser')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'myprojectpassword')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': POSTGRES_DB,
        'USER': POSTGRES_USER,
        'PASSWORD': POSTGRES_PASSWORD,
        'HOST': POSTGRES_ADDRESS,
        'PORT': '5432',
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Singapore'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
