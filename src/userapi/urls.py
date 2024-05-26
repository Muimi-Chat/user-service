from django.urls import path

from . import routers

urlpatterns = [
    path("register", routers.register, name="register"),
    path("login", routers.login, name="login"),
    path('csrf_token/', routers.request_registration_csrf, name='get_csrf_token'),
]