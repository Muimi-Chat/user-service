from django.urls import path

from . import routers

urlpatterns = [
    path("register", routers.register, name="register"),
    path("login", routers.login, name="login"),
    path('csrf_token/', routers.request_registration_csrf, name='get_csrf_token'),
    path("service-user-info/", routers.get_user_info, name="service_get_user_information"),
    path("verify-email/", routers.accept_email_token, name="verify_email"),
    path("request-email-verification-token/", routers.resend_email_verification, name="request_email_verification_token"),
]