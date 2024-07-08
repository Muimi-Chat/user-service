from django.urls import path

from . import routers
from . import totp_routers
from . import user_routers
from . import forgot_password_routers

urlpatterns = [
    path("logout/", routers.logout, name="logout"),
    path("register", routers.register, name="register"),
    path("login", routers.login, name="login"),
    path('csrf_token/', routers.request_registration_csrf, name='get_csrf_token'),
    path("service-user-info/", routers.get_user_info, name="service_get_user_information"),
    path("verify-email/", routers.accept_email_token, name="verify_email"),
    path("request-email-verification-token/", routers.resend_email_verification, name="request_email_verification_token"),

    path("enable-totp/", totp_routers.enable_totp, name="enable_totp"),
    path("confirm-totp/", totp_routers.confirm_totp, name="confirm_totp"),
    path("disable-totp/", totp_routers.disable_totp, name="disable_totp"),

    path("request-user-info/", user_routers.request_user_info, name="request_user_info"),
    path("change-email/", user_routers.change_email, name="change_email"),
    path("change-password/", user_routers.change_password, name="change_password"),
    path("confirm-email-change/", user_routers.confirm_email_change, name="confirm_email_change"),
    path("revoke-session/", user_routers.revoke_session, name="revoke_session"),

    path("reset-password/", forgot_password_routers.send_forgot_password_email, name="reset_password"),
    path("confirm-password-reset/", forgot_password_routers.confirm_password_reset, name="confirm_password_reset"),
]