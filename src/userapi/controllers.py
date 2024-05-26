import os
import secrets
import traceback
import datetime
import pytz

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.db import IntegrityError
from django.core.cache import cache
from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_duration

from .models import Account, ServiceLog, SessionToken
from .enums.log_severity import LogSeverity
from .enums.account_status import AccountStatus

from .utils.encrypt_email import encrypt_email
from .utils.hash_email import hash_email
from .utils.hash_password import hash_password
from .utils.is_valid_email import is_valid_email
from .utils.is_valid_password import is_valid_password
from .utils.verify_password import verify_password
from .utils.get_country_from_ip import get_country_from_ip

from argon2 import PasswordHasher
from cryptography.fernet import Fernet

def _cache_login_attempt(ip_address):
    """
    Cache login attempts and returns a specific string status on how to handle logins after.

    Return Codes (string)
    - OK: Proceed to try login.
    - CAPTCHA: Login handler should request for captcha.
    - TIMEOUT: Login handler should reject the request.
    """
    max_login_attempts = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '6'))
    timeout_seconds = int(os.environ.get('LOGIN_BRUTEFORCE_TIMEOUT', '60'))

    key = "login_" + ip_address
    current_attempts = int(cache.get(key, "0"))
    current_attempts += 1

    # NOTE: Currently, it will just let the user try for the next `timeout_seconds`
    # We can consider resetting the timeout counter if the user tries to login while timed-out
    if current_attempts >= max_login_attempts:
        return "TIMEOUT"

    cache.set(key, str(current_attempts), timeout_seconds)
    if current_attempts >= (max_login_attempts / 2):
        return "CAPTCHA"
    return "OK"

def _insert_session_token(new_token, account, client_info, country, days_until_expiry=30):
    # Hash the token using Argon2 with a pepper
    pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
    pepper_bytes = bytes.fromhex(pepper_hex)
    hasher = PasswordHasher()
    hashed_token = hasher.hash(new_token.encode() + pepper_bytes)

    # Calculate expiry date
    current_time = timezone.now()
    expiry_date = current_time + datetime.timedelta(days=days_until_expiry)

    # encrypt country and client information...
    cipher_suite = Fernet(os.environ.get('AES_SECRET', 'key-not-set').encode())
    encrypted_client_info = cipher_suite.encrypt(client_info.encode()).decode()
    encrypted_country = cipher_suite.encrypt(country.encode()).decode()

    print(f"LENGTH :: {len(hashed_token)}", flush=True)

    # Save the session token to the database
    session_token = SessionToken.objects.create(
        account=account,
        hashed_token=hashed_token,
        encrypted_client_info=encrypted_client_info,
        encrypted_country=encrypted_country,
        expiry_date=expiry_date
    )
    session_token.save()

    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) logged in with new session token.",
        severity=LogSeverity.LOG
    )
    log.save()

    return session_token

def handle_login(username, password, second_fa_code, user_agent, ip_address):
    try:
        login_procedural = _cache_login_attempt(ip_address)

        # TODO: Handle captcha request
        if login_procedural == "TIMEOUT":
            # TODO: Service warning? etc...
            log = ServiceLog.objects.create(
                content=f"{ip_address} attempted to login too many times into {username}.",
                severity=LogSeverity.LOG
            )
            log.save()
            return JsonResponse({'status': 'TIMEOUT'}, status=429)
        
        if len(username) < 4 or len(username) > 64:
            return JsonResponse({'status': 'BAD_USERNAME'}, status=400)

        if not is_valid_password(password):
            return JsonResponse({'status': 'BAD_PASSWORD'}, status=400)

        account = Account.objects.get(username=username)
        if account is None:
            return JsonResponse({'status': 'BAD_USERNAME'}, status=401)

        if not verify_password(account.hashed_password, password):
            return JsonResponse({'status': 'BAD_PASSWORD'}, status=401)

        # TODO: Check if user is authenticated, ask user to authenticate email if not
        # TODO: Check if user setup 2fa, request 2fa if 2fa code not given

        if account.status == AccountStatus.BANNED:
            return JsonResponse({'status': 'BANNED'}, status=401)
        if account.status == AccountStatus.LOCKED:
            return JsonResponse({'status': 'LOCKED'}, status=401)

        # TODO: Determine if suspicious if was not previously one of the logged in countries
        country = get_country_from_ip(ip_address)
        session_token = secrets.token_urlsafe(32)
        _insert_session_token(session_token, account, user_agent, country)
        return JsonResponse({'status': 'SUCCESS', 'token': session_token}, status=200)
    except ObjectDoesNotExist:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=401)
    except Exception as e:
        log_message = f"Tried to login {username}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)

def handle_registration(username, email, password):
    if len(username) < 4 or len(username) > 64:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=400)

    if not is_valid_email(email) or len(email) > 256:
        return JsonResponse({'status': 'BAD_EMAIL'}, status=400)

    if not is_valid_password(password):
        return JsonResponse({'status': 'BAD_PASSWORD'}, status=400)

    try:
        hashed_email = hash_email(email)
        encrypted_email = encrypt_email(email)
        hashed_password = hash_password(password)

        # Attempt to insert into database
        account = Account.objects.create(
            username=username,
            hashed_password=hashed_password,
            encrypted_email=encrypted_email,
            hashed_email=hashed_email
        )
        account.save()

        # TODO: Setup authentication email

        log = ServiceLog.objects.create(
            content=f"New user {username} created with uuid {account.id}.",
            severity=LogSeverity.LOG
        )
        log.save()
        return JsonResponse({'status': 'SUCCESS'})
    except IntegrityError as e:
        # If username/email conflict
        if 'username' in str(e):
            return JsonResponse({'status': 'USERNAME_TAKEN'}, status=409)
        if 'hashed_email' in str(e):
            return JsonResponse({'status': 'EMAIL_TAKEN'}, status=409)
    except Exception as e:
        log_message = f"Tried to register {username}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)
    # Shouldn't reach here...
    return JsonResponse({'status': 'ERROR CONTACT ADMIN'}, status=500)