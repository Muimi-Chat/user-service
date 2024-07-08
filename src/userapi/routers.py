import os
import json
import uuid
import traceback
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache

from .utils.verify_password import verify_password
from .utils.generate_verification_url import generate_verification_url

from .services.send_email_with_content import send_email_with_content
from .services.verify_email_verification_token import verify_email_verification_token
from .services.validate_cloudflare_token import validate_cloudflare_token
from .services.request_decrypt import request_decrypt
from .services.generate_email_verification_token import generate_email_verification_token

from .models import ServiceLog, Account, SessionToken

from .enums.log_severity import LogSeverity

from .controllers import handle_registration, handle_login, validate_session_token

def _verify_csrf(csrf_token, user_agent, ip_address):
    """
    Helper function to verify the CSRF token against a User Agent.

    Returns None object, if the CSRF token is valid.
    Returns a JsonResponse object to be sent back to the client, if theres any bad CSRF

    Auto-logs into the database if there are any possible CSRF Attack.
    """
    if not user_agent:
        return JsonResponse({'ERROR': 'User agent is missing or empty'}, status=400)
    if not csrf_token:
        return JsonResponse({'ERROR': 'Missing CSRF Token'}, status=400)
    original_user_agent = cache.get(csrf_token)
    if original_user_agent is None:
        return JsonResponse({'ERROR': 'Expire CSRF Token'}, status=403)

    if original_user_agent != user_agent:
        # CSRF Token did not came from the same requestor client.
        log_message = f"Detected possible CSRF Attack on {csrf_token}, source from {ip_address} using {user_agent}; Original CSRF created by {original_user_agent}"
        print(log_message)
        try:
            log = ServiceLog.objects.create(
                content=log_message,
                severity=LogSeverity.ERROR
            )
            log.save()
        except Exception:
            print("Failed to log the CSRF Attack into database!")
        cache.delete(csrf_token)
        return JsonResponse({'ERROR': 'CSRF Attack!'}, status=403)
    return None

def request_registration_csrf(request):
    """
    CSRF used for registration or login.

    (Everything after, would require user's session token...)
    """
    if request.method != 'GET':
        return JsonResponse({'status': 'ERROR'}, status=404)

    user_agent = request.META['HTTP_USER_AGENT']

    if not user_agent:
        return JsonResponse({'error': 'User agent is missing or empty'}, status=406)

    csrf_token = get_token(request)

    # Valid for 1 hour
    # It should be none of our business on why a user would take more than 1 hour to fill up a 2~3input login/register form,
    # and we shouldn't entertain it either.
    cache.set(csrf_token, user_agent, timeout=3600)
    return JsonResponse({'csrfToken': csrf_token})

@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    # CSRF Token Checking
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    ip_address = request.META.get('REMOTE_ADDR', '')
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status

    username = data.get('username', '')
    password = data.get('password', '')
    second_fa_code = data.get('2fa_code', '')

    cloudflare_token = data.get('cloudflare_token', '')
    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=401)

    return handle_login(username, password, second_fa_code, user_agent, ip_address)

@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    # CSRF Token Checking
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    ip_address = request.META.get('REMOTE_ADDR', '')
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    
    cloudflare_token = data.get('cloudflare_token', '')
    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=401)

    return handle_registration(username, email, password)

@csrf_exempt
def get_user_info(request):
    """
    For other services to use to get user information...
    """
    if request.method != 'GET':
        return JsonResponse({'status': 'ERROR'}, status=404)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    service_token = request.headers.get('service-token', '')

    expected_service_token = os.environ.get('SERVICE_API_TOKEN', 'token-not-set')
    if expected_service_token != service_token:
        return JsonResponse({'status': 'ERROR'}, status=401)

    username = request.GET.get('username', '')

    account = validate_session_token(username, user_agent, session_token)
    if account == None:
        return JsonResponse({'status': 'USERNAME_NOT_FOUND'}, status=401)
    
    return JsonResponse({'status': 'SUCCESS', 'uuid': account.id, 'user_status': account.status, 'deleted': account.deleted, 'authenticated': account.authenticated}, status=200)

@csrf_exempt
def resend_email_verification(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)
    
    data = json.loads(request.body)

    username = data.get('username', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    cloudflare_token = data.get('cloudflare_token', '')
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status

    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=401)
    
    account = Account.objects.get(username=username)
    if account.authenticated:
        return JsonResponse({'status': 'ALREADY_AUTHENTICATED'}, status=403)

    has_send_token_recently = cache.get(f"email_verification_{str(account.id)}")
    if has_send_token_recently is not None:
        return JsonResponse({'status': 'WAIT_BEFORE_SENDING'}, status=403)

    email = request_decrypt(str(account.id), account.encrypted_email, str(account.id))
    try:
        # Generate email verification token
        response = generate_email_verification_token(str(account.id))
        if response['status'] != "SUCCESS":
            return JsonResponse({'status': 'ERROR'}, status=500)
        
        # Send email with verification URL
        verification_token = response['verificationToken']
        token_id = str(response['tokenID'])

        verification_url = generate_verification_url(token_id, verification_token)
        email_content = f"Heres your verification URL: <a href={verification_url}>{verification_url}</a><br><br>It will expire in 1 hour."
        email_header = "Muimi Email Verification"

        response = send_email_with_content(email, email_header, email_content)
        if not response['success']:
            return JsonResponse({'status': 'ERROR'}, status=500)
        cache.set(f"email_verification_{str(account.id)}", True, timeout=120)

    except Exception as e:
        log_message = f"Tried to send verification email to {email}, but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        log = ServiceLog.objects.create(
            content=log_message,
            severity=LogSeverity.ERROR
        )
        log.save()
        return JsonResponse({'status': 'ERROR'}, status=500)

    return JsonResponse({'status': 'SUCCESS'})

@csrf_exempt
def accept_email_token(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)
    
    data = json.loads(request.body)

    token = data.get('token', '')
    token_id = data.get('id', '')
    
    ip_address = request.META.get('REMOTE_ADDR', '')
    cloudflare_token = data.get('cloudflare_token', '')
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = request.META['HTTP_USER_AGENT']
    csrf_status = _verify_csrf(csrf_token, user_agent, ip_address)
    if not csrf_status is None:
        return csrf_status

    if not validate_cloudflare_token(cloudflare_token, ip_address):
        return JsonResponse({'status': 'INVALID_CLOUDFLARE_TOKEN'}, status=401)

    account = None
    try:
        result = verify_email_verification_token(token_id, token)
        if not result['valid']:
            return JsonResponse({'status': 'INVALID_TOKEN'}, status=401)
        
        account_id = uuid.UUID(result['accountID'])
        account = Account.objects.get(id=account_id)
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to verify email verification token due to :: {e}",
            severity=LogSeverity.ERROR
        )
        return JsonResponse({'status': 'TOKEN_NOT_FOUND'}, status=404)

    account.authenticated = True
    account.save()
    
    log = ServiceLog.objects.create(
        content=f"{account.username} ({account.id}) accepted email token.",
        severity=LogSeverity.LOG
    )
    log.save()

    return JsonResponse({'status': 'SUCCESS'}, status=200)

def logout(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)
    
    data = json.loads(request.body)

    username = data.get('username', '')
    user_agent = request.META['HTTP_USER_AGENT']
    session_token = request.headers.get('session-token', '')

    try:
        # Retrieve the user's account based on the username
        account = Account.objects.get(username=username)

        # Get the pepper from the environment variable
        pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
        pepper_bytes = bytes.fromhex(pepper_hex)

        # Iterate through all session tokens associated with the user's account
        for session_token in SessionToken.objects.filter(account=account):
            decrypted_client_info = request_decrypt(str(account.id), session_token.encrypted_client_info, str(account.id))

            if session_token.expiry_date < timezone.now():
                session_token.delete()
                ServiceLog.objects.create(
                    content=f"Session Token Expired for user :: {username} ({account.id})",
                    severity=LogSeverity.VERBOSE
                )
                continue

            # Validate the hashed token against the session token's hashed token
            try:
                hasher = PasswordHasher()
                if hasher.verify(session_token.hashed_token, session_token.encode() + pepper_bytes):
                    if not decrypted_client_info == user_agent:
                        # Token is invalid since client information doesnt match
                        session_token.delete()
                        ServiceLog.objects.create(
                            content=f"Client Information Mismatch for user :: {username} ({account.id})",
                            severity=LogSeverity.WARNING
                        )
                        return JsonResponse({'status': 'SUCCESS'}, status=200)

                    # Token is valid
                    session_token.delete()
                    ServiceLog.objects.create(
                        content=f"User Logged Out :: {username} ({account.id})",
                        severity=LogSeverity.LOG
                    )
                    return JsonResponse({'status': 'SUCCESS'}, status=200)
            except VerifyMismatchError:
                continue

        # No matching valid token found
        return JsonResponse({'status': 'BAD'}, status=404)

    except ObjectDoesNotExist:
        # User account not found
        return JsonResponse({'status': 'BAD'}, status=404)