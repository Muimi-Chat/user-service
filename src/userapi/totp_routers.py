import os
import json
import uuid
import traceback

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .enums.log_severity import LogSeverity

from .models import Account, ServiceLog

from .controllers import validate_session_token

from .services.generate_totp_token import generate_totp_token
from .services.verify_totp_code import verify_totp_code
from .services.generate_recovery_codes import generate_recovery_codes
from .services.verify_recovery_code import verify_recovery_code
from .services.send_email_with_content import send_email_with_content
from .services.request_decrypt import request_decrypt

@csrf_exempt
def enable_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)

    if account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_ENABLED'}, status=403)
    
    response_data = generate_totp_token(account.id, account.username)
    if response_data['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)

    return JsonResponse({
        'status': 'SUCCESS',
        'secret': response_data['secret'],
        'qrCodeUri': response_data['qrCodeUri']
    })

@csrf_exempt
def confirm_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    session_token = request.headers.get('session-token', '')
    user_agent = request.META['HTTP_USER_AGENT']
    username = data.get('username', '')
    code = data.get('code', '')

    account = validate_session_token(username, user_agent, session_token)
    if account is None:
        return JsonResponse({'status': 'BAD_SESSION_TOKEN'}, status=401)
    
    if account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_ENABLED'}, status=403)
    
    verify_result = verify_totp_code(account.id, code)
    if verify_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    if not verify_result['valid']:
        return JsonResponse({'status': 'INVALID_CODE'}, status=403)
    
    recovery_codes_result = generate_recovery_codes(account.id)
    if recovery_codes_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    codes = recovery_codes_result['codes']
    
    account.totp_enabled = True
    account.save()

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'TOTP Enabled!', 'This is a notice that you have enabled TOTP on your account!')
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send TOTP disabled email to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()

    return JsonResponse({'status': 'SUCCESS', 'codes': codes})

@csrf_exempt
def disable_totp(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    username = data.get('username', '')
    recovery_code = data.get('recovery_code', '')

    account = Account.objects.filter(username=username).first()
    if account is None:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=401)

    if not account.totp_enabled:
        return JsonResponse({'status': 'ALREADY_DISABLED'}, status=403)
    
    verify_result = verify_recovery_code(account.id, recovery_code)
    if verify_result['status'] != 'SUCCESS':
        return JsonResponse({'status': 'ERROR'}, status=500)
    
    if not verify_result['valid']:
        return JsonResponse({'status': 'INVALID_CODE'}, status=403)
    
    account.totp_enabled = False
    account.save()

    try:
        email = request_decrypt(account.id, account.encrypted_email, account.id)
        send_email_with_content(email, 'TOTP Disabled Successfully!', 'This is a notice that you have disabled TOTP successfully!')
    except Exception as e:
        print(e, flush=True)
        log = ServiceLog.objects.create(
            content=f"Failed to send TOTP disabled email to {account.username} ({account.id}) due to :: {e}",
            severity=LogSeverity.ERROR
        )
        log.save()
    
    return JsonResponse({'status': 'SUCCESS'})
