import os
import json

from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache

from .models import ServiceLog
from .enums.log_severity import LogSeverity

from .controllers import handle_registration

def request_registration_csrf(request):
    """
    CSRF used for registration or login.

    (Everything after, would require user's session token...)
    """
    if request.method != 'GET':
        return JsonResponse({'status': 'ERROR'}, status=404)

    user_agent = request.GET.get('userAgent', '')

    if not user_agent:
        return JsonResponse({'error': 'User agent is missing or empty'}, status=406)

    csrf_token = get_token(request)

    # Valid for 1 hour
    # It should be none of our business on why a user would take more than 1 hour to fill up a 2~3input login/register form,
    # and we shouldn't entertain it either.
    cache.set(csrf_token, user_agent, timeout=3600)
    return JsonResponse({'csrfToken': csrf_token})

@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'ERROR'}, status=404)

    data = json.loads(request.body)

    # CSRF Token Checking
    csrf_token = request.headers.get('X-CSRFToken', '')
    user_agent = data.get('userAgent', '')
    if not user_agent:
        return JsonResponse({'ERROR': 'User agent is missing or empty'}, status=406)
    if not csrf_token:
        return JsonResponse({'ERROR': 'Missing CSRF Token'}, status=406)
    original_user_agent = cache.get(csrf_token)
    if original_user_agent is None:
        return JsonResponse({'ERROR': 'Expire CSRF Token'}, status=403)

    if original_user_agent != user_agent:
        # CSRF Token did not came from the same requestor client.
        ip_address = request.META.get('REMOTE_ADDR', '')
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

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    message = data.get('message', '')
    return handle_registration(username, email, password, message)