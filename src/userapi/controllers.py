import traceback

from django.http import JsonResponse
from django.db import IntegrityError

from .models import Account, ServiceLog
from .enums.log_severity import LogSeverity

from .utils.encrypt_email import encrypt_email
from .utils.hash_email import hash_email
from .utils.hash_password import hash_password
from .utils.is_valid_email import is_valid_email
from .utils.is_valid_password import is_valid_password

def handle_registration(username, email, password, message):
    if len(username) < 4 or len(username) > 64:
        return JsonResponse({'status': 'BAD_USERNAME'}, status=406)

    if not is_valid_email(email) or len(email) > 256:
        return JsonResponse({'status': 'BAD_EMAIL'}, status=406)

    if not is_valid_password(password):
        return JsonResponse({'status': 'BAD_PASSWORD'}, status=406)

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