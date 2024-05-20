def get_account_by_username(username):
    try:
        return Account.objects.get(username=username)
    except ObjectDoesNotExist:
        return None