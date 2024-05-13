def is_valid_password(password):
    return len(password) >= 8 and password.isalnum()