import os

from cryptography.fernet import Fernet

def encrypt_email(email):
    # TODO: Use a Key Management Service instead of global static key...
    cipher_suite = Fernet(os.environ.get('AES_SECRET', 'key-not-set').encode())
    return cipher_suite.encrypt(email.encode()).decode()