from cryptography.fernet import Fernet

def fernet_encrypt(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data)

def fernet_decrypt(encrypted_data, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data)