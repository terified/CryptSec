from cryptography.hazmat.primitives.kdf.argon2 import Argon2

def argon2_hash(password, salt):
    kdf = Argon2()
    return kdf.derive(password.encode())