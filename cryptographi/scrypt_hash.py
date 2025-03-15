from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def scrypt_hash(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())