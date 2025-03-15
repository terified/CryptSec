import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Util.Padding import pad, unpad

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=algorithms.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def aes_encrypt(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(pad(data, AES.block_size)) + encryptor.finalize()
    return salt + iv + encrypted_data

def aes_decrypt(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = unpad(decryptor.update(encrypted_data[32:]) + decryptor.finalize(), AES.block_size)
    return decrypted_data