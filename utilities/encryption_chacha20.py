from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import os

# Шифрование текста с использованием ChaCha20
def encrypt_text_chacha20(plain_text, key=None):
    if key is None:
        key = get_random_bytes(32)  # 256 бит для ChaCha20
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.nonce + cipher.encrypt(plain_text.encode())
    return ciphertext, key

# Дешифрование текста с использованием ChaCha20
def decrypt_text_chacha20(ciphertext, key):
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext).decode()
    return plain_text

# Шифрование файла с использованием ChaCha20
def encrypt_file_chacha20(file_path, key=None):
    if key is None:
        key = get_random_bytes(32)  # 256 бит для ChaCha20
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = ChaCha20.new(key=key)
    encrypted_data = cipher.nonce + cipher.encrypt(data)
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)
    return key

# Дешифрование файла с использованием ChaCha20
def decrypt_file_chacha20(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    nonce = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    data = cipher.decrypt(encrypted_data)
    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(data)