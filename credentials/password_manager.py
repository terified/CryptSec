from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Генерация ключа для шифрования паролей
def generate_key():
    return get_random_bytes(16)  # 16 байт для AES-128

# Сохранение ключа в файл
def save_key(key, key_file):
    with open(key_file, 'wb') as file:
        file.write(key)

# Загрузка ключа из файла
def load_key(key_file):
    with open(key_file, 'rb') as file:
        return file.read()

# Шифрование пароля
def encrypt_password(password, key_file):
    key = load_key(key_file)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_password = cipher.encrypt(pad(password.encode(), AES.block_size))
    return cipher.iv + encrypted_password

# Дешифрование пароля
def decrypt_password(encrypted_password, key_file):
    key = load_key(key_file)
    iv = encrypted_password[:16]
    encrypted_password = encrypted_password[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(encrypted_password), AES.block_size)
    return decrypted_password.decode()

# Добавление пароля
def add_password(user, account, password):
    key_file = f'{user}_key.key'
    if not os.path.exists(key_file):
        key = generate_key()
        save_key(key, key_file)
    encrypted_password = encrypt_password(password, key_file)
    with open(f'{user}_passwords.txt', 'a') as file:
        file.write(f'{account}:{encrypted_password.hex()}\n')

# Получение пароля
def get_password(user, account):
    key_file = f'{user}_key.key'
    if not os.path.exists(key_file):
        raise FileNotFoundError("Key file not found.")
    with open(f'{user}_passwords.txt', 'r') as file:
        for line in file:
            acc, enc_password = line.strip().split(':')
            if acc == account:
                return decrypt_password(bytes.fromhex(enc_password), key_file)
    return None