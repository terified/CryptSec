from cryptography.fernet import Fernet

# Генерация ключа для шифрования конфигурации
def generate_key():
    return Fernet.generate_key()

# Сохранение ключа в файл
def save_key(key, key_file):
    with open(key_file, 'wb') as file:
        file.write(key)

# Загрузка ключа из файла
def load_key(key_file):
    with open(key_file, 'rb') as file:
        return file.read()

# Шифрование конфигурационного файла
def encrypt_config(config_file, key_file):
    key = load_key(key_file)
    cipher_suite = Fernet(key)
    with open(config_file, 'rb') as file:
        config_data = file.read()
    encrypted_data = cipher_suite.encrypt(config_data)
    with open(config_file, 'wb') as file:
        file.write(encrypted_data)
    print(f"Configuration file '{config_file}' encrypted successfully.")

# Дешифрование конфигурационного файла
def decrypt_config(config_file, key_file):
    key = load_key(key_file)
    cipher_suite = Fernet(key)
    with open(config_file, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    with open(config_file, 'wb') as file:
        file.write(decrypted_data)
    print(f"Configuration file '{config_file}' decrypted successfully.")

# Пример использования
if __name__ == "__main__":
    key = generate_key()
    save_key(key, 'config_key.key')
    encrypt_config('config.json', 'config_key.key')
    decrypt_config('config.json', 'config_key.key')