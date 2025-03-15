import readchar
import getpass
from credentials.user_auth import register_user, login_user
from credentials.password_manager import add_password, get_password
from utilities.menu import menu
from utilities.banner import print_banner
from utilities.config_encrypt import encrypt_config, decrypt_config
from utilities.logging import log_info, log_warning, log_error
from utilities.report_generator import generate_report
from utilities.encryption import encrypt_text_aes, decrypt_text_aes, encrypt_file_aes, decrypt_file_aes, encrypt_file_rsa, decrypt_file_rsa
from utilities.qr_code import generate_qr_code, read_qr_code
from utilities.password_checker import check_password_strength
from utilities.otp import generate_totp, validate_totp
from utilities.encryption_chacha20 import encrypt_text_chacha20, decrypt_text_chacha20, encrypt_file_chacha20, decrypt_file_chacha20
from utilities.pgp import generate_pgp_key_pair, encrypt_data_pgp, decrypt_data_pgp
from utilities.secure_chat import secure_chat
from utilities.stealth_mode import activate_stealth_mode
from utilities.console_utils import clear_console, wait_for_enter
import os
import socks
import socket

# Настройка прокси-сервера
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 60009
socks.set_default_proxy(socks.HTTP, PROXY_HOST, PROXY_PORT)
socket.socket = socks.socksocket

# Путь к базе данных пользователей
users_db_path = 'security/encryption_tool.db'

# Функция для ввода пароля с отображением звездочек
def get_password_with_stars(prompt="Enter password: "):
    print(prompt, end="", flush=True)
    password = ""
    while True:
        char = readchar.readchar()
        if char == "\r" or char == "\n":  # Если Enter, выходим
            print()
            break
        elif char == "\b" or char == "\x7f":  # Backspace
            if password:
                password = password[:-1]
                print("\b \b", end="", flush=True)
        else:
            password += char
            print("*", end="", flush=True)
    return password

# Основная функция
def main():
    current_user = None
    user_actions = []
    while True:
        clear_console()
        print_banner()
        if current_user is None:
            print("Please register or login first.")
            choice = input("[1] Register [2] Login [0] Exit: ")
            clear_console()
            if choice == '1':
                username = input("Enter username: ")
                password = get_password_with_stars("Enter password: ")
                email = input("Enter email: ")
                if register_user(username, password, email):
                    current_user = username
                    user_actions.append("Registered successfully")
            elif choice == '2':
                username = input("Enter username: ")
                password = get_password_with_stars("Enter password: ")
                email = input("Enter your registered email: ")
                if login_user(username, password):
                    current_user = username
                    user_actions.append("Logged in successfully")
            elif choice == '0':
                break
            else:
                print("Invalid choice. Please try again.")
                wait_for_enter()
        else:
            clear_console()
            print_banner()
            menu()
            choice = input("Enter your choice: ")
            clear_console()
            try:
                # Add your functionality here
                if choice == '3':
                    data = input("Enter data to encrypt: ").encode()
                    password = get_password_with_stars("Enter password: ")
                    encrypted_data = encrypt_text_aes(data, password)
                    print("Encrypted data:", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using AES.")
                    user_actions.append("Encrypted data using AES")
                    wait_for_enter()
                elif choice == '4':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    password = get_password_with_stars("Enter password: ")
                    decrypted_data = decrypt_text_aes(encrypted_data, password)
                    print("Decrypted data:", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using AES.")
                    user_actions.append("Decrypted data using AES")
                    wait_for_enter()
                elif choice == '5':
                    data = input("Enter data to encrypt: ").encode()
                    private_key, public_key = generate_rsa_keys()
                    encrypted_data = encrypt_file_rsa(data, public_key)
                    print("Encrypted data (RSA):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using RSA.")
                    user_actions.append("Encrypted data using RSA")
                    wait_for_enter()
                elif choice == '6':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    private_key, public_key = generate_rsa_keys()
                    decrypted_data = decrypt_file_rsa(encrypted_data, private_key)
                    print("Decrypted data (RSA):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using RSA.")
                    user_actions.append("Decrypted data using RSA")
                    wait_for_enter()
                elif choice == '7':
                    data = input("Enter data for HMAC: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    hmac_value = generate_hmac(data, key)
                    print("Generated HMAC:", hmac_value)
                    log_info(f"User '{current_user}' generated HMAC.")
                    user_actions.append("Generated HMAC")
                    wait_for_enter()
                elif choice == '8':
                    data = input("Enter data for HMAC verification: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    hmac_value = input("Enter HMAC value: ").encode()
                    if verify_hmac(data, key, hmac_value):
                        print("HMAC verified successfully.")
                        log_info(f"User '{current_user}' verified HMAC.")
                        user_actions.append("Verified HMAC")
                    else:
                        print("Failed to verify HMAC.")
                        log_warning(f"User '{current_user}' failed to verify HMAC.")
                    wait_for_enter()
                elif choice == '9':
                    password = get_password_with_stars("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = hash_password_pbkdf2(password, salt)
                    print("Hashed password:", hashed_password)
                    log_info(f"User '{current_user}' hashed password using PBKDF2.")
                    user_actions.append("Hashed password using PBKDF2")
                    wait_for_enter()
                elif choice == '10':
                    password = get_password_with_stars("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = hash_password_scrypt(password, salt)
                    print("Hashed password (Scrypt):", hashed_password)
                    log_info(f"User '{current_user}' hashed password using Scrypt.")
                    user_actions.append("Hashed password using Scrypt")
                    wait_for_enter()
                elif choice == '11':
                    password = get_password_with_stars("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = hash_password_argon2(password, salt)
                    print("Hashed password (Argon2):", hashed_password)
                    log_info(f"User '{current_user}' hashed password using Argon2.")
                    user_actions.append("Hashed password using Argon2")
                    wait_for_enter()
                elif choice == '12':
                    data = input("Enter data to encrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    encrypted_data = des3_encrypt(data, key)
                    print("Encrypted data (DES3):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using DES3.")
                    user_actions.append("Encrypted data using DES3")
                    wait_for_enter()
                elif choice == '13':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    decrypted_data = des3_decrypt(encrypted_data, key)
                    print("Decrypted data (DES3):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using DES3.")
                    user_actions.append("Decrypted data using DES3")
                    wait_for_enter()
                elif choice == '14':
                    data = input("Enter data to encrypt: ").encode()
                    key = generate_key()
                    encrypted_data = fernet_encrypt(data, key)
                    print("Encrypted data (Fernet):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using Fernet.")
                    user_actions.append("Encrypted data using Fernet")
                    wait_for_enter()
                elif choice == '15':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = input("Enter key: ").encode()
                    decrypted_data = fernet_decrypt(encrypted_data, key)
                    print("Decrypted data (Fernet):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using Fernet.")
                    user_actions.append("Decrypted data using Fernet")
                    wait_for_enter()
                elif choice == '16':
                    data = input("Enter data to encrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    encrypted_data = xor_encrypt(data, key)
                    print("Encrypted data (XOR):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using XOR.")
                    user_actions.append("Encrypted data using XOR")
                    wait_for_enter()
                elif choice == '17':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    decrypted_data = xor_decrypt(encrypted_data, key)
                    print("Decrypted data (XOR):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using XOR.")
                    user_actions.append("Decrypted data using XOR")
                    wait_for_enter()
                elif choice == '18':
                    image_path = input("Enter image path: ")
                    data = input("Enter data to hide: ").encode()
                    hide_data_in_image(image_path, data)
                    print("Data hidden in image successfully.")
                    log_info(f"User '{current_user}' hid data in image.")
                    user_actions.append("Hid data in image")
                    wait_for_enter()
                elif choice == '19':
                    image_path = input("Enter image path: ")
                    extracted_data = extract_data_from_image(image_path)
                    print("Extracted data:", extracted_data)
                    log_info(f"User '{current_user}' extracted data from image.")
                    user_actions.append("Extracted data from image")
                    wait_for_enter()
                elif choice == '20':
                    account = input("Enter account name: ")
                    password = get_password_with_stars("Enter password to store: ")
                    add_password(current_user, account, password)
                    log_info(f"User '{current_user}' added password for account '{account}'.")
                    user_actions.append(f"Added password for account '{account}'")
                    wait_for_enter()
                elif choice == '21':
                    account = input("Enter account name: ")
                    password = get_password(current_user, account)
                    print(f"Password for account '{account}': {password}")
                    log_info(f"User '{current_user}' retrieved password for account '{account}'.")
                    user_actions.append(f"Retrieved password for account '{account}'")
                    wait_for_enter()
                elif choice == '22':
                    config_file = input("Enter the path to the configuration file: ")
                    key_file = input("Enter the path to the key file: ")
                    encrypt_config(config_file, key_file)
                    log_info(f"User '{current_user}' encrypted configuration file '{config_file}'.")
                    user_actions.append(f"Encrypted configuration file '{config_file}'")
                    wait_for_enter()
                elif choice == '23':
                    config_file = input("Enter the path to the configuration file: ")
                    key_file = input("Enter the path to the key file: ")
                    decrypt_config(config_file, key_file)
                    log_info(f"User '{current_user}' decrypted configuration file '{config_file}'.")
                    user_actions.append(f"Decrypted configuration file '{config_file}'")
                    wait_for_enter()
                elif choice == '24':
                    report_file = generate_report(current_user, user_actions)
                    log_info(f"User '{current_user}' generated report: {report_file}")
                    user_actions.append(f"Generated report: {report_file}")
                    wait_for_enter()
                elif choice == '25':
                    file_path = input("Enter the path of the file to encrypt: ")
                    password = get_password_with_stars("Enter password: ")
                    key = hashlib.sha256(password.encode()).digest()
                    encrypt_file_aes(file_path, key)
                    log_info(f"User '{current_user}' encrypted file '{file_path}' using AES.")
                    user_actions.append(f"Encrypted file '{file_path}' using AES")
                    wait_for_enter()
                elif choice == '26':
                    file_path = input("Enter the path of the file to decrypt: ")
                    password = get_password_with_stars("Enter password: ")
                    key = hashlib.sha256(password.encode()).digest()
                    decrypt_file_aes(file_path, key)
                    log_info(f"User '{current_user}' decrypted file '{file_path}' using AES.")
                    user_actions.append(f"Decrypted file '{file_path}' using AES")
                    wait_for_enter()
                elif choice == '27':
                    file_path = input("Enter the path of the file to encrypt: ")
                    private_key, public_key = generate_rsa_keys()
                    encrypt_file_rsa(file_path, public_key)
                    log_info(f"User '{current_user}' encrypted file '{file_path}' using RSA.")
                    user_actions.append(f"Encrypted file '{file_path}' using RSA")
                    wait_for_enter()
                elif choice == '28':
                    file_path = input("Enter the path of the file to decrypt: ")
                    private_key, public_key = generate_rsa_keys()
                    decrypt_file_rsa(file_path, private_key)
                    log_info(f"User '{current_user}' decrypted file '{file_path}' using RSA.")
                    user_actions.append(f"Decrypted file '{file_path}' using RSA")
                    wait_for_enter()
                elif choice == '29':
                    data = input("Enter data to encode in QR code: ")
                    generate_qr_code(data)
                    log_info(f"User '{current_user}' generated QR code.")
                    user_actions.append("Generated QR code")
                    wait_for_enter()
                elif choice == '30':
                    file_path = input("Enter the path of the QR code to read: ")
                    data = read_qr_code(file_path)
                    print("Decoded data from QR code:", data)
                    log_info(f"User '{current_user}' read QR code.")
                    user_actions.append("Read QR code")
                    wait_for_enter()
                elif choice == '31':
                    password = get_password_with_stars("Enter password to check strength: ")
                    valid, message = check_password_strength(password)
                    print(message)
                    log_info(f"User '{current_user}' checked password strength.")
                    user_actions.append("Checked password strength")
                    wait_for_enter()
                elif choice == '32':
                    secret = generate_totp_secret()
                    print("Your TOTP secret is:", secret)
                    log_info(f"User '{current_user}' generated TOTP secret.")
                    user_actions.append("Generated TOTP secret")
                    wait_for_enter()
                elif choice == '33':
                    token = input("Enter the TOTP token: ")
                    secret = input("Enter the TOTP secret: ")
                    if validate_totp(token, secret):
                        print("TOTP token is valid.")
                        log_info(f"User '{current_user}' validated TOTP token.")
                        user_actions.append("Validated TOTP token")
                    else:
                        print("Invalid TOTP token.")
                        log_warning(f"User '{current_user}' failed to validate TOTP token.")
                    wait_for_enter()
                elif choice == '34':
                    data = input("Enter text to encrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    encrypted_data = encrypt_text_chacha20(data, key)
                    print("Encrypted text:", encrypted_data)
                    log_info(f"User '{current_user}' encrypted text using ChaCha20.")
                    user_actions.append("Encrypted text using ChaCha20")
                    wait_for_enter()
                elif choice == '35':
                    encrypted_data = input("Enter text to decrypt: ").encode()
                    key = get_password_with_stars("Enter key: ").encode()
                    decrypted_data = decrypt_text_chacha20(encrypted_data, key)
                    print("Decrypted text:", decrypted_data)
                    log_info(f"User '{current_user}' decrypted text using ChaCha20.")
                    user_actions.append("Decrypted text using ChaCha20")
                    wait_for_enter()
                elif choice == '36':
                    file_path = input("Enter the path of the file to encrypt: ")
                    key = get_password_with_stars("Enter key: ").encode()
                    encrypt_file_chacha20(file_path, key)
                    log_info(f"User '{current_user}' encrypted file '{file_path}' using ChaCha20.")
                    user_actions.append(f"Encrypted file '{file_path}' using ChaCha20")
                    wait_for_enter()
                elif choice == '37':
                    file_path = input("Enter the path of the file to decrypt: ")
                    key = get_password_with_stars("Enter key: ").encode()
                    decrypt_file_chacha20(file_path, key)
                    log_info(f"User '{current_user}' decrypted file '{file_path}' using ChaCha20.")
                    user_actions.append(f"Decrypted file '{file_path}' using ChaCha20")
                    wait_for_enter()
                elif choice == '38':
                    private_key, public_key = generate_pgp_key_pair()
                    print("PGP key pair generated.")
                    log_info(f"User '{current_user}' generated PGP key pair.")
                    user_actions.append("Generated PGP key pair")
                    wait_for_enter()
                elif choice == '39':
                    data = input("Enter data to encrypt: ").encode()
                    public_key = input("Enter the public key: ").encode()
                    encrypted_data = encrypt_data_pgp(data, public_key)
                    print("Encrypted data (PGP):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using PGP.")
                    user_actions.append("Encrypted data using PGP")
                    wait_for_enter()
                elif choice == '40':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    private_key = get_password_with_stars("Enter the private key: ").encode()
                    decrypted_data = decrypt_data_pgp(encrypted_data, private_key)
                    print("Decrypted data (PGP):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using PGP.")
                    user_actions.append("Decrypted data using PGP")
                    wait_for_enter()
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                    log_warning(f"User '{current_user}' chose an invalid option.")
                    wait_for_enter()
            except Exception as e:
                print(f"An error occurred: {e}")
                log_error(f"An error occurred for user '{current_user}': {e}")

if __name__ == "__main__":
   main()